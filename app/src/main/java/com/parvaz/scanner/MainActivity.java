
package com.parvaz.scanner;

import android.content.*;
import android.net.Uri;
import android.os.*;
import android.view.*;
import android.widget.*;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.*;
import java.net.*;
import java.nio.*;
import java.security.*;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.crypto.*;
import javax.crypto.spec.*;

public class MainActivity extends AppCompatActivity {
  // FCAE exact: 7 /24 prefixes, 54 ports
  static final int[] WG_PORTS = {
    2408,500,1701,4500,854,859,864,878,880,890,891,894,903,908,928,934,
    939,942,943,945,946,955,968,987,988,1002,1010,1014,1018,1070,1074,
    1180,1387,1843,2371,2506,3138,3476,3581,3854,4177,4198,4233,5279,
    5956,7103,7152,7156,7281,7559,8319,8742,8854,8886
  };
  static final String[] PREFIXES = {
    "162.159.192.0/24", "162.159.193.0/24", "162.159.195.0/24",
    "188.114.96.0/24",  "188.114.97.0/24",  "188.114.98.0/24",
    "188.114.99.0/24"
  };
  static final String[] SEEDS = {
    "162.159.192.1","162.159.193.1","162.159.195.1",
    "188.114.96.1","188.114.97.1"
  };

  // CF WARP peer public (well-known, all edges share this key)
  static final String CF_PEER_PUB_B64 = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";
  static final byte[] CF_PEER_PUB_RAW = android.util.Base64.decode(CF_PEER_PUB_B64, android.util.Base64.DEFAULT);

  TextView tvLog, tvStat; Button btnScan, btnStop, btnCopy, btnBot;
  RecyclerView rv; Adapter ad;
  ExecutorService pool; AtomicBoolean abort = new AtomicBoolean(false);
  List<Result> okList = Collections.synchronizedList(new ArrayList<>());

  static class Result { String ip; int port; long rtt; Result(String ip,int port,long rtt){this.ip=ip;this.port=port;this.rtt=rtt;} String ep(){return ip+":"+port;} }

  @Override protected void onCreate(Bundle b){
    super.onCreate(b); setContentView(R.layout.activity_main);
    tvLog=findViewById(R.id.tvLog); tvStat=findViewById(R.id.tvStat);
    btnScan=findViewById(R.id.btnScan); btnStop=findViewById(R.id.btnStop);
    btnCopy=findViewById(R.id.btnCopy); btnBot=findViewById(R.id.btnBot);
    rv=findViewById(R.id.rv); rv.setLayoutManager(new LinearLayoutManager(this));
    ad=new Adapter(okList); rv.setAdapter(ad);
    btnScan.setOnClickListener(v-> startScan());
    btnStop.setOnClickListener(v-> { abort.set(true); log("[-] stopped"); tvStat.setText("stopped"); });
    btnCopy.setOnClickListener(v-> copyAll());
    btnBot.setOnClickListener(v-> sendToBot());
  }
  void log(String s){ runOnUiThread(()->{ tvLog.append("\n"+s); }); }
  void stat(String s){ runOnUiThread(()-> tvStat.setText(s)); }

  // FCAE build_wg_candidates equivalent:
  // - anchors (SEEDS) × first 4 ports
  // - pool (sampled CIDR hosts) in waves rotating ports
  List<int[]> buildCandidates(){
    List<int[]> out = new ArrayList<>();
    Set<String> seen = new HashSet<>();
    java.util.function.BiConsumer<String,Integer> push = (ip,p)-> {
      String k=ip+":"+p; if(seen.add(k)){ String[] pp=ip.split("\\."); out.add(new int[]{Integer.parseInt(pp[0]),Integer.parseInt(pp[1]),Integer.parseInt(pp[2]),Integer.parseInt(pp[3]),p}); }
    };
    // anchors × first 4 ports (priority)
    int[] anchorPorts = {2408,500,1701,4500};
    for(int p: anchorPorts) for(String s: SEEDS) push.accept(s,p);
    // sampled pool: ~120 random hosts per prefix × 3 waves rotating ports
    SecureRandom sr=new SecureRandom();
    for(int wave=0; wave<3; wave++){
      for(String cidr: PREFIXES){
        String base=cidr.split("/")[0]; String[] b=base.split("\\.");
        int a=Integer.parseInt(b[0]), b2=Integer.parseInt(b[1]), c=Integer.parseInt(b[2]);
        // sample 40 random hosts per prefix per wave
        for(int k=0;k<40;k++){
          int host=1+sr.nextInt(254);
          int port=WG_PORTS[(k+wave)%WG_PORTS.length];
          push.accept(a+"."+b2+"."+c+"."+host, port);
        }
      }
    }
    // also add full sweep of top-4 ports for all 254 hosts (thorough for V4)
    // only 4*7*254=7112 — fast via TCP pre-filter
    for(String cidr: PREFIXES){
      String base=cidr.split("/")[0]; String[] b=base.split("\\.");
      int a=Integer.parseInt(b[0]), b2=Integer.parseInt(b[1]), c=Integer.parseInt(b[2]);
      for(int host=1; host<=254; host++){
        for(int port: anchorPorts){
          String ip=a+"."+b2+"."+c+"."+host;
          if(seen.add(ip+":"+port)) out.add(new int[]{a,b2,c,host,port});
        }
      }
    }
    return out;
  }

  // WireGuard Noise_IK init matching boringtun format_handshake_initiation:
  // INITIAL_CHAIN_KEY = BLAKE2s("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" 32B)
  // INITIAL_CHAIN_HASH = BLAKE2s(INITIAL_CHAIN_KEY || "WireGuard v1 ...")
  static final byte[] INITIAL_CHAIN_KEY = new byte[]{(byte)96,(byte)226,109,(byte)174,(byte)243,39,(byte)239,(byte)192,46,(byte)195,53,(byte)226,(byte)160,37,(byte)210,(byte)208,22,(byte)235,66,6,(byte)248,114,119,(byte)245,45,56,(byte)209,(byte)152,(byte)139,120,(byte)205,54};
  static final byte[] INITIAL_CHAIN_HASH = new byte[]{34,17,(byte)179,97,8,26,(byte)197,102,105,18,67,(byte)219,69,(byte)138,(byte)213,50,45,(byte)156,108,102,34,(byte)147,(byte)232,(byte)183,14,(byte)225,(byte)156,101,(byte)186,7,(byte)158,(byte)243};
  static final byte[] LABEL_MAC1 = "mac1----".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

  static byte[] b2sHash(byte[] a, byte[] b){
    try{ org.bouncycastle.crypto.digests.Blake2sDigest d=new org.bouncycastle.crypto.digests.Blake2sDigest(32); d.update(a,0,a.length); d.update(b,0,b.length); byte[] o=new byte[32]; d.doFinal(o,0); return o; }catch(Exception e){ throw new RuntimeException(e); }
  }
  static byte[] b2sHmac(byte[] key, byte[] data){
    try{ org.bouncycastle.crypto.macs.HMac m=new org.bouncycastle.crypto.macs.HMac(new org.bouncycastle.crypto.digests.Blake2sDigest(32)); m.init(new KeyParameter(key)); m.update(data,0,data.length); byte[] o=new byte[32]; m.doFinal(o,0); return o; }catch(Exception e){ throw new RuntimeException(e); }
  }
  static byte[] b2sHmac2(byte[] key, byte[] d1, byte[] d2){
    try{ org.bouncycastle.crypto.macs.HMac m=new org.bouncycastle.crypto.macs.HMac(new org.bouncycastle.crypto.digests.Blake2sDigest(32)); m.init(new KeyParameter(key)); m.update(d1,0,d1.length); m.update(d2,0,d2.length); byte[] o=new byte[32]; m.doFinal(o,0); return o; }catch(Exception e){ throw new RuntimeException(e); }
  }
  static byte[] b2sKeyedMac16(byte[] key, byte[] data){
    try{ org.bouncycastle.crypto.digests.Blake2sDigest d=new org.bouncycastle.crypto.digests.Blake2sDigest(16, key); d.update(data,0,data.length); byte[] o=new byte[16]; d.doFinal(o,0); return o; }catch(Exception e){ throw new RuntimeException(e); }
  }
  static void aeadSeal(byte[] out, byte[] key, long counter, byte[] plain, byte[] aad){
    try{
      byte[] nonce=new byte[12]; ByteBuffer.wrap(nonce,4,8).putLong(counter);
      // ring uses LittleEndian for counter in nonce[4..12] — but boringtun uses LE u64 at 4..12
      // BouncyCastle ChaCha7539 expects 12B nonce LE as well
      org.bouncycastle.crypto.engines.ChaChaEngine engine=new org.bouncycastle.crypto.engines.ChaChaEngine();
      // Use ChaCha20Poly1305 via AEAD: manual Poly1305
      // Simpler: use javax.crypto ChaCha20Poly1305 if available, else BC
      // Here use BouncyCastle's ChaCha20Poly1305
      org.bouncycastle.crypto.modes.ChaCha20Poly1305 aead=new org.bouncycastle.crypto.modes.ChaCha20Poly1305();
      aead.init(true, new org.bouncycastle.crypto.params.AEADParameters(new KeyParameter(key), 128, nonce, aad));
      byte[] ct=new byte[aead.getOutputSize(plain.length)];
      int off=aead.processBytes(plain,0,plain.length, ct,0);
      aead.doFinal(ct, off);
      System.arraycopy(ct,0,out,0,ct.length);
    }catch(Exception e){ throw new RuntimeException(e); }
  }
  static byte[] x25519Dh(byte[] priv32, byte[] pub32){
    X25519PrivateKeyParameters priv=new X25519PrivateKeyParameters(priv32,0);
    X25519PublicKeyParameters pub=new X25519PublicKeyParameters(pub32,0);
    X25519Agreement agree=new X25519Agreement(); agree.init(priv);
    byte[] shared=new byte[32]; agree.calculateAgreement(pub, shared, 0); return shared;
  }
  static byte[] x25519PubFromPriv(byte[] priv32){
    return new X25519PrivateKeyParameters(priv32,0).generatePublicKey().getEncoded();
  }
  // Build a REAL boringtun-compatible WG init (148B) with random ephemeral + static derived from random local priv
  static byte[] buildWgInitReal() {
    byte[] localPriv=new byte[32]; new SecureRandom().nextBytes(localPriv);
    localPriv[0]&=(byte)248; localPriv[31]&=(byte)127; localPriv[31]|=(byte)64;
    byte[] localPub=x25519PubFromPriv(localPriv);
    byte[] ephPriv=new byte[32]; new SecureRandom().nextBytes(ephPriv);
    ephPriv[0]&=(byte)248; ephPriv[31]&=(byte)127; ephPriv[31]|=(byte)64;
    byte[] ephPub=x25519PubFromPriv(ephPriv);

    byte[] chainingKey=INITIAL_CHAIN_KEY.clone();
    byte[] hash=b2sHash(INITIAL_CHAIN_HASH, CF_PEER_PUB_RAW);

    byte[] pkt=new byte[148];
    // msg type 1 LE
    pkt[0]=1; pkt[1]=0; pkt[2]=0; pkt[3]=0;
    int senderIdx=new SecureRandom().nextInt() & 0x00FFFFFF | 0x01000000; // non-zero 24-bit
    ByteBuffer.wrap(pkt,4,4).order(ByteOrder.LITTLE_ENDIAN).putInt(senderIdx);
    System.arraycopy(ephPub,0,pkt,8,32);
    hash=b2sHash(hash, ephPub);
    byte[] temp=b2sHmac(chainingKey, ephPub);
    chainingKey=b2sHmac(temp, new byte[]{0x01});
    byte[] ephShared=x25519Dh(ephPriv, CF_PEER_PUB_RAW);
    temp=b2sHmac(chainingKey, ephShared);
    chainingKey=b2sHmac(temp, new byte[]{0x01});
    byte[] key=b2sHmac2(temp, chainingKey, new byte[]{0x02});
    byte[] encStatic=new byte[48];
    aeadSeal(encStatic, key, 0, localPub, hash);
    System.arraycopy(encStatic,0,pkt,40,48);
    hash=b2sHash(hash, encStatic);
    byte[] staticShared=x25519Dh(localPriv, CF_PEER_PUB_RAW);
    temp=b2sHmac(chainingKey, staticShared);
    chainingKey=b2sHmac(temp, new byte[]{0x01});
    key=b2sHmac2(temp, chainingKey, new byte[]{0x02});
    // timestamp TAI64N 12B
    byte[] tai=new byte[12]; ByteBuffer.wrap(tai).order(ByteOrder.BIG_ENDIAN).putLong(System.currentTimeMillis()/1000L + 4611686018427387914L).putInt(new SecureRandom().nextInt());
    // boringtun Tai64N::now() = seconds since 1970 + 2^62
    byte[] encTs=new byte[28];
    aeadSeal(encTs, key, 0, tai, hash);
    System.arraycopy(encTs,0,pkt,88,28);
    hash=b2sHash(hash, encTs);
    // MAC1 = BLAKE2sMac16(key=HASH(LABEL_MAC1||peer_pub), data=pkt[0..116])
    byte[] macKey=b2sHash(LABEL_MAC1, CF_PEER_PUB_RAW);
    byte[] mac1=b2sKeyedMac16(macKey, Arrays.copyOf(pkt, 116));
    System.arraycopy(mac1,0,pkt,116,16);
    // MAC2 zero
    return pkt;
  }

  boolean probeUdp(String ip, int port) {
    DatagramSocket sock=null;
    try{
      InetAddress addr=InetAddress.getByName(ip);
      sock=new DatagramSocket();
      sock.setSoTimeout(2500);
      byte[] out=buildWgInitReal();
      DatagramPacket p=new DatagramPacket(out,out.length,addr,port);
      sock.send(p);
      byte[] buf=new byte[2048];
      DatagramPacket in=new DatagramPacket(buf,buf.length);
      try{ sock.receive(in); }catch(SocketTimeoutException e1){ sock.send(p); sock.receive(in); }
      int n=in.getLength(); sock.close();
      if(n<32) return false;
      int msgType=buf[0]&0xFF; return msgType==2 || msgType==4;
    }catch(Exception e){ if(sock!=null) try{sock.close();}catch(Exception x){} return false; }
  }

  boolean probeEndpoint(String ip, int port){ return probeUdp(ip,port); }

  void startScan() {
    if (pool != null) pool.shutdownNow();
    abort.set(false); okList.clear(); ad.notifyDataSetChanged();
    tvLog.setText("");
    log("[*] === PARVAZ WG SCAN (FCAE-matched) ===");
    List<int[]> cands = buildCandidates();
    log("[*] candidates: "+cands.size()+"  ports: "+WG_PORTS.length+"  prefixes: "+PREFIXES.length);
    stat("scanning "+cands.size()+"...");
    pool = Executors.newFixedThreadPool(16);
    final int total=cands.size();
    final int[] done={0};
    for(int[] cand: cands){
      pool.execute(()->{
        if(abort.get()) return;
        String ip=cand[0]+"."+cand[1]+"."+cand[2]+"."+cand[3]; int port=cand[4];
        long t0=System.nanoTime();
        boolean ok=probeEndpoint(ip,port);
        long rtt=(System.nanoTime()-t0)/1_000_000;
        int dn; synchronized(done){ dn=++done[0]; }
        if(ok){
          okList.add(new Result(ip,port,rtt));
          synchronized(okList){ Collections.sort(okList,(x,y)-> Long.compare(x.rtt,y.rtt)); }
          runOnUiThread(()->{ ad.notifyDataSetChanged(); log("[+] OPEN  "+ip+":"+port+"  RTT="+rtt+"ms"); });
        }
        if(dn%400==0) stat(dn+"/"+total+"  open:"+okList.size());
        if(dn==total){
          stat("DONE — "+okList.size()+"/"+total+" open");
          if(okList.size()>0) log("[+] best: "+topStr());
          else log("[-] no open — try different network / mode");
        }
      });
    }
  }
  String topStr(){ StringBuilder sb=new StringBuilder(); for(int i=0;i<Math.min(5,okList.size());i++){ if(i>0) sb.append(", "); sb.append(okList.get(i).ep()); } return sb.toString(); }
  void copyAll(){ if(okList.isEmpty()){ Toast.makeText(this,"no results",Toast.LENGTH_SHORT).show(); return; } StringBuilder sb=new StringBuilder(); for(Result r: okList) sb.append(r.ep()).append("\n"); ClipboardManager cm=(ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE); cm.setPrimaryClip(ClipData.newPlainText("eps", sb.toString().trim())); Toast.makeText(this, okList.size()+" copied",Toast.LENGTH_SHORT).show(); }
  void sendToBot(){ if(okList.isEmpty()){ Toast.makeText(this,"no results",Toast.LENGTH_SHORT).show(); return; } String best=okList.get(0).ep(); ClipboardManager cm=(ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE); cm.setPrimaryClip(ClipData.newPlainText("ep", best)); Toast.makeText(this,"copied: "+best,Toast.LENGTH_LONG).show(); try{ startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/parvazpanelbot?start="+Uri.encode(best)))); }catch(Exception e){ log("[-] bot open failed: "+e.getMessage()); } }
  static class Adapter extends RecyclerView.Adapter<Adapter.VH>{
    List<Result> list; Adapter(List<Result> l){list=l;}
    static class VH extends RecyclerView.ViewHolder{ TextView tv; Button b1,b2; VH(View v){super(v); tv=v.findViewById(android.R.id.text1); b1=v.findViewById(android.R.id.button1); b2=v.findViewById(android.R.id.button2);} }
    @Override public VH onCreateViewHolder(ViewGroup p,int t){
      LinearLayout row=new LinearLayout(p.getContext()); row.setOrientation(LinearLayout.HORIZONTAL); row.setPadding(10,8,10,8);
      TextView tv=new TextView(p.getContext()); tv.setId(android.R.id.text1); tv.setTextColor(0xFFE6EEFC); tv.setTextSize(12); tv.setLayoutParams(new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT,1)); tv.setTypeface(android.graphics.Typeface.MONOSPACE);
      Button b1=new Button(p.getContext()); b1.setId(android.R.id.button1); b1.setText("copy"); b1.setTextSize(11);
      Button b2=new Button(p.getContext()); b2.setId(android.R.id.button2); b2.setText("bot"); b2.setTextSize(11); b2.setAllCaps(false);
      row.addView(tv); row.addView(b1); row.addView(b2); return new VH(row);
    }
    @Override public void onBindViewHolder(VH h,int pos){
      Result r=list.get(pos); h.tv.setText(r.ep()+"  "+r.rtt+"ms");
      h.b1.setOnClickListener(v->{ ClipboardManager cm=(ClipboardManager)v.getContext().getSystemService(Context.CLIPBOARD_SERVICE); cm.setPrimaryClip(ClipData.newPlainText("ep", r.ep())); Toast.makeText(v.getContext(),"copied: "+r.ep(),Toast.LENGTH_SHORT).show(); });
      h.b2.setOnClickListener(v->{ ClipboardManager cm=(ClipboardManager)v.getContext().getSystemService(Context.CLIPBOARD_SERVICE); cm.setPrimaryClip(ClipData.newPlainText("ep", r.ep())); try{ v.getContext().startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/parvazpanelbot?start="+Uri.encode(r.ep())))); }catch(Exception e){ Toast.makeText(v.getContext(),e.getMessage(),Toast.LENGTH_SHORT).show(); } });
    }
    @Override public int getItemCount(){ return list.size(); }
  }
}
