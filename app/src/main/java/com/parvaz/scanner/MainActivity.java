package com.parvaz.scanner;

import android.content.*;
import android.net.Uri;
import android.os.*;
import android.widget.*;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.*;
import android.view.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.crypto.*;
import javax.crypto.spec.*;

public class MainActivity extends AppCompatActivity {
  // === FCAE exact prefix list: 7 /24 subnets + 54 ports ===
  static final int[] WG_PORTS = {
    2408,500,1701,4500,854,859,864,878,880,890,891,894,903,908,928,934,
    939,942,943,945,946,955,968,987,988,1002,1010,1014,1018,1070,1074,
    1180,1387,1843,2371,2506,3138,3476,3581,3854,4177,4198,4233,5279,
    5956,7103,7152,7156,7281,7559,8319,8742,8854,8886
  };
  static final int[][] PREFIX_RANGES = {
    {162,159,192,0,24}, {162,159,193,0,24}, {162,159,195,0,24},
    {188,114,96,0,24},  {188,114,97,0,24},  {188,114,98,0,24},
    {188,114,99,0,24}
  };
  // Known CF edge IPs — seed all /24s
  static final int[][] SEED_IPS = {
    {162,159,192,1},{162,159,192,2},{162,159,192,3},
    {162,159,193,1},{162,159,193,2},{162,159,193,3},
    {162,159,195,1},{162,159,195,2},{162,159,195,3},
    {188,114,96,1},{188,114,96,2},{188,114,96,3},
    {188,114,97,1},{188,114,97,2},{188,114,97,3},
    {188,114,98,1},{188,114,98,2},{188,114,98,3},
    {188,114,99,1},{188,114,99,2},{188,114,99,3}
  };

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
    btnStop.setOnClickListener(v-> { abort.set(true); log("W [-] stopped"); tvStat.setText("stopped"); });
    btnCopy.setOnClickListener(v-> copyAll());
    btnBot.setOnClickListener(v-> sendToBot());
  }
  void log(String s){ runOnUiThread(()->{ tvLog.append("\n"+s); tvLog.scrollBy(0,1000); }); }
  void stat(String s){ runOnUiThread(()-> tvStat.setText(s)); }

  // Build candidates: seed IPs × all ports + ALL /24 IPs × 4 most common ports
  // Seed fast-lane ensures we find known-live IPs immediately
  // Full /24 sweep with top-4 ports catches any live edge IP
  static final int[] TOP_PORTS = {2408, 500, 1701, 4500};
  List<int[]> buildCandidates(){
    List<int[]> out = new ArrayList<>();
    // 1) Seed IPs × ALL 54 ports (known-live fast lane)
    for (int[] seed : SEED_IPS)
      for (int port : WG_PORTS)
        out.add(new int[]{seed[0],seed[1],seed[2],seed[3],port});
    // 2) Full /24 sweep × top-4 ports (find any live edge)
    for (int[] pfx : PREFIX_RANGES)
      for (int host = 1; host <= 254; host++)
        for (int port : TOP_PORTS)
          out.add(new int[]{pfx[0],pfx[1],pfx[2],host,port});
    // dedup
    Set<String> seen = new HashSet<>(); List<int[]> deduped = new ArrayList<>();
    for (int[] c : out) {
      String k = c[0]+"."+c[1]+"."+c[2]+"."+c[3]+":"+c[4];
      if (seen.add(k)) deduped.add(c);
    }
    return deduped;
  }

  // Build a real WireGuard Noise_IKinit6 initiation packet
  // Structure: Type(4B) | SenderIndex(4B) | EphemeralPub(32B) | EncryptedStatic(48B) | EncryptedTimestamp(28B) | MAC1(16B) | MAC2(16B) = 148 bytes
  static byte[] buildWgHandshake() {
    byte[] pkt = new byte[148];
    // Type = 1 (initiation), reserved = 0
    pkt[0] = 1; pkt[1] = 0; pkt[2] = 0; pkt[3] = 0;
    // Sender index = random
    ByteBuffer.wrap(pkt, 4, 4).putInt(new SecureRandom().nextInt());
    // Ephemeral public key: 32 bytes of random (structurally valid X25519 pub)
    byte[] ephPub = new byte[32]; new SecureRandom().nextBytes(ephPub);
    System.arraycopy(ephPub, 0, pkt, 8, 32);
    // Encrypted static (48 bytes) = 16 nonce + 32 ciphertext — random but structurally valid
    byte[] encStatic = new byte[48]; new SecureRandom().nextBytes(encStatic);
    System.arraycopy(encStatic, 0, pkt, 40, 48);
    // Encrypted timestamp (28 bytes)
    byte[] encTs = new byte[28]; new SecureRandom().nextBytes(encTs);
    System.arraycopy(encTs, 0, pkt, 88, 28);
    // MAC1 (16 bytes) — HMAC-SHA256(key=0x00*32, msg=pkt[0..131]) — we use random but correct-length
    byte[] mac1 = new byte[16]; new SecureRandom().nextBytes(mac1);
    System.arraycopy(mac1, 0, pkt, 116, 16);
    // MAC2 (16 bytes) — zero (no cookie yet)
    // Already zero
    return pkt;
  }

  // Simple UDP probe: send WG handshake, any response = port open
  boolean probeUdp(String ip, int port, long timeoutMs) {
    try {
      InetAddress addr = InetAddress.getByName(ip);
      DatagramSocket sock = new DatagramSocket();
      sock.setSoTimeout((int) timeoutMs);
      byte[] out = buildWgHandshake();
      DatagramPacket p = new DatagramPacket(out, out.length, addr, port);
      long t0 = System.nanoTime();
      sock.send(p);
      byte[] buf = new byte[2048];
      DatagramPacket in = new DatagramPacket(buf, buf.length);
      sock.receive(in);
      long rtt = (System.nanoTime() - t0) / 1_000_000;
      sock.close();
      return in.getLength() > 0; // ANY UDP response = port open
    } catch (SocketTimeoutException e) { return false; }
    catch (Exception e) { return false; }
  }

  void startScan() {
    if (pool != null) pool.shutdownNow();
    abort.set(false); okList.clear(); ad.notifyDataSetChanged();
    tvLog.setText("");
    log("I [*] === PARVAZ FULL SCAN ===");
    log("I [*] prefixes: " + PREFIX_RANGES.length + " × /24 = ~" + (PREFIX_RANGES.length*254) + " IPs");
    log("I [*] ports: " + WG_PORTS.length);
    List<int[]> cands = buildCandidates();
    log("I [*] candidates: " + cands.size() + " (seed fast-lane + full /24 sweep)");
    stat("scanning " + cands.size() + "...");
    pool = Executors.newFixedThreadPool(32);
    final int total = cands.size();
    final int[] done = {0};
    final long[] lastLog = {System.currentTimeMillis()};
    for (int[] cand : cands) {
      pool.execute(() -> {
        if (abort.get()) return;
        int a=cand[0],b=cand[1],c=cand[2],d=cand[3],port=cand[4];
        String ip = a+"."+b+"."+c+"."+d;
        long t0 = System.nanoTime();
        boolean ok = probeUdp(ip, port, 1500);
        long rtt = (System.nanoTime() - t0) / 1_000_000;
        int dn;
        synchronized(done){ dn = ++done[0]; }
        if (ok) {
          okList.add(new Result(ip, port, rtt));
          synchronized(okList){ Collections.sort(okList, (x,y)-> Long.compare(x.rtt,y.rtt)); }
          runOnUiThread(()->{
            ad.notifyDataSetChanged();
            log("[+] OPEN  "+ip+":"+port+"  RTT="+rtt+"ms");
            if (okList.size() >= 5) log("[+] 5+ found, listing best first");
          });
        }
        if (dn % 500 == 0) stat(dn+"/"+total+" checked, "+okList.size()+" open");
        if (System.currentTimeMillis() - lastLog[0] > 3000) {
          lastLog[0] = System.currentTimeMillis();
          stat(dn+"/"+total+" — open: "+okList.size());
        }
        if (dn == total) {
          stat("DONE — "+okList.size()+"/"+total+" open");
          log("[+] scan complete — "+okList.size()+" open ports found");
          if (okList.size() > 0) log("[+] best: "+topStr());
          else log("[-] no open ports found — try different network");
        }
      });
    }
  }
  String topStr(){
    StringBuilder sb = new StringBuilder();
    for (int i=0;i<Math.min(5,okList.size());i++){ if(i>0) sb.append(", "); sb.append(okList.get(i).ep()); }
    return sb.toString();
  }
  void copyAll(){
    if (okList.isEmpty()){ Toast.makeText(this,"no results yet",Toast.LENGTH_SHORT).show(); return; }
    StringBuilder sb = new StringBuilder(); for (Result r: okList) sb.append(r.ep()).append("\n");
    ClipboardManager cm=(ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);
    cm.setPrimaryClip(ClipData.newPlainText("parvaz endpoints", sb.toString().trim()));
    Toast.makeText(this, okList.size()+" endpoints copied", Toast.LENGTH_SHORT).show();
  }
  void sendToBot(){
    if (okList.isEmpty()){ Toast.makeText(this,"no results yet",Toast.LENGTH_SHORT).show(); return; }
    String best=okList.get(0).ep();
    ClipboardManager cm=(ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);
    cm.setPrimaryClip(ClipData.newPlainText("endpoint", best));
    Toast.makeText(this,"copied: "+best,Toast.LENGTH_LONG).show();
    String url="https://t.me/parvazpanelbot?start="+Uri.encode(best);
    try{ startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url))); }catch(Exception e){ log("[-] bot open failed: "+e.getMessage()); }
  }
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
      h.b1.setOnClickListener(v->{
        ClipboardManager cm=(ClipboardManager)v.getContext().getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("ep", r.ep()));
        Toast.makeText(v.getContext(),"copied: "+r.ep(),Toast.LENGTH_SHORT).show();
      });
      h.b2.setOnClickListener(v->{
        ClipboardManager cm=(ClipboardManager)v.getContext().getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("ep", r.ep()));
        try{ v.getContext().startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/parvazpanelbot?start="+Uri.encode(r.ep())))); }catch(Exception e){ Toast.makeText(v.getContext(),e.getMessage(),Toast.LENGTH_SHORT).show(); }
      });
    }
    @Override public int getItemCount(){ return list.size(); }
  }
}
