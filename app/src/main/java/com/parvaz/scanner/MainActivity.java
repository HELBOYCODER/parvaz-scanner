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
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class MainActivity extends AppCompatActivity {
  // === BPB-matched: 54 ports ===
  static final int[] WG_PORTS = {
    500,854,859,864,878,880,890,891,894,903,
    908,928,934,939,942,943,945,946,955,968,
    987,988,1002,1010,1014,1018,1070,1074,1180,1387,
    1701,1843,2371,2408,2506,3138,3476,3581,3854,4177,
    4198,4233,4500,5279,5956,7103,7152,7156,7281,7559,8319,8742,8854,8886
  };
  // === BPB-matched: 14 IPv4 prefixes ===
  static final String[] IPV4_PREFIXES = {
    "188.114.96.", "188.114.97.", "188.114.98.", "188.114.99.",
    "162.159.192.", "162.159.193.", "162.159.195.",
    "8.34.146.", "8.39.214.", "8.39.204.", "8.6.112.",
    "8.35.211.", "8.39.125.", "8.47.69."
  };
  // === BPB-matched: 2 IPv6 prefixes ===
  static final String[] IPV6_PREFIXES = {
    "2606:4700:d0::", "2606:4700:d1::"
  };

  TextView tvLog, tvStat; Button btnScan, btnStop, btnCopy, btnBot;
  RecyclerView rv; Adapter ad;
  ExecutorService pool; AtomicBoolean abort = new AtomicBoolean(false);
  List<Result> okList = Collections.synchronizedList(new ArrayList<>());

  static class Result { String ip; int port; long rtt; long loss; String ep(){ return ip+":"+port; } Result(String ip,int port,long rtt,long loss){this.ip=ip;this.port=port;this.rtt=rtt;this.loss=loss;} }

  @Override protected void onCreate(Bundle b){
    super.onCreate(b); setContentView(R.layout.activity_main);
    tvLog=findViewById(R.id.tvLog); tvStat=findViewById(R.id.tvStat);
    btnScan=findViewById(R.id.btnScan); btnStop=findViewById(R.id.btnStop);
    btnCopy=findViewById(R.id.btnCopy); btnBot=findViewById(R.id.btnBot);
    rv=findViewById(R.id.rv); rv.setLayoutManager(new LinearLayoutManager(this));
    ad=new Adapter(okList); rv.setAdapter(ad);
    btnScan.setOnClickListener(v-> startScan());
    btnStop.setOnClickListener(v-> { abort.set(true); log("[-] stopped"); });
    btnCopy.setOnClickListener(v-> copyAll());
    btnBot.setOnClickListener(v-> sendToBot());
  }
  void log(String s){ runOnUiThread(()->{ tvLog.append("\n"+s); }); }
  void stat(String s){ runOnUiThread(()-> tvStat.setText(s)); }

  // BPB generateEndpoints: random sample 1000 endpoints (500 v4 + 500 v6 preferred)
  List<String[]> genEndpoints(int count){
    List<String[]> out=new ArrayList<>();
    Set<String> seen=new HashSet<>();
    SecureRandom sr=new SecureRandom();
    int v4=count*2/3, v6=count-v4;
    for(int i=0;i<v4;i++){
      String pfx=IPV4_PREFIXES[sr.nextInt(IPV4_PREFIXES.length)];
      String ip=pfx+sr.nextInt(256);
      int port=WG_PORTS[sr.nextInt(WG_PORTS.length)];
      String k=ip+":"+port;
      if(seen.add(k)) out.add(new String[]{ip,String.valueOf(port)});
    }
    for(int i=0;i<v6;i++){
      String pfx=IPV6_PREFIXES[sr.nextInt(IPV6_PREFIXES.length)];
      String ip="["+pfx+Integer.toHexString(sr.nextInt(65536))+":"+Integer.toHexString(sr.nextInt(65536))+":"+Integer.toHexString(sr.nextInt(65536))+":"+Integer.toHexString(sr.nextInt(65536))+"]";
      int port=WG_PORTS[sr.nextInt(WG_PORTS.length)];
      String k=ip+":"+port;
      if(seen.add(k)) out.add(new String[]{ip,String.valueOf(port)});
    }
    return out;
  }

  // BPB scanPort: TCP dial + UDP noise ping, any reply (>0 bytes) = open
  boolean scanUdp(String ip, int port, int timeoutMs){
    DatagramSocket sock=null;
    try{
      String cleanIp = ip.startsWith("[") && ip.endsWith("]") ? ip.substring(1,ip.length()-1) : ip;
      InetAddress addr=InetAddress.getByName(cleanIp);
      sock=new DatagramSocket();
      sock.setSoTimeout(timeoutMs);
      // BPB noise ping: 64 bytes random works because bpbscanner doesn't verify handshake,
      // it checks that UDP socket receives ANY reply (port open, not filtered)
      byte[] out=new byte[64]; new SecureRandom().nextBytes(out);
      DatagramPacket p=new DatagramPacket(out,out.length,addr,port);
      sock.send(p);
      byte[] buf=new byte[2048];
      DatagramPacket in=new DatagramPacket(buf,buf.length);
      sock.receive(in);
      sock.close();
      return in.getLength()>0;
    }catch(Exception e){ if(sock!=null) try{sock.close();}catch(Exception x){} return false; }
  }

  // BPB warpTest equivalent: latency test via TCP 443 + loss measurement
  // For scanner: quick TCP connect to port 443 measures reachability
  long tcpRtt(String ip){
    String cleanIp = ip.startsWith("[") && ip.endsWith("]") ? ip.substring(1,ip.length()-1) : ip;
    try{
      long t0=System.nanoTime();
      Socket s=new Socket();
      s.connect(new InetSocketAddress(cleanIp,443),3000);
      s.close();
      return (System.nanoTime()-t0)/1_000_000;
    }catch(Exception e){ return -1; }
  }

  void startScan(){
    if(pool!=null) pool.shutdownNow();
    abort.set(false); okList.clear(); ad.notifyDataSetChanged();
    tvLog.setText("");
    log("[*] === PARVAZ SCAN (BPB-matched) ===");
    log("[*] 14 IPv4 + 2 IPv6 prefixes × 54 ports, 1000 random endpoints");
    List<String[]> eps=genEndpoints(1000);
    log("[*] generated "+eps.size()+" endpoints");
    stat("scanning "+eps.size()+"...");
    pool=Executors.newFixedThreadPool(50);
    final int total=eps.size();
    AtomicInteger done=new AtomicInteger(0);
    AtomicInteger found=new AtomicInteger(0);
    for(String[] ep: eps){
      pool.execute(()->{
        if(abort.get()) return;
        String ip=ep[0]; int port=Integer.parseInt(ep[1]);
        long t0=System.nanoTime();
        // BPB two-step: first UDP ping test, survivors get TCP RTT
        if(scanUdp(ip,port,2000)){
          long rtt=tcpRtt(ip);
          if(rtt<0) rtt=(System.nanoTime()-t0)/1_000_000;
          Result r=new Result(ip,port,rtt,0);
          okList.add(r);
          synchronized(okList){ Collections.sort(okList,(x,y)-> Long.compare(x.rtt,y.rtt)); }
          int f=found.incrementAndGet();
          runOnUiThread(()->{ ad.notifyDataSetChanged(); log("[+] OPEN  "+ip+":"+port+"  RTT="+r.rtt+"ms  (#"+f+")"); });
        }
        int dn=done.incrementAndGet();
        if(dn%100==0) stat(dn+"/"+total+"  open:"+found.get());
        if(dn==total){
          stat("DONE — "+found.get()+"/"+total+" open");
          if(found.get()>0) log("[+] best: "+topStr());
          else log("[-] no open — try again / different network");
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
