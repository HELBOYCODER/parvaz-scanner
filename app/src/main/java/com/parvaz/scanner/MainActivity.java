package com.parvaz.scanner;

import android.content.*;
import android.net.Uri;
import android.os.*;
import android.view.*;
import android.widget.*;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.security.SecureRandom;

public class MainActivity extends AppCompatActivity {
  static final int[] WG_PORTS = {
    500,854,859,864,878,880,890,891,894,903,
    908,928,934,939,942,943,945,946,955,968,
    987,988,1002,1010,1014,1018,1070,1074,1180,1387,
    1701,1843,2371,2408,2506,3138,3476,3581,3854,4177,
    4198,4233,4500,5279,5956,7103,7152,7156,7281,7559,8319,8742,8854,8886
  };
  static final String[] IPV4_PREFIXES = {
    "188.114.96.", "188.114.97.", "188.114.98.", "188.114.99.",
    "162.159.192.", "162.159.193.", "162.159.195.",
    "8.34.146.", "8.39.214.", "8.39.204.", "8.6.112.",
    "8.35.211.", "8.39.125.", "8.47.69."
  };
  static final String[] IPV6_PREFIXES = { "2606:4700:d0::", "2606:4700:d1::" };

  // UI
  TextView tvLog, tvStat, tvStatCount, tvStatOk, tvStatRtt, tvCount, tvLive;
  View btnScan, btnStop;
  View btnCopyAll, btnCopyTop5, btnCopyTop, btnCopyCSV, btnShare, btnBot;
  Spinner spCount;
  ProgressBar prog;
  RecyclerView rv; Adapter ad;

  ExecutorService pool;
  AtomicBoolean abort = new AtomicBoolean(false);
  List<Result> okList = Collections.synchronizedList(new ArrayList<>());
  int scanCount = 1000;

  static class Result {
    String ip; int port; long rtt;
    String ep(){ return ip+":"+port; }
    Result(String ip,int port,long rtt){ this.ip=ip; this.port=port; this.rtt=rtt; }
  }

  @Override protected void onCreate(Bundle b){
    super.onCreate(b);
    setContentView(R.layout.activity_main);

    tvLog=findViewById(R.id.tvLog); tvStat=findViewById(R.id.tvStat);
    tvStatCount=findViewById(R.id.tvStatCount); tvStatOk=findViewById(R.id.tvStatOk);
    tvStatRtt=findViewById(R.id.tvStatRtt); tvCount=findViewById(R.id.tvCount);
    tvLive=findViewById(R.id.tvLive);
    prog=findViewById(R.id.prog);
    btnScan=findViewById(R.id.btnScan); btnStop=findViewById(R.id.btnStop);
    btnCopyAll=findViewById(R.id.btnCopyAll); btnCopyTop5=findViewById(R.id.btnCopyTop5);
    btnCopyTop=findViewById(R.id.btnCopyTop); btnCopyCSV=findViewById(R.id.btnCopyCSV);
    btnShare=findViewById(R.id.btnShare); btnBot=findViewById(R.id.btnBot);
    spCount=findViewById(R.id.spCount);
    rv=findViewById(R.id.rv); rv.setLayoutManager(new LinearLayoutManager(this));
    ad=new Adapter(okList); rv.setAdapter(ad);

    // spinner: تعداد IP
    String[] opts = {"1,000  (سریع)", "5,000  (متعادل)", "10,000  (دقیق)", "20,000  (حرفه‌ای)", "50,000  (غول)"};
    int[] vals = {1000,5000,10000,20000,50000};
    ArrayAdapter<String> spAd = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, opts);
    spAd.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
    spCount.setAdapter(spAd);
    spCount.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener(){
      public void onItemSelected(AdapterView<?> p, View v,int pos,long id){
        scanCount = vals[pos];
        tvStatCount.setText(String.format("%,d", scanCount));
        tvStat.setText("آماده — "+scanCount+" اندپوینت × 54 پورت");
      }
      public void onNothingSelected(AdapterView<?> p){}
    });

    btnScan.setOnClickListener(v-> startScan());
    btnStop.setOnClickListener(v->{ abort.set(true); log("[-] توقف درخواست شد"); toast("⏹ متوقف شد"); });
    btnCopyAll.setOnClickListener(v-> copyAll());
    btnCopyTop5.setOnClickListener(v-> copyTop(5));
    btnCopyTop.setOnClickListener(v-> copyTop(1));
    btnCopyCSV.setOnClickListener(v-> copyCSV());
    btnShare.setOnClickListener(v-> shareAll());
    btnBot.setOnClickListener(v-> sendToBot());

    // long-press log to copy/clear
    tvLog.setOnLongClickListener(v->{
      PopupMenu m=new PopupMenu(this, v);
      m.getMenu().add("📋 کپی لاگ").setOnMenuItemClickListener(i->{ copyClip("log", tvLog.getText().toString()); return true; });
      m.getMenu().add("🗑 پاک کردن").setOnMenuItemClickListener(i->{ tvLog.setText(""); return true; });
      m.show(); return true;
    });
  }

  void log(String s){ runOnUiThread(()-> tvLog.append("\n"+s)); }
  void toast(String s){ Toast.makeText(this, s, Toast.LENGTH_SHORT).show(); }
  void copyClip(String label, String txt){
    ClipboardManager cm=(ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);
    cm.setPrimaryClip(ClipData.newPlainText(label, txt));
    toast("📋 کپی شد");
  }

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
    // pad if dedup removed some
    while(out.size()<count){
      String pfx=IPV4_PREFIXES[sr.nextInt(IPV4_PREFIXES.length)];
      String ip=pfx+sr.nextInt(256);
      int port=WG_PORTS[sr.nextInt(WG_PORTS.length)];
      String k=ip+":"+port;
      if(seen.add(k)) out.add(new String[]{ip,String.valueOf(port)});
    }
    Collections.shuffle(out, sr);
    return out;
  }

  boolean scanUdp(String ip, int port, int timeoutMs){
    DatagramSocket sock=null;
    try{
      String clean = ip.startsWith("[") && ip.endsWith("]") ? ip.substring(1,ip.length()-1) : ip;
      InetAddress addr=InetAddress.getByName(clean);
      sock=new DatagramSocket(); sock.setSoTimeout(timeoutMs);
      byte[] out=new byte[64]; new SecureRandom().nextBytes(out);
      sock.send(new DatagramPacket(out,out.length,addr,port));
      byte[] buf=new byte[2048];
      DatagramPacket in=new DatagramPacket(buf,buf.length);
      sock.receive(in);
      sock.close();
      return in.getLength()>0;
    }catch(Exception e){ if(sock!=null) try{sock.close();}catch(Exception x){} return false; }
  }

  long tcpRtt(String ip){
    String clean = ip.startsWith("[") && ip.endsWith("]") ? ip.substring(1,ip.length()-1) : ip;
    try{
      long t0=System.nanoTime();
      Socket s=new Socket(); s.connect(new InetSocketAddress(clean,443),3000); s.close();
      return (System.nanoTime()-t0)/1_000_000;
    }catch(Exception e){ return -1; }
  }

  void startScan(){
    if(pool!=null) pool.shutdownNow();
    abort.set(false); okList.clear(); ad.notifyDataSetChanged();
    tvLog.setText(""); prog.setProgress(0); tvCount.setText("0"); tvStatOk.setText("—");
    log("[*] === PARVAZ SCAN v1.4 — BPB-matched ===");
    log("[*] "+scanCount+" endpoints × 54 ports — 14 IPv4 + 2 IPv6 prefixes");
    List<String[]> eps=genEndpoints(scanCount);
    log("[*] تولید شد: "+eps.size()+" اندپوینت — شروع اسکن…");
    tvStat.setText("⏳ در حال اسکن "+eps.size()+" …");
    tvLive.setText("● SCANNING"); tvLive.setTextColor(0xFFEAB308);
    pool=Executors.newFixedThreadPool(50);
    final int total=eps.size();
    AtomicInteger done=new AtomicInteger(0), found=new AtomicInteger(0);
    long tStart=System.currentTimeMillis();
    for(String[] ep: eps){
      pool.execute(()->{
        if(abort.get()) return;
        String ip=ep[0]; int port=Integer.parseInt(ep[1]);
        long t0=System.nanoTime();
        if(scanUdp(ip,port,2000)){
          long rtt=tcpRtt(ip);
          if(rtt<0) rtt=(System.nanoTime()-t0)/1_000_000;
          Result r=new Result(ip,port,rtt);
          okList.add(r);
          synchronized(okList){ Collections.sort(okList,(a,b)-> Long.compare(a.rtt,b.rtt)); }
          int f=found.incrementAndGet();
          runOnUiThread(()->{
            ad.notifyDataSetChanged();
            tvCount.setText(String.valueOf(f));
            tvStatOk.setText(String.valueOf(f));
            if(f==1) tvStatRtt.setText(r.rtt+"ms بهترین");
            log("[+] OPEN  "+ip+":"+port+"  "+r.rtt+"ms  (#"+f+")");
          });
        }
        int dn=done.incrementAndGet();
        int pct=(int)(dn*100L/total);
        runOnUiThread(()-> prog.setProgress(pct));
        if(dn%200==0 || dn==total) runOnUiThread(()-> tvStat.setText(dn+"/"+total+" — سالم: "+found.get()));
        if(dn==total){
          long sec=(System.currentTimeMillis()-tStart)/1000;
          runOnUiThread(()->{
            prog.setProgress(100);
            tvLive.setText("● DONE"); tvLive.setTextColor(0xFF22C55E);
            tvStat.setText("✅ تمام — "+found.get()+"/"+total+" سالم در "+sec+"s");
            if(found.get()>0){ log("[★] بهترین: "+topStr(3)); toast("✅ "+found.get()+" سالم پیدا شد"); }
            else { log("[-] چیزی پیدا نشد — دوباره تست کن / نت را عوض کن"); }
          });
        }
      });
    }
  }

  String topStr(int n){
    StringBuilder sb=new StringBuilder();
    for(int i=0;i<Math.min(n,okList.size());i++){ if(i>0) sb.append(", "); sb.append(okList.get(i).ep()); }
    return sb.toString();
  }

  // ====== کپی حرفه‌ای ======
  void copyAll(){
    if(okList.isEmpty()){ toast("نتیجه‌ای نیست"); return; }
    StringBuilder sb=new StringBuilder();
    for(Result r: okList) sb.append(r.ep()).append("\n");
    copyClip("all", sb.toString().trim());
    toast("📋 "+okList.size()+" کپی شد");
  }
  void copyTop(int n){
    if(okList.isEmpty()){ toast("نتیجه‌ای نیست"); return; }
    int k=Math.min(n, okList.size());
    StringBuilder sb=new StringBuilder();
    for(int i=0;i<k;i++) sb.append(okList.get(i).ep()).append("\n");
    copyClip("top"+k, sb.toString().trim());
    toast("⭐ "+k+" برتر کپی شد");
  }
  void copyCSV(){
    if(okList.isEmpty()){ toast("نتیجه‌ای نیست"); return; }
    StringBuilder sb=new StringBuilder("ip,port,rtt_ms\n");
    for(Result r: okList) sb.append(r.ip.replace("[","").replace("]","")).append(",").append(r.port).append(",").append(r.rtt).append("\n");
    copyClip("csv", sb.toString().trim());
    toast("📄 CSV کپی شد ("+okList.size()+" ردیف)");
  }
  void shareAll(){
    if(okList.isEmpty()){ toast("نتیجه‌ای نیست"); return; }
    StringBuilder sb=new StringBuilder("Parvaz Scanner — "+okList.size()+" سالم (بهترین اول):\n");
    for(Result r: okList) sb.append(r.ep()).append("  ").append(r.rtt).append("ms\n");
    Intent it=new Intent(Intent.ACTION_SEND); it.setType("text/plain"); it.putExtra(Intent.EXTRA_TEXT, sb.toString());
    startActivity(Intent.createChooser(it, "اشتراک نتایج"));
  }
  void sendToBot(){
    if(okList.isEmpty()){ toast("نتیجه‌ای نیست"); return; }
    String best=okList.get(0).ep();
    copyClip("best", best);
    try{ startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/parvazpanelbot?start="+Uri.encode(best)))); }
    catch(Exception e){ toast(e.getMessage()); }
  }

  // ====== Adapter پرمیوم ======
  static class Adapter extends RecyclerView.Adapter<Adapter.VH>{
    List<Result> list; Adapter(List<Result> l){ list=l; }
    static class VH extends RecyclerView.ViewHolder{
      TextView tvRank, tvEp, tvRtt, tvBadge; View btnCopy, btnShare;
      VH(View v){ super(v);
        tvRank=v.findViewById(1001); tvEp=v.findViewById(1002); tvRtt=v.findViewById(1003);
        tvBadge=v.findViewById(1004); btnCopy=v.findViewById(1005); btnShare=v.findViewById(1006);
      }
    }
    @Override public VH onCreateViewHolder(ViewGroup p,int t){
      android.content.Context c=p.getContext();
      LinearLayout card=new LinearLayout(c); card.setOrientation(LinearLayout.HORIZONTAL);
      card.setGravity(Gravity.CENTER_VERTICAL); card.setPadding(12,10,12,10);
      card.setBackgroundResource(R.drawable.bg_card);
      LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
      lp.setMargins(0,6,0,0); card.setLayoutParams(lp);

      TextView rank=new TextView(c); rank.setId(1001); rank.setTextColor(0xFF5B6B8A); rank.setTextSize(11); rank.setTypeface(android.graphics.Typeface.MONOSPACE);
      rank.setLayoutParams(new LinearLayout.LayoutParams(36, LinearLayout.LayoutParams.WRAP_CONTENT));

      LinearLayout mid=new LinearLayout(c); mid.setOrientation(LinearLayout.VERTICAL);
      mid.setLayoutParams(new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT,1));
      TextView ep=new TextView(c); ep.setId(1002); ep.setTextColor(0xFFE6EEFC); ep.setTextSize(12); ep.setTypeface(android.graphics.Typeface.MONOSPACE);
      TextView rtt=new TextView(c); rtt.setId(1003); rtt.setTextColor(0xFF8AA0C8); rtt.setTextSize(10);
      mid.addView(ep); mid.addView(rtt);

      TextView badge=new TextView(c); badge.setId(1004); badge.setTextSize(10); badge.setTextColor(0xFF22C55E);
      badge.setBackgroundResource(R.drawable.bg_chip); badge.setPadding(8,4,8,4);
      badge.setVisibility(View.GONE);

      TextView bCopy=new TextView(c); bCopy.setId(1005); bCopy.setText("📋"); bCopy.setTextSize(14);
      bCopy.setGravity(Gravity.CENTER); bCopy.setPadding(10,6,10,6); bCopy.setBackgroundResource(R.drawable.bg_chip);
      TextView bShare=new TextView(c); bShare.setId(1006); bShare.setText("↗"); bShare.setTextSize(14);
      bShare.setGravity(Gravity.CENTER); bShare.setPadding(10,6,10,6); bShare.setBackgroundResource(R.drawable.bg_chip);
      LinearLayout.LayoutParams bp=new LinearLayout.LayoutParams(44,44); bp.setMargins(6,0,0,0);
      bCopy.setLayoutParams(bp); bShare.setLayoutParams(bp);

      card.addView(rank); card.addView(mid); card.addView(badge); card.addView(bCopy); card.addView(bShare);
      return new VH(card);
    }
    @Override public void onBindViewHolder(VH h,int pos){
      Result r=list.get(pos);
      h.tvRank.setText("#"+(pos+1));
      h.tvEp.setText(r.ep());
      String speed = r.rtt<80?"⚡ ":""; 
      h.tvRtt.setText(speed + r.rtt+"ms  •  :"+r.port);
      if(pos==0){ h.tvBadge.setVisibility(View.VISIBLE); h.tvBadge.setText("👑 BEST"); h.tvBadge.setTextColor(0xFF070B1E);
        h.tvBadge.setBackgroundResource(R.drawable.btn_primary); }
      else if(pos<3){ h.tvBadge.setVisibility(View.VISIBLE); h.tvBadge.setText("★ TOP"); h.tvBadge.setTextColor(0xFFEAB308); h.tvBadge.setBackgroundResource(R.drawable.bg_chip); }
      else h.tvBadge.setVisibility(View.GONE);

      h.btnCopy.setOnClickListener(v->{
        ClipboardManager cm=(ClipboardManager)v.getContext().getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("ep", r.ep()));
        Toast.makeText(v.getContext(),"📋 "+r.ep(),Toast.LENGTH_SHORT).show();
      });
      h.btnShare.setOnClickListener(v->{
        ClipboardManager cm=(ClipboardManager)v.getContext().getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("ep", r.ep()));
        Intent it=new Intent(Intent.ACTION_SEND); it.setType("text/plain"); it.putExtra(Intent.EXTRA_TEXT, r.ep()+"  "+r.rtt+"ms");
        v.getContext().startActivity(Intent.createChooser(it, r.ep()));
      });
      h.itemView.setOnLongClickListener(v->{
        PopupMenu m=new PopupMenu(v.getContext(), v);
        m.getMenu().add("📋 کپی").setOnMenuItemClickListener(i->{
          ClipboardManager cm=(ClipboardManager)v.getContext().getSystemService(Context.CLIPBOARD_SERVICE);
          cm.setPrimaryClip(ClipData.newPlainText("ep", r.ep()));
          Toast.makeText(v.getContext(),"کپی شد: "+r.ep(),Toast.LENGTH_SHORT).show(); return true;
        });
        m.getMenu().add("↗ اشتراک").setOnMenuItemClickListener(i->{
          Intent it=new Intent(Intent.ACTION_SEND); it.setType("text/plain"); it.putExtra(Intent.EXTRA_TEXT, r.ep());
          v.getContext().startActivity(Intent.createChooser(it, r.ep())); return true;
        });
        m.getMenu().add("🤖 ارسال به ربات").setOnMenuItemClickListener(i->{
          try{ v.getContext().startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/parvazpanelbot?start="+Uri.encode(r.ep())))); }catch(Exception e){}
          return true;
        });
        m.show(); return true;
      });
    }
    @Override public int getItemCount(){ return list.size(); }
  }
}
