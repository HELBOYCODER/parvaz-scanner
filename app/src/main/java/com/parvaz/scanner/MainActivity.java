package com.parvaz.scanner;

import android.content.*;
import android.net.Uri;
import android.os.*;
import android.view.*;
import android.widget.*;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class MainActivity extends AppCompatActivity {
  // Fallback WG port list (when port=random)
  static final int[] WG_PORTS = {
    500,854,859,864,878,880,890,891,894,903,908,928,934,939,942,943,945,946,955,968,
    987,988,1002,1010,1014,1018,1070,1074,1180,1387,1701,1843,2371,2408,2506,3138,3476,3581,
    3854,4177,4198,4233,4500,5279,5956,7103,7152,7156,7281,7559,8319,8742,8854,8886
  };

  TextView tvLog, tvStat, tvStatCount, tvStatOk, tvStatRtt, tvCount, tvLive;
  View btnScan, btnStop;
  View btnCopyAll, btnCopyTop5, btnCopyTop, btnCopyCSV, btnShare, btnBot, btnCopyVless;
  Spinner spCount, spPort, spThreads, spTimeout;
  CheckBox cbSpeed;
  EditText etCidr;
  ProgressBar prog;
  RecyclerView rv; Adapter ad;

  ExecutorService pool;
  AtomicBoolean abort = new AtomicBoolean(false);
  List<WarpScanEngine.Result> okList = Collections.synchronizedList(new ArrayList<>());
  int scanCount = 1000;
  int cfgPort = 443;
  boolean cfgRandomPort = false;
  int cfgThreads = 32;
  int cfgTimeout = 1200;
  boolean cfgSpeed = false;

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
    btnCopyVless=findViewById(R.id.btnCopyVless);
    spCount=findViewById(R.id.spCount);
    spPort=findViewById(R.id.spPort);
    spThreads=findViewById(R.id.spThreads);
    spTimeout=findViewById(R.id.spTimeout);
    cbSpeed=findViewById(R.id.cbSpeed);
    etCidr=findViewById(R.id.etCidr);
    rv=findViewById(R.id.rv); rv.setLayoutManager(new LinearLayoutManager(this));
    ad=new Adapter(okList); rv.setAdapter(ad);

    // COUNT
    String[] countOpts = {"1,000  (سریع)", "5,000  (متعادل)", "10,000  (دقیق)", "20,000  (حرفه‌ای)", "50,000  (غول)"};
    int[] countVals = {1000,5000,10000,20000,50000};
    ArrayAdapter<String> aCount = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, countOpts);
    aCount.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
    spCount.setAdapter(aCount);
    spCount.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener(){
      public void onItemSelected(AdapterView<?> p, View v,int pos,long id){ scanCount = countVals[pos]; tvStatCount.setText(String.format("%,d", scanCount)); }
      public void onNothingSelected(AdapterView<?> p){}
    });

    // PORT — senpai style: fixed or random per-IP; default 443 (best for CF/WARP TCP RTT)
    String[] portOpts = {"443  (CF/WARP)", "80  (HTTP)", "2408  (WG)", "878  (WG)", "تصادفی WG (54 پورت)"};
    int[] portVals = {443,80,2408,878,-1};
    ArrayAdapter<String> aPort = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, portOpts);
    aPort.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
    spPort.setAdapter(aPort);
    spPort.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener(){
      public void onItemSelected(AdapterView<?> p, View v,int pos,long id){
        if(portVals[pos]==-1){ cfgRandomPort=true; cfgPort=443; } else { cfgRandomPort=false; cfgPort=portVals[pos]; }
      }
      public void onNothingSelected(AdapterView<?> p){}
    });

    // THREADS — senpai: default 16, here default 32 for Warp pool breadth
    String[] thOpts = {"16", "32 (پیشنهادی)", "64", "96", "128"};
    int[] thVals = {16,32,64,96,128};
    ArrayAdapter<String> aTh = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, thOpts);
    aTh.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
    spThreads.setAdapter(aTh);
    spThreads.setSelection(1);
    spThreads.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener(){
      public void onItemSelected(AdapterView<?> p, View v,int pos,long id){ cfgThreads = thVals[pos]; }
      public void onNothingSelected(AdapterView<?> p){}
    });

    // TIMEOUT
    String[] toOpts = {"800ms (تند)", "1200ms (متعادل)", "2000ms (صبور)", "3000ms"};
    int[] toVals = {800,1200,2000,3000};
    ArrayAdapter<String> aTo = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, toOpts);
    aTo.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
    spTimeout.setAdapter(aTo);
    spTimeout.setSelection(1);
    spTimeout.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener(){
      public void onItemSelected(AdapterView<?> p, View v,int pos,long id){ cfgTimeout = toVals[pos]; }
      public void onNothingSelected(AdapterView<?> p){}
    });

    cbSpeed.setOnCheckedChangeListener((btn, checked)-> cfgSpeed=checked);

    btnScan.setOnClickListener(v-> startScan());
    btnStop.setOnClickListener(v->{ abort.set(true); log("[-] توقف درخواست شد"); toast("⏹ متوقف شد"); });
    btnCopyAll.setOnClickListener(v-> copyAll());
    btnCopyTop5.setOnClickListener(v-> copyTop(5));
    btnCopyTop.setOnClickListener(v-> copyTop(1));
    btnCopyCSV.setOnClickListener(v-> copyCSV());
    btnShare.setOnClickListener(v-> shareAll());
    btnBot.setOnClickListener(v-> sendToBot());
    btnCopyVless.setOnClickListener(v-> copyVless());

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

  // Build IP list — senpai trick: CIDR sample; WarpCidr pool or custom CIDR, else WARP pool
  List<String> buildIpList(int count){
    String custom = etCidr.getText().toString().trim();
    Random rnd=new Random();
    if(!custom.isEmpty()){
      WarpCidr.IpRange r=WarpCidr.parse(custom);
      if(r==null){ toast("CIDR نامعتبر: "+custom); return new ArrayList<>(); }
      Set<String> out=new LinkedHashSet<>();
      while(out.size()<count) out.add(r.random(rnd));
      return new ArrayList<>(out);
    }
    return WarpCidr.sampleIps(count, rnd);
  }

  void startScan(){
    if(pool!=null) pool.shutdownNow();
    List<String> ips=buildIpList(scanCount);
    if(ips.isEmpty()) return;
    abort.set(false); okList.clear(); ad.notifyDataSetChanged();
    tvLog.setText(""); prog.setProgress(0); tvCount.setText("0"); tvStatOk.setText("—");
    String portLabel = cfgRandomPort ? "random WG" : String.valueOf(cfgPort);
    log("[*] === PARVAZ WARP v1.5 — senpai×WARP ===");
    log("[*] "+ips.size()+" IPs × port "+portLabel+" | threads="+cfgThreads+" timeout="+cfgTimeout+"ms speed="+(cfgSpeed?"on":"off"));
    tvStat.setText("⏳ اسکن "+ips.size()+" روی :"+portLabel+" …");
    tvLive.setText("● SCANNING"); tvLive.setTextColor(0xFFEAB308);
    pool=Executors.newFixedThreadPool(cfgThreads);
    final int total=ips.size();
    AtomicInteger done=new AtomicInteger(0), found=new AtomicInteger(0);
    long tStart=System.currentTimeMillis();
    Random rnd=new Random();
    for(String ip: ips){
      pool.execute(()->{
        if(abort.get()) return;
        int port = cfgRandomPort ? WG_PORTS[rnd.nextInt(WG_PORTS.length)] : cfgPort;
        WarpScanEngine.Result res=WarpScanEngine.checkLatency(ip, port, cfgTimeout);
        if(res.isClean && cfgSpeed){
          double kbps=WarpScanEngine.checkDownloadSpeed(ip, 500_000, 5000);
          res.speedKBps=kbps;
        }
        if(res.isClean){
          okList.add(res);
          // sort: latency asc, then speed desc when speed test is on
          synchronized(okList){
            Collections.sort(okList,(a,b)->{
              int c=Long.compare(a.latencyMs,b.latencyMs);
              if(c!=0) return c;
              return Double.compare(b.speedKBps, a.speedKBps);
            });
          }
          int f=found.incrementAndGet();
          WarpScanEngine.Result fr=res;
          runOnUiThread(()->{
            ad.notifyDataSetChanged();
            tvCount.setText(String.valueOf(f));
            tvStatOk.setText(String.valueOf(f));
            if(f==1) tvStatRtt.setText(fr.latencyMs+"ms");
            String extra = cfgSpeed && fr.speedKBps>0 ? String.format("  %.0f KB/s", fr.speedKBps) : "";
            log("[+] "+fr.ep()+"  "+fr.latencyMs+"ms"+extra+"  (#"+f+")");
          });
        }
        int dn=done.incrementAndGet();
        int pct=(int)(dn*100L/total);
        runOnUiThread(()-> prog.setProgress(pct));
        if(dn%200==0 || dn==total) runOnUiThread(()-> tvStat.setText(dn+"/"+total+" — سالم: "+found.get()));
        if(dn==total){
          long sec=(System.currentTimeMillis()-tStart)/1000;
          // dedup + final sort already done
          runOnUiThread(()->{
            prog.setProgress(100);
            tvLive.setText("● DONE"); tvLive.setTextColor(0xFF22C55E);
            tvStat.setText("✅ تمام — "+found.get()+"/"+total+" سالم در "+sec+"s");
            if(found.get()>0){ toast("✅ "+found.get()+" سالم — بهترین اول مرتب شد"); }
            else { log("[-] چیزی پیدا نشد — پورت/تایم‌اوت/ساب‌نت را عوض کن"); }
          });
        }
      });
    }
  }

  void copyAll(){
    if(okList.isEmpty()){ toast("نتیجه‌ای نیست"); return; }
    StringBuilder sb=new StringBuilder();
    for(WarpScanEngine.Result r: okList) sb.append(r.ep()).append("\n");
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
    StringBuilder sb=new StringBuilder("ip,port,latency_ms,speed_kbps\n");
    for(WarpScanEngine.Result r: okList) sb.append(r.ip).append(",").append(r.port).append(",").append(r.latencyMs).append(",").append(String.format("%.0f", r.speedKBps)).append("\n");
    copyClip("csv", sb.toString().trim());
    toast("📄 CSV کپی شد ("+okList.size()+" ردیف)");
  }
  void copyVless(){
    if(okList.isEmpty()){ toast("نتیجه‌ای نیست"); return; }
    // sample VLESS template — user can paste endpoint as address
    StringBuilder sb=new StringBuilder();
    for(WarpScanEngine.Result r: okList){
      sb.append("vless://uuid@").append(r.ip).append(":").append(r.port).append("?encryption=none&security=none&type=tcp#Parvaz-").append(r.latencyMs).append("ms\n");
    }
    copyClip("vless", sb.toString().trim());
    toast("🔗 VLESS کپی شد");
  }
  void shareAll(){
    if(okList.isEmpty()){ toast("نتیجه‌ای نیست"); return; }
    StringBuilder sb=new StringBuilder("Parvaz WARP — "+okList.size()+" سالم (بهترین اول):\n");
    for(WarpScanEngine.Result r: okList){
      sb.append(r.ep()).append("  ").append(r.latencyMs).append("ms");
      if(cfgSpeed && r.speedKBps>0) sb.append("  ").append(String.format("%.0f KB/s", r.speedKBps));
      sb.append("\n");
    }
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

  static class Adapter extends RecyclerView.Adapter<Adapter.VH>{
    List<WarpScanEngine.Result> list; Adapter(List<WarpScanEngine.Result> l){ list=l; }
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
      WarpScanEngine.Result r=list.get(pos);
      h.tvRank.setText("#"+(pos+1));
      h.tvEp.setText(r.ep());
      String extra = r.speedKBps>0 ? String.format("  %.0f KB/s", r.speedKBps) : "";
      h.tvRtt.setText(r.latencyMs+"ms"+extra+"  •  :"+r.port);
      if(pos==0){ h.tvBadge.setVisibility(View.VISIBLE); h.tvBadge.setText("👑 BEST"); h.tvBadge.setTextColor(0xFF070B1E); h.tvBadge.setBackgroundResource(R.drawable.btn_primary); }
      else if(pos<3){ h.tvBadge.setVisibility(View.VISIBLE); h.tvBadge.setText("★ TOP"); h.tvBadge.setTextColor(0xFFEAB308); h.tvBadge.setBackgroundResource(R.drawable.bg_chip); }
      else h.tvBadge.setVisibility(View.GONE);
      h.btnCopy.setOnClickListener(v->{
        ClipboardManager cm=(ClipboardManager)v.getContext().getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("ep", r.ep()));
        Toast.makeText(v.getContext(),"📋 "+r.ep(),Toast.LENGTH_SHORT).show();
      });
      h.btnShare.setOnClickListener(v->{
        Intent it=new Intent(Intent.ACTION_SEND); it.setType("text/plain"); it.putExtra(Intent.EXTRA_TEXT, r.ep()+"  "+r.latencyMs+"ms");
        v.getContext().startActivity(Intent.createChooser(it, r.ep()));
      });
      h.itemView.setOnLongClickListener(v->{
        PopupMenu m=new PopupMenu(v.getContext(), v);
        m.getMenu().add("📋 کپی").setOnMenuItemClickListener(i->{
          ClipboardManager cm=(ClipboardManager)v.getContext().getSystemService(Context.CLIPBOARD_SERVICE);
          cm.setPrimaryClip(ClipData.newPlainText("ep", r.ep()));
          Toast.makeText(v.getContext(),"کپی شد: "+r.ep(),Toast.LENGTH_SHORT).show(); return true;
        });
        m.getMenu().add("🔗 VLESS").setOnMenuItemClickListener(i->{
          String vless="vless://uuid@"+r.ip+":"+r.port+"?encryption=none&security=none&type=tcp#Parvaz-"+r.latencyMs+"ms";
          ClipboardManager cm=(ClipboardManager)v.getContext().getSystemService(Context.CLIPBOARD_SERVICE);
          cm.setPrimaryClip(ClipData.newPlainText("vless", vless));
          Toast.makeText(v.getContext(),"VLESS کپی شد",Toast.LENGTH_SHORT).show(); return true;
        });
        m.getMenu().add("↗ اشتراک").setOnMenuItemClickListener(i->{
          Intent it=new Intent(Intent.ACTION_SEND); it.setType("text/plain"); it.putExtra(Intent.EXTRA_TEXT, r.ep());
          v.getContext().startActivity(Intent.createChooser(it, r.ep())); return true;
        });
        m.show(); return true;
      });
    }
    @Override public int getItemCount(){ return list.size(); }
  }
}
