package com.parvaz.scanner;
import java.io.InputStream;
import java.net.*;
import javax.net.ssl.*;
import java.util.concurrent.*;

/** WarpScanEngine — senpai ScanEngine ported to Warp.
 *  Tricks ported:
 *   1) TCP latency via Socket.connect (measureTimeMillis)
 *   2) Optional downloadSpeed via Host: speed.cloudflare.com over direct CF IP (Host header + hostnameVerifier bypass)
 *   3) Two-stage pipeline: TCP pass -> speed test (so slow speedtest only on clean IPs)
 *   4) Tight timeout per IP so throughput stays high even on 10k+ batches.
 */
public class WarpScanEngine {
  public static class Result {
    public String ip; public int port; public boolean isClean; public long latencyMs; public double speedKBps;
    public Result(String ip,int port,boolean c,long l,double s){ this.ip=ip; this.port=port; this.isClean=c; this.latencyMs=l; this.speedKBps=s; }
    public String ep(){ return ip+":"+port; }
  }

  /** TCP latency to ip:port (same trick as senpai ScanEngine.checkLatency) */
  public static Result checkLatency(String ip, int port, int timeoutMs){
    Socket sock=null;
    try{
      String clean = ip.startsWith("[")? ip.substring(1,ip.length()-1) : ip;
      InetAddress addr=InetAddress.getByName(clean);
      sock=new Socket();
      long t0=System.currentTimeMillis();
      sock.connect(new InetSocketAddress(addr, port), timeoutMs);
      long lat = System.currentTimeMillis()-t0;
      sock.close();
      return new Result(ip,port,true,lat,0);
    }catch(Exception e){
      if(sock!=null) try{sock.close();}catch(Exception x){}
      return new Result(ip,port,false,-1,0);
    }
  }

  /** Optional speed test via Host: speed.cloudflare.com to direct IP (senpai checkDownloadSpeed) */
  public static double checkDownloadSpeed(String ip, int payloadBytes, int timeoutMs){
    if(ip.startsWith("[")) return 0; // skip IPv6 for speedtest
    HttpURLConnection conn=null; InputStream is=null; double kbps=0;
    try{
      URL url=new URL("https://"+ip+"/__down?bytes="+payloadBytes);
      conn=(HttpURLConnection)url.openConnection();
      conn.setRequestProperty("Host","speed.cloudflare.com");
      conn.setConnectTimeout(timeoutMs);
      conn.setReadTimeout(timeoutMs);
      if(conn instanceof HttpsURLConnection){
        ((HttpsURLConnection)conn).setHostnameVerifier((h,s)->true);
        // default TrustManager is fine (CF cert covers *.cloudflare.com but hostname check is bypassed above)
      }
      long t0=System.currentTimeMillis();
      is=conn.getInputStream();
      byte[] buf=new byte[4096]; int total=0;
      while(true){
        if(System.currentTimeMillis()-t0 > timeoutMs) break;
        int n=is.read(buf); if(n==-1) break; total+=n;
      }
      long dt=System.currentTimeMillis()-t0;
      if(dt>10 && total>0) kbps=(total/1024.0)/(dt/1000.0);
    }catch(Exception e){}
    finally{
      if(is!=null) try{is.close();}catch(Exception x){}
      if(conn!=null) try{conn.disconnect();}catch(Exception x){}
    }
    return kbps;
  }
}
