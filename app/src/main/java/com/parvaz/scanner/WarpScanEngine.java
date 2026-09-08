package com.parvaz.scanner;
import java.io.*;
import java.net.*;
import java.util.*;

/**
 * WarpScanEngine — ported from BPB (bia-pain-bache/BPB-Warp-Scanner) + senpai tricks.
 *
 * BPB truth: NO WireGuard handshake needed for scan. scanPort(port,host):
 *   - UDP ping: send random bytes to host:port, wait any reply -> port open
 *   - TCP RTT: socket to host:443, measure latency (routing quality)
 *   - Sort by DetailResult / RTT
 * Here: UDP reachability = Warp candidate; TCP 443 RTT = quality sort.
 * Speed test (optional) still via Host: speed.cloudflare.com trick.
 */
public class WarpScanEngine {
  public static class Result {
    public String ip; public int port; public boolean isClean; public long latencyMs; public double speedKBps;
    public Result(String ip,int port,boolean c,long l,double s){ this.ip=ip; this.port=port; this.isClean=c; this.latencyMs=l; this.speedKBps=s; }
    public String ep(){ return ip+":"+port; }
  }

  /** BPB-style UDP availability check: any reply on udp port => Warp edge is there */
  public static boolean udpAvailable(String host, int port, int timeoutMs){
    DatagramSocket ds=null;
    try{
      InetAddress addr=InetAddress.getByName(host);
      byte[] out=new byte[32]; new Random().nextBytes(out);
      DatagramPacket p=new DatagramPacket(out, out.length, addr, port);
      ds=new DatagramSocket();
      ds.setSoTimeout(timeoutMs);
      ds.send(p);
      byte[] in=new byte[512];
      DatagramPacket resp=new DatagramPacket(in, in.length);
      ds.receive(resp);
      return true; // any packet back => port reachable
    }catch(SocketTimeoutException e){
      return false;
    }catch(Exception e){
      return false;
    }finally{
      if(ds!=null) try{ ds.close(); }catch(Exception x){}
    }
  }

  /** TCP RTT to host:port — quality metric (BPB measures 443, we measure the Warp port itself for Warp RTT) */
  public static long tcpRtt(String host, int port, int timeoutMs){
    Socket s=null;
    try{
      InetAddress addr=InetAddress.getByName(host);
      s=new Socket();
      long t0=System.currentTimeMillis();
      s.connect(new InetSocketAddress(addr, port), timeoutMs);
      long lat=System.currentTimeMillis()-t0;
      s.close();
      return lat;
    }catch(Exception e){
      if(s!=null) try{s.close();}catch(Exception x){}
      return -1;
    }
  }

  /** Full Warp check: UDP open on Warp port + TCP RTT (for sorting). Timeout 2s UDP, timeoutMs TCP. */
  public static Result checkWarp(String ip, int port, int timeoutMs){
    String host = ip.startsWith("[") ? ip.substring(1, ip.length()-1) : ip;
    boolean udp = udpAvailable(host, port, 2000);
    if(!udp) return new Result(ip, port, false, -1, 0);
    long rtt = tcpRtt(host, port, timeoutMs);
    // UDP open is already Warp-capable; rtt <0 still counts but sorted last
    long lat = (rtt<0 ? timeoutMs : rtt);
    return new Result(ip, port, true, lat, 0);
  }

  /** Legacy alias — now Warp-aware */
  public static Result checkLatency(String ip, int port, int timeoutMs){
    return checkWarp(ip, port, timeoutMs);
  }

  public static double checkDownloadSpeed(String ip, int payloadBytes, int timeoutMs){
    if(ip.startsWith("[")) return 0;
    HttpURLConnection conn=null; InputStream is=null; double kbps=0;
    try{
      URL url=new URL("https://"+ip+"/__down?bytes="+payloadBytes);
      conn=(HttpURLConnection)url.openConnection();
      conn.setRequestProperty("Host","speed.cloudflare.com");
      conn.setConnectTimeout(timeoutMs);
      conn.setReadTimeout(timeoutMs);
      if(conn instanceof javax.net.ssl.HttpsURLConnection){
        ((javax.net.ssl.HttpsURLConnection)conn).setHostnameVerifier((h,s)->true);
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

  /** senpai trick: batch scan via UDP Warp — same port per call; speed only on clean */
  public static List<Result> batchCheck(List<String> ips, int port, int timeoutMs, boolean speed, int speedPayload){
    List<Result> out=new ArrayList<>(ips.size());
    for(String ip: ips){
      Result r=checkWarp(ip, port, timeoutMs);
      if(r.isClean && speed && !ip.startsWith("[")){
        r.speedKBps = checkDownloadSpeed(ip, speedPayload, 5000);
      }
      out.add(r);
    }
    return out;
  }
}
