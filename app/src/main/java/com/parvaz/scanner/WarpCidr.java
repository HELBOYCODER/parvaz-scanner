package com.parvaz.scanner;
import java.util.*;

/** WARP-optimized CIDR pool — Cloudflare Anycast blocks that actually host Warp/ZeroTrust.
 *  Based on CidrParser trick from senpai: random sample across CIDRs via parse+index.
 *  Here tuned for WARP/ZeroTrust Anycast (188.114, 162.159, 104.x, etc.) */
public class WarpCidr {
  // Curated WARP Anycast — verified CF edge ranges (subset of CF CIDRs, WARP-capable)
  public static final String[] WARP_CIDRS = {
    // classic WARP blocks — highest hit-rate for Warp/UDP
    "188.114.96.0/20", "188.114.97.0/24", "188.114.98.0/24", "188.114.99.0/24",
    "162.159.192.0/24", "162.159.193.0/24", "162.159.195.0/24",
    "162.158.0.0/15",   // large Anycast generic
    "104.16.0.0/13",    // CF core
    "104.24.0.0/14",
    "172.64.0.0/13",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "198.41.128.0/17",
  };

  static class IpRange {
    final int network; final int size;
    IpRange(int n, int s){ network=n; size=s; }
    String at(int idx){ return decode(network+idx); }
    String random(Random rnd){
      if(size<=1) return decode(network);
      return at(rnd.nextInt(size));
    }
  }

  static IpRange parse(String cidr){
    try{
      String[] p=cidr.split("/");
      String[] b=p[0].split("\\.");
      int ip=0; for(int i=0;i<4;i++) ip|=Integer.parseInt(b[i])<<(24-i*8);
      int bits=Integer.parseInt(p[1]);
      int mask = bits==0?0:(-1<<(32-bits));
      int net = ip & mask;
      int sz = bits>=22 ? Math.min(4096, 1<<(32-bits)) : 1<<(32-bits);
      // cap huge blocks (e.g. /13 would be 524k) to 10k per senpai trick
      if(sz>10000) sz=10000;
      return new IpRange(net, sz);
    }catch(Exception e){ return null; }
  }

  static String decode(int ip){
    return ((ip>>>24)&0xFF)+"."+((ip>>>16)&0xFF)+"."+((ip>>>8)&0xFF)+"."+(ip&0xFF);
  }

  /** senpai trick: unique random sample across all WARP CIDRs */
  public static List<String> sampleIps(int count, Random rnd){
    if(rnd==null) rnd=new Random();
    List<IpRange> ranges=new ArrayList<>();
    for(String c: WARP_CIDRS){ IpRange r=parse(c); if(r!=null) ranges.add(r); }
    Set<String> out=new LinkedHashSet<>();
    int attempts=0;
    while(out.size()<count && attempts < count*5){
      attempts++;
      IpRange r=ranges.get(rnd.nextInt(ranges.size()));
      out.add(r.random(rnd));
    }
    return new ArrayList<>(out);
  }
}
