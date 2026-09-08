# Parvaz Scanner — WARP Endpoint Scanner (FCAE corescan)

Exact FCAE hunting engine — 54 ports × 7 prefixes (~2537 candidates) + UDP handshake hands @ 1.2s timeout; Best 5 like log:

```
I [*] hunting for a working WireGuard endpoint (handshake + data-plane verification, aethernoize='balanced')
I [+] wg candidate ok 188.114.96.1:500 rtt=404ms
```

WARP clean-ips: 162.159.192/195.0/24 + 188.114.96-99.0/24 + 162.159.193.0/24
Copy سالمترین endpoint → paste into @parvazpanelbot as `/new alice 188.114.96.1:2408` (no VPN sub — per-user .conf)
