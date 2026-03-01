# HANDOFF — Lantern Network Toolkit

## What Is This
Suite of single-file C network tools for Windows. Open source. Each tool does one thing,
compiles to one standalone .exe, no dependencies. MIT licensed.

**Repo:** https://github.com/michaelfperla/lantern

## Project Structure
```
lantern.h      — shared header (colors, OUI table, MAC formatting, thread helpers, sockaddr helpers)
netscan.c      — ARP subnet scanner + adapter info
portscan.c     — TCP port scanner with parallel banner grabbing (table-driven flags)
wifiscan.c     — WiFi enumeration with per-BSSID security from 802.11 IE parsing
netwatch.c     — continuous network sentry (alerts on device join/leave)
routercheck.c  — router security checker (admin panel, creds, UPnP, SSH, DNS)
netreport.c    — full audit report generator (Markdown output)
Makefile       — build rules for all 6 tools
README.md      — usage examples with real output
LICENSE        — MIT
```

## Compile
```bash
export PATH="/c/msys64/mingw64/bin:$PATH"
gcc -O2 -Wall -Wextra -o netscan.exe      netscan.c      -lws2_32 -liphlpapi
gcc -O2 -Wall -Wextra -o portscan.exe     portscan.c     -lws2_32 -liphlpapi
gcc -O2 -Wall -Wextra -o wifiscan.exe     wifiscan.c     -lws2_32 -lwlanapi -lole32
gcc -O2 -Wall -Wextra -o netwatch.exe     netwatch.c     -lws2_32 -liphlpapi
gcc -O2 -Wall -Wextra -o routercheck.exe  routercheck.c  -lws2_32 -liphlpapi
gcc -O2 -Wall -Wextra -o netreport.exe    netreport.c    -lws2_32 -liphlpapi -lwlanapi -lole32
```

## Verified
- All 6 tools compile with zero warnings (GCC 15.2.0)
- netscan: 6 hosts on local network
- portscan: 4 open ports on router with parallel banner grabs
- wifiscan: 20 APs with per-BSSID security from IE parsing
- netwatch: baseline scan + watch loop + session summary on Ctrl+C
- routercheck: found admin/admin creds, UPnP enabled, SSH open, DNS resolver active
- netreport: generated full Markdown audit report with all sections populated
- Code reviewed by 3 agents (reuse, quality, efficiency) — all findings fixed

## What Was Done
### Session 1
1. Split monolithic netscanner.c into suite of 4 tools + shared header
2. Created lantern.h with shared utilities (colors, OUI, MAC, thread wait, sockaddr, ip_to_str)
3. Code review pass: fixed 12 issues (parallel banners, table-driven port flags, goto cleanup,
   removed dead state, capped race condition, shared helpers for dedup)
4. Fixed WiFi security: replaced SSID matching with direct 802.11 IE parsing (RSN/WPA elements)
5. Built netwatch (continuous sentry)
6. Added README, LICENSE (MIT), cleaned root directory
7. Pushed to https://github.com/michaelfperla/lantern (2 commits on main)

### Session 2
1. Full home network audit with all existing tools (netscan, portscan all 6 hosts, wifiscan)
2. Built routercheck.c — admin panel probing, default credential testing (HTTP Basic Auth with
   inline Base64), UPnP/SSDP discovery, DNS query, SSH banner grab, open service summary
3. **CRITICAL FINDING: Router accepts admin/admin credentials. UPnP enabled with IGD exposed.**
4. Built netreport.c — runs all scans inline, generates Markdown audit report with tables,
   severity ratings, and recommended actions. Supports `-o report.md` for file output.
5. Updated Makefile and README with all 6 tools
6. Audit toolkit is complete: scan → probe → assess → monitor → report

## Critical Security Findings (Michael's Network)
- **admin/admin works on router** — change immediately
- **UPnP enabled** with InternetGatewayDevice exposed — any device can open external ports
- SSH open on router (port 22)
- HTTP admin panel unencrypted (port 80)
- 3 open WiFi networks nearby (Club_Totalplay_WiFi)

## Known Network (from scans)
- Router: 192.168.0.1 (Samsung 88:71:B1:05:8B:68) — SSH, HTTP, HTTPS, SSDP, DNS open
- Network: 192.168.0.0/24 (254 hosts scanned)
- WiFi: IZZI-1F56 (2.4GHz) + IZZI-1F56-5G (5GHz), both WPA2-PSK
- 6 devices typically online
- 20 neighboring APs visible, 3 Open (Club_Totalplay_WiFi)

## Next Steps
- **Commit and push** routercheck, netreport, updated Makefile/README
- **Change router password** from admin/admin (critical)
- **Disable UPnP** on router
- Consider going public: write up the audit as a case study, post to Hacker News / Reddit
- Potential new tools: traceroute, bandwidth test, DNS leak checker

## Dev Environment
- GCC 15.2.0 at C:\msys64\mingw64\bin\gcc.exe
- No make installed — compile manually or install mingw-w64-x86_64-make
- Git: michael@clixhouse.com / Michael Perla (repo-local config)
- Branch: main
