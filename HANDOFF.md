# HANDOFF — Lantern Network Toolkit

## What Is This
Suite of 8 single-file C network tools for Windows. Open source. Each tool does one thing,
compiles to one standalone .exe, no dependencies. MIT licensed.

**Repo:** https://github.com/michaelfperla/lantern

## Project Structure
```
lantern.h      — shared header-only library (~840 lines)
                  Colors, OUI table, MAC formatting, ARP scan, TCP open, HTTP helpers,
                  Base64, 802.11 IE parser, thread pool, SNMP probe, WLAN extension
netscan.c      — ARP subnet scanner + adapter info
portscan.c     — TCP port scanner with banner grabbing (-p port filter)
wifiscan.c     — WiFi enumeration with per-BSSID security from 802.11 IE parsing
netwatch.c     — continuous network sentry (alerts on device join/leave)
routercheck.c  — router security checker (admin panel, creds, UPnP, SNMP, SSH, DNS)
netreport.c    — full audit report generator (Markdown output)
keygen.c       — ARRIS default password candidate generator (--all flag)
wificrack.c    — ARRIS default password prover (--dry-run flag)
Makefile       — builds standard tools (make) + attack tools (make attack)
.github/       — GitHub Actions CI (build + release artifacts)
README.md      — professional docs with sanitized examples
LICENSE        — MIT
```

## Compile
```bash
export PATH="/c/msys64/mingw64/bin:$PATH"

# Standard tools
make

# Attack tools (keygen + wificrack)
make attack

# Or individually
gcc -O2 -Wall -Wextra -o netscan.exe      netscan.c      -lws2_32 -liphlpapi
gcc -O2 -Wall -Wextra -o portscan.exe     portscan.c     -lws2_32 -liphlpapi
gcc -O2 -Wall -Wextra -o wifiscan.exe     wifiscan.c     -lws2_32 -lwlanapi -lole32
gcc -O2 -Wall -Wextra -o netwatch.exe     netwatch.c     -lws2_32 -liphlpapi
gcc -O2 -Wall -Wextra -o routercheck.exe  routercheck.c  -lws2_32 -liphlpapi
gcc -O2 -Wall -Wextra -o netreport.exe    netreport.c    -lws2_32 -liphlpapi -lwlanapi -lole32
gcc -O2 -Wall -Wextra -o keygen.exe       keygen.c       -lws2_32 -lwlanapi -lole32
gcc -O2 -Wall -Wextra -o wificrack.exe    wificrack.c    -lws2_32 -lwlanapi -lole32
```

## Verified
- All 8 tools compile with `-Werror` (GCC 15.2.0, zero warnings)
- All 8 tools respond to `--help` and `--version`
- netscan: 5 hosts on local network
- portscan: 4 open ports on router with parallel banner grabs, -p filter works
- wifiscan: 20 APs with per-BSSID security from IE parsing
- netwatch: baseline scan + watch loop + session summary on Ctrl+C
- routercheck: default creds, UPnP, SNMP (now UDP), SSH, DNS
- netreport: full Markdown audit report (64-thread bounded port scan)
- keygen --help, wificrack --help: both output usage correctly

## What Was Done

### Session 1
1. Split monolithic netscanner.c into suite of 4 tools + shared header
2. Created lantern.h with shared utilities
3. Code review: fixed 12 issues (parallel banners, table-driven port flags, etc.)
4. Fixed WiFi security: replaced SSID matching with direct 802.11 IE parsing
5. Built netwatch, README, LICENSE (MIT)
6. Pushed to GitHub (2 commits on main)

### Session 2
1. Full home network audit with all tools
2. Built routercheck.c and netreport.c
3. Code review (3 agents) — extracted 7 shared functions to lantern.h
4. Fixed critical perf: netreport port scan sequential → threaded
5. Pushed to GitHub (3 commits on main)

### Session 3 — Full Cleanup (the plan)
Executed 7-phase cleanup to professionalize the codebase:

1. **Phase 0: Security** — .gitignore blocks HARDENING.md/audit-*.md, scrubbed passwords
2. **Phase 1: Build** — Makefile with `attack:` target, GitHub Actions CI workflow
3. **Phase 2: ARP Dedup** — Extracted `lantern_arp_scan()` to lantern.h, removed ~120 lines
   of copy-pasted ARP code from netscan, netwatch, netreport
4. **Phase 3: ARRIS Dedup** — Extracted `lantern_scan_arris_targets()` to WLAN extension,
   removed ~114 lines from keygen + wificrack. Solved include-order problem with
   re-include pattern (code lives outside `#ifndef LANTERN_H` guard)
5. **Phase 4: Thread Pool** — Added `lantern_run_bounded()`, capped netreport at 64 threads
   (was spawning up to 6,096 simultaneously)
6. **Phase 5: CLI Flags** — `lantern_check_flags()` helper, --help/--version for all 8 tools,
   -p for portscan, --all for keygen, --dry-run for wificrack
7. **Phase 6: Bug Fixes** — Fixed `lantern_tcp_open` error FD check, simplified portscan
   `port_thread`, added `lantern_snmp_probe` (UDP) for routercheck, added
   `lantern_wlan_scan_wait` (event-driven WiFi scan), `#error` platform guard,
   updated netreport to use event-driven scan
8. **Phase 7: README** — Full rewrite: problem statement, tools grouped by risk level,
   sanitized examples, build + GitHub Releases, responsible use section, expanded design

**Net result:** ~200 lines removed from tools, ~300 lines added to lantern.h (shared).
Codebase is smaller, every tool benefits from shared improvements.

## Critical Security Findings (Michael's Network)
- **admin/admin works on router** — change immediately
- **UPnP enabled** with InternetGatewayDevice exposed
- SSH open on router (port 22)
- HTTP admin panel unencrypted (port 80)

## Next Steps
- **Change router password** from admin/admin (critical)
- **Disable UPnP** on router
- Commit all changes (7 commits per plan)
- Push to GitHub, tag v1.1.0
- JSON export option in netreport
- MAC randomization detection in netwatch
- OUI table refresh script (pull from IEEE)
- Consider: case study write-up, Hacker News / Reddit

## Dev Environment
- GCC 15.2.0 at C:\msys64\mingw64\bin\gcc.exe
- Make available via Makefile
- Git: michael@clixhouse.com / Michael Perla
- Branch: main (uncommitted — all changes pending commit)
