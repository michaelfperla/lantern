# Lantern

A suite of single-file C network tools for Windows. Each tool compiles to one standalone `.exe` — no dependencies, no install, no runtime. Built for home network auditing and security research.

## Why

Most network toolkits assume Linux, require Python runtimes, or install heavy frameworks. Lantern is the opposite: drop a single `.exe` on any Windows machine and start auditing. Every tool is one C file plus one shared header. The entire toolkit compiles in seconds and runs with zero setup.

Built because the home network is the most neglected attack surface. ISP-provided routers ship with default credentials, UPnP wide open, and telnet enabled. Lantern finds all of that in under a minute.

## Tools

### Passive Recon

These tools observe — they don't modify anything or send credentials.

**netscan** — Discover devices on your local network

ARP scans your subnet and identifies every device by IP, MAC address, and vendor.

```
$ netscan

  lantern netscan — discover devices on your local network
  ─────────────────────────────────────────

  ═══ NETWORK ADAPTERS ═══

  Adapter                        MAC                IP               Gateway          Subnet
  ------------------------------ ------------------ ---------------- ---------------- ----------------
  Wi-Fi Adapter                  A1:B2:C3:D4:E5:F6  192.168.1.10     192.168.1.1      255.255.255.0

  ═══ ARP SCAN ═══

  Scanning 192.168.1.0/255.255.255.0 (254 hosts)...

  IP Address       MAC Address        Vendor
  ---------------- ------------------ --------------------
  192.168.1.1      00:11:22:33:44:55  ARRIS
  192.168.1.10     A1:B2:C3:D4:E5:F6  Intel
  192.168.1.15     AA:BB:CC:DD:EE:FF  Samsung
  192.168.1.23     11:22:33:44:55:66  Apple

  4 hosts found.
```

**wifiscan** — Enumerate nearby WiFi networks

Lists all visible access points with signal strength, channel, band, and security. Security is parsed per-BSSID from raw 802.11 Information Elements — not the unreliable SSID-matching approach most tools use.

```
$ wifiscan

  lantern wifiscan — enumerate nearby WiFi networks
  ─────────────────────────────────────────

  Interface: Wi-Fi Adapter

  SSID                             BSSID              Signal               Ch    Band       Security
  -------------------------------- ------------------ -------------------- ----- ---------- ----------
  HomeNetwork-5G                   00:11:22:33:44:56  ████ -42 dBm         36    5 GHz      WPA3-SAE
  HomeNetwork                      00:11:22:33:44:55  ███░ -55 dBm         6     2.4 GHz    WPA2-PSK
  Neighbor-WiFi                    AA:BB:CC:DD:EE:F0  ██░░ -65 dBm         1     2.4 GHz    WPA2-PSK
  Guest-Network                    11:22:33:44:55:67  █░░░ -78 dBm         11    2.4 GHz    Open

  15 access points found.
```

**netwatch** — Continuous network monitoring

Watches your network and alerts when devices join or leave.

```
$ netwatch

  lantern netwatch — continuous network sentry
  ─────────────────────────────────────────

  Baseline: 4 devices on 192.168.1.0/24
  Watching every 30s... (Ctrl+C to stop)

  [12:03:41] [+] NEW   192.168.1.25  A4:83:E7:1A:2B:3C  Apple
  [12:05:12] [-] GONE  192.168.1.15  AA:BB:CC:DD:EE:FF  Samsung
  [12:08:33] [+] NEW   192.168.1.15  AA:BB:CC:DD:EE:FF  Samsung
```

### Active Scanning

These tools probe targets — they open TCP connections, send HTTP requests, or attempt logins. Run only against devices you own.

**portscan** — Scan a host for open TCP ports

Threaded connect scan with parallel banner grabbing. Checks 34 common ports including smart TV, IoT, and remote access services.

```
$ portscan 192.168.1.1

  lantern portscan — scan a host for open TCP ports
  ─────────────────────────────────────────

  Target: 192.168.1.1
  MAC:    00:11:22:33:44:55 (ARRIS)
  Scanning 34 ports...

  Port    Service        Description                  Banner
  ------- -------------- ---------------------------- ----------------------------------------
  22      ssh            SSH remote shell
  80      http           HTTP web server              HTTP/1.0 200 OK
  443     https          HTTPS web server
  5000    ssdp           SSDP / misc                  HTTP/1.0 404 Not Found

  4 open ports.
```

Use `-p` to scan specific ports: `portscan -p 22,80,443 192.168.1.1`

**routercheck** — Test your router for misconfigurations

Probes your gateway for common security issues: open admin panels, default credentials, UPnP exposure, SNMP, SSH, DNS, and dangerous services.

```
$ routercheck

  lantern routercheck — test your router for misconfigurations
  ─────────────────────────────────────────

  Router: 192.168.1.1 (00:11:22:33:44:55 — ARRIS)

  ═══ OPEN SERVICES ═══

  SSH      Port 22    — Remote shell access — ensure key-based auth
  HTTP     Port 80    — Unencrypted admin panel
  HTTPS    Port 443   — Encrypted admin panel (good)
  SNMP     Port 161   — SNMP responds to "public" community
  UPnP     Port 5000  — UPnP/SSDP service

  5 services open on router

  ═══ DEFAULT CREDENTIALS ═══

  CRITICAL Default credentials work: admin/admin on 192.168.1.1/

  ═══ UPnP / SSDP ═══

  WARNING  UPnP is enabled
  CRITICAL InternetGatewayDevice exposed — any device can open ports
```

**netreport** — Generate a full network audit report

Runs all scans (device discovery, port scanning, router security, WiFi enumeration) and produces a Markdown audit report with severity ratings and recommended actions.

```
$ netreport -o report.md

  lantern netreport — generating report to report.md
  Scanning network...
  Found 6 devices, scanning ports...
  Port scan complete, checking router...
  Report saved to report.md
```

Output is a structured Markdown document with tables for devices, open ports, router findings, WiFi networks, and a summary with action items. Suitable for PDF conversion or client delivery.

### Research Only

These tools target ARRIS/IZZI router default password derivation. **For authorized security research only.**

**keygen** — Generate default password candidates for ARRIS routers

Derives WPA2 password candidates from the SSID suffix using the known ARRIS CMAC key derivation algorithm.

```
$ keygen IZZI-1F56

  lantern keygen — ARRIS default password candidates
  ─────────────────────────────────────────

  SSID:   IZZI-1F56
  Suffix: 1F56

  Candidate passwords (most likely first):
    1. T8s9Kp2mXw    ← start here
    2. Qr4vN7bYcE
    3. Jd6hL0fZaU
    ...

  Use --all to print all candidates (pipeable).
```

**wificrack** — Prove ARRIS default passwords are crackable

Attempts each keygen candidate against the target network to demonstrate the vulnerability. Use `--dry-run` to list candidates without connecting.

```
$ wificrack --dry-run IZZI-1F56

  lantern wificrack — dry run (no connections)
  ─────────────────────────────────────────

  SSID:   IZZI-1F56
  12 candidate passwords generated.

  Candidates:
    1. T8s9Kp2mXw
    2. Qr4vN7bYcE
    ...
```

## Responsible Use

`keygen` and `wificrack` exist to demonstrate a real vulnerability in ISP-deployed ARRIS routers that derive WPA2 passwords from the SSID. Millions of routers in Mexico and Latin America use this scheme.

**Rules:**
- Only test networks you own or have written permission to audit
- The purpose is to prove the password should be changed, not to gain unauthorized access
- If you find your own router is vulnerable, change the WiFi password immediately

These tools are separated from the default `make` build — you must explicitly run `make attack` to compile them.

## Install

### Download

Grab pre-built `.exe` files from [GitHub Releases](https://github.com/michaelfperla/lantern/releases).

### Build from source

Requires GCC (MinGW-w64). No other dependencies.

```bash
# Build all standard tools
make

# Build research tools (keygen, wificrack)
make attack

# Build everything
make all attack

# Or compile individually
gcc -O2 -Wall -Wextra -o netscan.exe      netscan.c      -lws2_32 -liphlpapi
gcc -O2 -Wall -Wextra -o portscan.exe     portscan.c     -lws2_32 -liphlpapi
gcc -O2 -Wall -Wextra -o wifiscan.exe     wifiscan.c     -lws2_32 -lwlanapi -lole32
gcc -O2 -Wall -Wextra -o netwatch.exe     netwatch.c     -lws2_32 -liphlpapi
gcc -O2 -Wall -Wextra -o routercheck.exe  routercheck.c  -lws2_32 -liphlpapi
gcc -O2 -Wall -Wextra -o netreport.exe    netreport.c    -lws2_32 -liphlpapi -lwlanapi -lole32
gcc -O2 -Wall -Wextra -o keygen.exe       keygen.c       -lws2_32 -lwlanapi -lole32
gcc -O2 -Wall -Wextra -o wificrack.exe    wificrack.c    -lws2_32 -lwlanapi -lole32
```

## Design

**Single-file tools.** Each `.c` file compiles independently to one `.exe`. No build system required — just `gcc` and the Windows SDK headers that ship with MinGW.

**Header-only shared library.** `lantern.h` provides common utilities as `static` functions: ANSI colors, OUI vendor lookup (binary search over ~120 entries), MAC formatting, TCP connect probes, HTTP helpers, Base64 encoding, 802.11 IE parsing, ARP scanning, and bounded thread pools. The compiler strips unused functions per-tool.

**Zero external dependencies.** Only Windows APIs: WinSock2, IP Helper, WLAN API. No curl, no OpenSSL, no package managers.

**Correct WiFi security detection.** WiFi security is parsed from raw 802.11 Information Elements per-BSSID — walking RSN/WPA IEs to identify WPA2-PSK, WPA3-SAE, WPA2-Enterprise, etc. Most tools approximate this from SSID matching, which misidentifies multi-BSSID APs and hidden networks.

**Non-blocking connect scan.** Port scanning uses `connect()` + `select()` with proper error FD checking, not blocking connects with timeouts. This gives accurate open/closed results in 1.5s per port.

**Bounded concurrency.** Network-wide port scans (netreport) use a thread pool capped at 64 concurrent threads with `WaitForMultipleObjects`, preventing the thousands-of-threads explosion that crashes on large networks.

**Event-driven WiFi scanning.** WiFi scans use `WlanRegisterNotification` callbacks instead of fixed `Sleep(2000)` delays, returning results as soon as the driver finishes scanning.

**Lock-free ARP collection.** ARP scanning runs 254 threads in parallel, collecting results with `InterlockedIncrement` — no mutexes, no contention.

## License

MIT
