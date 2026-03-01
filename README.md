# Lantern

Suite of single-file C network tools for Windows. Each tool compiles to one standalone `.exe` — no dependencies, no install, no runtime.

## Tools

### netscan — Discover devices on your local network

ARP scans your subnet and identifies every device by IP, MAC address, and vendor.

```
$ netscan

  lantern netscan — discover devices on your local network
  ─────────────────────────────────────────

  ═══ NETWORK ADAPTERS ═══

  Adapter                        MAC                IP               Gateway          Subnet
  ------------------------------ ------------------ ---------------- ---------------- ----------------
  MediaTek Wi-Fi 6 MT7921 Wirele F8:54:F6:3B:C8:C9  192.168.0.3      192.168.0.1      255.255.255.0

  ═══ ARP SCAN ═══

  Scanning 192.168.0.0/255.255.255.0 (254 hosts)...

  IP Address       MAC Address        Vendor
  ---------------- ------------------ --------------------
  192.168.0.1      88:71:B1:05:8B:68  Samsung
  192.168.0.2      82:CF:C0:B1:C5:E7  Unknown
  192.168.0.3      F8:54:F6:3B:C8:C9  Unknown
  192.168.0.5      BC:5C:17:3A:F6:A2  Unknown

  4 hosts found.
```

### portscan — Scan a host for open TCP ports

Threaded connect scan with parallel banner grabbing. Checks 34 common ports including smart TV, IoT, and remote access services.

```
$ portscan 192.168.0.1

  lantern portscan — scan a host for open TCP ports
  ─────────────────────────────────────────

  Target: 192.168.0.1
  MAC:    88:71:B1:05:8B:68 (Samsung)
  Scanning 34 ports...

  Port    Service        Description                  Banner
  ------- -------------- ---------------------------- ----------------------------------------
  22      ssh            SSH remote shell
  80      http           HTTP web server              HTTP/1.0 200 OK
  443     https          HTTPS web server
  5000    ssdp           SSDP / misc                  HTTP/1.0 404 Not Found

  4 open ports.
```

### wifiscan — Enumerate nearby WiFi networks

Lists all visible access points with signal strength, channel, band, and security. Security is parsed per-BSSID from raw 802.11 Information Elements — not the unreliable SSID-matching approach most tools use.

```
$ wifiscan

  lantern wifiscan — enumerate nearby WiFi networks
  ─────────────────────────────────────────

  Interface: MediaTek Wi-Fi 6 MT7921 Wireless LAN Card

  SSID                             BSSID              Signal               Ch    Band       Security
  -------------------------------- ------------------ -------------------- ----- ---------- ----------
  IZZI-11D7                        8C:61:A3:65:03:3A  █░░░ -71 dBm         1     2.4 GHz    WPA2-PSK
  Mega-2.4G-DEAF                   2A:FB:AE:05:6D:14  ██░░ -67 dBm         11    2.4 GHz    WPA3-SAE
  Club_Totalplay_WiFi              88:66:9F:9F:4F:89  █░░░ -71 dBm         1     2.4 GHz    Open
  IZZI-1F56                        88:71:B1:05:8B:66  ████ -47 dBm         1     2.4 GHz    WPA2-PSK
  IZZI-1F56-5G                     88:71:B1:05:8B:67  ███░ -58 dBm         44    5 GHz      WPA2-PSK

  20 access points found.
```

### netwatch — Continuous network monitoring

Watches your network and alerts when devices join or leave.

```
$ netwatch

  lantern netwatch — continuous network sentry
  ─────────────────────────────────────────

  Baseline: 5 devices on 192.168.0.0/24
  Watching every 30s... (Ctrl+C to stop)

  [12:03:41] [+] NEW   192.168.0.7  A4:83:E7:1A:2B:3C  Apple
  [12:05:12] [-] GONE  192.168.0.5  BC:5C:17:3A:F6:A2  Unknown
  [12:08:33] [+] NEW   192.168.0.5  BC:5C:17:3A:F6:A2  Unknown
```

### routercheck — Test your router for misconfigurations

Probes your gateway for common security issues: open admin panels, default credentials, UPnP exposure, SSH, DNS, and dangerous services.

```
$ routercheck

  lantern routercheck — test your router for misconfigurations
  ─────────────────────────────────────────

  Router: 192.168.0.1 (88:71:B1:05:8B:68 — Samsung)

  ═══ OPEN SERVICES ═══

  SSH      Port 22    — Remote shell access — ensure key-based auth
  HTTP     Port 80    — Unencrypted admin panel
  HTTPS    Port 443   — Encrypted admin panel (good)
  SSDP     Port 5000  — UPnP/SSDP service
  DNS      Port 53    — DNS resolver

  5 services open on router

  ═══ ADMIN PANEL ═══

  WARNING  Admin login page found at http://192.168.0.1/
  INFO     HTTPS admin panel on port 443 (TLS — good)

  ═══ DEFAULT CREDENTIALS ═══

  CRITICAL Default credentials work: admin/admin on 192.168.0.1/

  ═══ UPnP / SSDP ═══

  WARNING  UPnP is enabled (10 responses)
  CRITICAL InternetGatewayDevice exposed — any device can open ports

  ═══ DNS CONFIGURATION ═══

  INFO     Router is acting as DNS resolver
```

### netreport — Generate a full network audit report

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

## Build

Requires GCC (MinGW-w64). No other dependencies.

```bash
gcc -O2 -Wall -Wextra -o netscan.exe      netscan.c      -lws2_32 -liphlpapi
gcc -O2 -Wall -Wextra -o portscan.exe     portscan.c     -lws2_32 -liphlpapi
gcc -O2 -Wall -Wextra -o wifiscan.exe     wifiscan.c     -lws2_32 -lwlanapi -lole32
gcc -O2 -Wall -Wextra -o netwatch.exe     netwatch.c     -lws2_32 -liphlpapi
gcc -O2 -Wall -Wextra -o routercheck.exe  routercheck.c  -lws2_32 -liphlpapi
gcc -O2 -Wall -Wextra -o netreport.exe    netreport.c    -lws2_32 -liphlpapi -lwlanapi -lole32
```

Or with Make:

```bash
make
```

## Design

- **Single-file tools.** Each `.c` file compiles independently to one `.exe`.
- **Shared header.** `lantern.h` provides common utilities — ANSI colors, OUI vendor table (binary search over ~120 entries), MAC formatting, thread helpers.
- **Zero dependencies.** Only Windows APIs: WinSock2, IP Helper, WLAN API.
- **Full audit pipeline.** Scan → probe → assess → monitor → report. Six tools that cover the complete network audit workflow.
- **Correct by default.** WiFi security is parsed from raw 802.11 IEs per-BSSID, not approximated from SSID matching. Port scanning uses proper non-blocking connects with `select`. ARP scanning runs 254 threads with `InterlockedIncrement` for lock-free result collection.

## License

MIT
