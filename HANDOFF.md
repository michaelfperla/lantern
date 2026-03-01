# HANDOFF — Lantern Network Toolkit

## What Is This
Suite of single-file C network tools. Open source project. Each tool does one thing,
compiles to one standalone .exe, no dependencies.

## Project Structure
```
lantern.h      — shared header (colors, OUI table, MAC formatting, console setup, thread helpers)
netscan.c      — ARP subnet scanner + adapter info
portscan.c     — TCP port scanner with parallel banner grabbing
wifiscan.c     — WiFi network enumeration
Makefile       — build rules (needs mingw32-make or manual gcc)
```

## Compile
```bash
export PATH="/c/msys64/mingw64/bin:$PATH"
gcc -O2 -Wall -Wextra -o netscan.exe netscan.c -lws2_32 -liphlpapi
gcc -O2 -Wall -Wextra -o portscan.exe portscan.c -lws2_32 -liphlpapi
gcc -O2 -Wall -Wextra -o wifiscan.exe wifiscan.c -lws2_32 -lwlanapi -lole32
```

## Verified
- All three tools compile with zero warnings (GCC 15.2.0)
- `netscan` finds 6 hosts on local network
- `portscan` finds 4 open ports on router (ssh, http, https, ssdp) with parallel banners
- Branch: `main`, no commits yet

## Next Tools to Build
- `netwatch` — continuous monitoring, alert on new/departed devices
- `routercheck` — test router for default creds, open admin, UPnP exposure
- `dnsleak` — DNS leak / config checker
- `netreport` — run all tools, generate formatted report

## Dev Environment
- GCC 15.2.0 at `C:\msys64\mingw64\bin\gcc.exe`
- No `make` installed — compile manually or install `mingw-w64-x86_64-make`
- Git bash shell (MSYS2)
