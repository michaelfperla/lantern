/*
 * netreport — Run all Lantern tools and generate a network audit report
 * Part of the Lantern network toolkit
 *
 * Usage:
 *   netreport                (auto-detect network, output to stdout)
 *   netreport -o report.md   (save to file)
 *
 * Compile:
 *   gcc -O2 -Wall -Wextra -o netreport.exe netreport.c -lws2_32 -liphlpapi -lwlanapi -lole32
 */

#include "lantern.h"
#include <wlanapi.h>
#include "lantern.h"  /* re-include to activate WLAN extension */
#include <time.h>

/* ── Report output ───────────────────────────────────────────────── */

static FILE *g_out = NULL;
static int   g_crit = 0, g_warn = 0, g_info = 0;

static void rprintf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_out, fmt, ap);
    va_end(ap);
}

static void finding(const char *severity, const char *msg) {
    if (strcmp(severity, "CRITICAL") == 0) g_crit++;
    else if (strcmp(severity, "WARNING") == 0) g_warn++;
    else g_info++;
    rprintf("| **%s** | %s |\n", severity, msg);
}

/* ── ARP scan (shared via lantern.h) ─────────────────────────────── */

static LanternHost g_hosts[LANTERN_MAX_HOSTS];

/* ── Threaded port scan ──────────────────────────────────────────── */

static const struct { uint16_t port; const char *name; } common_ports[] = {
    {21,"FTP"},{22,"SSH"},{23,"Telnet"},{53,"DNS"},{80,"HTTP"},{443,"HTTPS"},
    {445,"SMB"},{554,"RTSP"},{631,"IPP"},{1883,"MQTT"},{1900,"UPnP"},
    {3000,"LG-TV"},{3389,"RDP"},{5000,"SSDP"},{5353,"mDNS"},{5555,"ADB"},
    {5900,"VNC"},{7000,"AirPlay"},{8008,"Cast"},{8009,"Cast-TLS"},
    {8060,"Roku"},{8080,"HTTP-Alt"},{8443,"HTTPS-Mgmt"},{9000,"WS"},
};
#define NPORTS (sizeof(common_ports) / sizeof(common_ports[0]))

/* Per-check result slot: one per (host, port) pair */
typedef struct {
    int      host_idx;
    int      port_idx;
    uint32_t host_ip;
} PortCheckArg;

/* Flat bitmap: g_port_open[host_idx * NPORTS + port_idx] */
static int g_port_open[LANTERN_MAX_HOSTS * NPORTS];

static DWORD WINAPI port_check_thread(LPVOID param) {
    PortCheckArg *arg = (PortCheckArg *)param;
    char ip[INET_ADDRSTRLEN];
    lantern_ip_to_str(arg->host_ip, ip, sizeof(ip));
    g_port_open[arg->host_idx * (int)NPORTS + arg->port_idx] =
        lantern_tcp_open(ip, common_ports[arg->port_idx].port, 1500);
    free(arg);
    return 0;
}

/* ── UPnP check ──────────────────────────────────────────────────── */

static int check_upnp_enabled(const char *target) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 0;
    struct sockaddr_in addr;
    lantern_fill_sockaddr(&addr, target, 1900);
    DWORD t = 2000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&t, sizeof(t));

    const char *m = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                    "MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";

    /* Send to both unicast and multicast */
    sendto(s, m, (int)strlen(m), 0, (struct sockaddr *)&addr, sizeof(addr));
    struct sockaddr_in mcast;
    lantern_fill_sockaddr(&mcast, "239.255.255.250", 1900);
    sendto(s, m, (int)strlen(m), 0, (struct sockaddr *)&mcast, sizeof(mcast));

    char buf[1024];
    struct sockaddr_in from;
    int fromlen = sizeof(from);
    int n = recvfrom(s, buf, sizeof(buf)-1, 0, (struct sockaddr *)&from, &fromlen);
    closesocket(s);
    return (n > 0) ? 1 : 0;
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    if (lantern_check_flags(argc, argv, "netreport",
            "generate a full network audit report",
            "Usage: netreport [-o file.md] [--help] [--version]\n"
            "\n"
            "Runs all scans (device discovery, port scanning, router security,\n"
            "WiFi enumeration) and produces a Markdown audit report.\n"
            "\n"
            "Options:\n"
            "  -o <file>    Save report to file (default: stdout)"))
        return 0;

    lantern_init();

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    /* Parse args */
    const char *outfile = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc)
            outfile = argv[++i];
    }

    g_out = outfile ? fopen(outfile, "w") : stdout;
    if (!g_out) {
        fprintf(stderr, "Cannot open %s for writing\n", outfile);
        WSACleanup();
        return 1;
    }

    /* Console feedback */
    if (outfile)
        printf(C_CYAN C_BOLD "  lantern netreport" C_RESET C_DIM
               " — generating report to %s\n" C_RESET, outfile);

    /* Network info — single adapter fetch for both IP and gateway */
    uint32_t base_ip = 0, mask = 0;
    char gateway[64] = "unknown";
    {
        IP_ADAPTER_INFO *info = lantern_get_adapters();
        if (info) {
            for (IP_ADAPTER_INFO *a = info; a; a = a->Next) {
                const char *ip_str   = a->IpAddressList.IpAddress.String;
                const char *mask_str = a->IpAddressList.IpMask.String;
                const char *gw_str   = a->GatewayList.IpAddress.String;
                if (strcmp(ip_str, "0.0.0.0") == 0) continue;
                base_ip = inet_addr(ip_str);
                mask    = inet_addr(mask_str);
                if (strcmp(gw_str, "0.0.0.0") != 0 && strlen(gw_str) > 0)
                    snprintf(gateway, sizeof(gateway), "%s", gw_str);
                break;
            }
            free(info);
        }
    }

    if (base_ip == 0) {
        fprintf(stderr, "No active network adapter\n");
        if (outfile) fclose(g_out);
        WSACleanup();
        return 1;
    }

    uint32_t network = base_ip & mask;
    int cidr = 0;
    for (uint32_t m = ntohl(mask); m & 0x80000000; m <<= 1) cidr++;

    char net_str[INET_ADDRSTRLEN];
    lantern_ip_to_str(network, net_str, sizeof(net_str));

    /* Timestamp */
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char datebuf[64];
    strftime(datebuf, sizeof(datebuf), "%Y-%m-%d %H:%M", t);

    if (outfile) printf("  Scanning network...\n");

    /* ── Report header ───────────────────────────────────────────── */

    rprintf("# Network Audit Report\n\n");
    rprintf("| Field | Value |\n");
    rprintf("|-------|-------|\n");
    rprintf("| Date | %s |\n", datebuf);
    rprintf("| Network | %s/%d |\n", net_str, cidr);
    rprintf("| Gateway | %s |\n", gateway);
    rprintf("| Generated by | Lantern Network Toolkit |\n\n");

    /* ── Device inventory ────────────────────────────────────────── */

    rprintf("## Device Inventory\n\n");

    int host_count = lantern_arp_scan(network, mask, g_hosts, 5000);

    rprintf("| IP Address | MAC Address | Vendor |\n");
    rprintf("|------------|-------------|--------|\n");
    for (int i = 0; i < host_count; i++) {
        char ip[INET_ADDRSTRLEN], mac[20];
        lantern_ip_to_str(g_hosts[i].ip, ip, sizeof(ip));
        lantern_format_mac(g_hosts[i].mac, mac, sizeof(mac));
        rprintf("| %s | %s | %s |\n", ip, mac, lantern_lookup_vendor(g_hosts[i].mac));
    }
    rprintf("\n**%d devices** found on network.\n\n", host_count);

    if (outfile) printf("  Found %d devices, scanning ports...\n", host_count);

    /* ── Port scan per host (threaded) ───────────────────────────── */

    rprintf("## Open Ports\n\n");

    memset(g_port_open, 0, sizeof(g_port_open));

    /* Build work items, run with bounded concurrency (max 64 threads) */
    int total_checks = host_count * (int)NPORTS;
    void **work = (void **)malloc(sizeof(void *) * (size_t)total_checks);
    int wi = 0;

    for (int h = 0; h < host_count; h++) {
        for (int p = 0; p < (int)NPORTS; p++) {
            PortCheckArg *arg = (PortCheckArg *)malloc(sizeof(PortCheckArg));
            if (!arg) continue;
            arg->host_idx = h;
            arg->port_idx = p;
            arg->host_ip  = g_hosts[h].ip;
            work[wi++] = arg;
        }
    }
    if (wi > 0) lantern_run_bounded(port_check_thread, work, wi, 64, 10000);
    free(work);

    rprintf("| Device | Port | Service | Note |\n");
    rprintf("|--------|------|---------|------|\n");

    int total_open = 0;
    for (int h = 0; h < host_count; h++) {
        char ip[INET_ADDRSTRLEN];
        lantern_ip_to_str(g_hosts[h].ip, ip, sizeof(ip));
        int is_gw = (strcmp(ip, gateway) == 0);

        for (int p = 0; p < (int)NPORTS; p++) {
            if (!g_port_open[h * (int)NPORTS + p]) continue;

            const char *note = "";
            if (common_ports[p].port == 23) note = "INSECURE";
            else if (common_ports[p].port == 22 && is_gw) note = "Router SSH";
            else if (common_ports[p].port == 80 && is_gw) note = "Router admin (HTTP)";
            else if (common_ports[p].port == 5555) note = "INSECURE";

            rprintf("| %s | %d | %s | %s |\n",
                    ip, common_ports[p].port, common_ports[p].name, note);
            total_open++;
        }
    }
    rprintf("\n**%d open ports** across %d devices.\n\n", total_open, host_count);

    if (outfile) printf("  Port scan complete, checking router...\n");

    /* ── Router checks ───────────────────────────────────────────── */

    rprintf("## Router Security\n\n");
    rprintf("| Severity | Finding |\n");
    rprintf("|----------|---------|\n");

    /* Admin panel */
    {
        char buf[4096];
        int n = lantern_http_get(gateway, 80, "/", NULL, buf, sizeof(buf));
        if (n > 0) {
            int has_login = lantern_body_contains_ci(buf, "password") ||
                            lantern_body_contains_ci(buf, "login");
            if (has_login)
                finding("WARNING", "HTTP admin panel has login page (unencrypted)");
            else
                finding("CRITICAL", "HTTP admin panel responds without login form");
        }
    }

    /* Default creds — test paths that return 401/403 (HTTP Basic Auth).
       Skip form-based login (200) to avoid false positives. */
    {
        static const char *cred_paths[] = { "/", "/status", "/admin", "/management" };
        char buf[4096];
        int cred_found = 0;
        for (int p = 0; p < 4 && !cred_found; p++) {
            int n = lantern_http_get(gateway, 80, cred_paths[p], NULL, buf, sizeof(buf));
            if (n <= 0) continue;
            int baseline = lantern_http_status(buf);
            if (baseline != 401 && baseline != 403) continue;

            for (int c = 0; c < (int)LANTERN_CRED_COUNT && !cred_found; c++) {
                n = lantern_http_get_auth(gateway, 80, cred_paths[p],
                                          LANTERN_DEFAULT_CREDS[c].user,
                                          LANTERN_DEFAULT_CREDS[c].pass,
                                          buf, sizeof(buf));
                if (n <= 0) continue;
                int status = lantern_http_status(buf);
                if (status == 200 || status == 301 || status == 302) {
                    char msg[128];
                    snprintf(msg, sizeof(msg),
                             "Default credentials **%s/%s** accepted",
                             LANTERN_DEFAULT_CREDS[c].user,
                             LANTERN_DEFAULT_CREDS[c].pass);
                    finding("CRITICAL", msg);
                    cred_found = 1;
                }
            }
        }
    }

    /* SSH */
    if (lantern_tcp_open(gateway, 22, 1500))
        finding("WARNING", "SSH (port 22) is open on router");

    /* UPnP */
    if (check_upnp_enabled(gateway))
        finding("WARNING", "UPnP is enabled — any device can open ports to the internet");

    /* Telnet */
    if (lantern_tcp_open(gateway, 23, 1500))
        finding("CRITICAL", "Telnet (port 23) is open — plaintext remote access");

    rprintf("\n");

    /* ── WiFi ────────────────────────────────────────────────────── */

    rprintf("## WiFi Networks\n\n");

    DWORD negotiated;
    HANDLE wlan = NULL;
    DWORD ret = WlanOpenHandle(2, NULL, &negotiated, &wlan);
    if (ret == ERROR_SUCCESS) {
        PWLAN_INTERFACE_INFO_LIST il = NULL;
        WlanEnumInterfaces(wlan, NULL, &il);
        if (il && il->dwNumberOfItems > 0) {
            GUID *guid = &il->InterfaceInfo[0].InterfaceGuid;
            lantern_wlan_scan_wait(wlan, guid, 3000);

            PWLAN_BSS_LIST bl = NULL;
            WlanGetNetworkBssList(wlan, guid, NULL, dot11_BSS_type_any, FALSE, NULL, &bl);

            if (bl && bl->dwNumberOfItems > 0) {
                rprintf("| SSID | BSSID | Signal | Security |\n");
                rprintf("|------|-------|--------|----------|\n");

                int open_count = 0;
                for (DWORD i = 0; i < bl->dwNumberOfItems; i++) {
                    WLAN_BSS_ENTRY *b = &bl->wlanBssEntries[i];
                    char ssid[33] = {0};
                    ULONG sl = b->dot11Ssid.uSSIDLength;
                    if (sl > 32) sl = 32;
                    memcpy(ssid, b->dot11Ssid.ucSSID, sl);
                    if (sl == 0) snprintf(ssid, sizeof(ssid), "<hidden>");

                    char bssid[20];
                    lantern_format_mac(b->dot11Bssid, bssid, sizeof(bssid));

                    const uint8_t *ies = (const uint8_t *)b + b->ulIeOffset;
                    const char *sec = lantern_security_from_ies(ies, b->ulIeSize);

                    rprintf("| %s | %s | %ld dBm | %s |\n",
                            ssid, bssid, b->lRssi, sec);

                    if (strcmp(sec, "Open") == 0) open_count++;
                }
                rprintf("\n**%lu access points** found", bl->dwNumberOfItems);
                if (open_count > 0)
                    rprintf(" (%d with **no encryption**)", open_count);
                rprintf(".\n\n");
                WlanFreeMemory(bl);
            }
        }
        if (il) WlanFreeMemory(il);
        WlanCloseHandle(wlan, NULL);
    }

    /* ── Summary ─────────────────────────────────────────────────── */

    rprintf("## Summary\n\n");
    rprintf("| Severity | Count |\n");
    rprintf("|----------|-------|\n");
    rprintf("| Critical | %d |\n", g_crit);
    rprintf("| Warning | %d |\n", g_warn);
    rprintf("| Info | %d |\n", g_info);
    rprintf("\n");

    if (g_crit > 0 || g_warn > 0) {
        rprintf("### Recommended Actions\n\n");
        int action = 1;
        if (g_crit > 0)
            rprintf("%d. **Review critical findings above** and remediate immediately\n", action++);
        rprintf("%d. **Disable UPnP** in router settings — prevents devices from opening external ports\n", action++);
        rprintf("%d. **Disable SSH** on the router if not actively used\n", action++);
        rprintf("%d. **Use HTTPS** for router admin access, not HTTP\n", action++);
        rprintf("\n");
    }

    rprintf("---\n*Generated by [Lantern Network Toolkit](https://github.com/michaelfperla/lantern)*\n");

    if (outfile) {
        fclose(g_out);
        printf("  Report saved to " C_GREEN C_BOLD "%s" C_RESET "\n\n", outfile);
    }

    WSACleanup();
    return 0;
}
