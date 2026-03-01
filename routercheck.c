/*
 * routercheck — Test router for common security misconfigurations
 * Part of the Lantern network toolkit
 *
 * Usage:
 *   routercheck              (auto-detect gateway)
 *   routercheck <ip>         (specify router IP)
 *
 * Compile:
 *   gcc -O2 -Wall -Wextra -o routercheck.exe routercheck.c -lws2_32 -liphlpapi
 */

#include "lantern.h"

/* HTTP helpers now in lantern.h: lantern_http_get, lantern_http_get_auth,
   lantern_http_status, lantern_body_contains_ci, lantern_tcp_open */

/* ── Check: Admin panel accessible ───────────────────────────────── */

static void check_admin_panel(const char *target) {
    lantern_section("ADMIN PANEL");

    static const char *paths[] = {
        "/", "/login.html", "/login.htm", "/index.html",
        "/cgi-bin/luci", "/webpages/login.html",
        "/ui/login", "/Main_Login.asp",
    };
    int path_count = sizeof(paths) / sizeof(paths[0]);

    char buf[4096];
    int found_panel = 0;

    /* Check HTTP (80) */
    for (int i = 0; i < path_count; i++) {
        int n = lantern_http_get(target, 80, paths[i], NULL, buf, sizeof(buf));
        if (n <= 0) continue;

        int status = lantern_http_status(buf);
        if (status == 200 || status == 301 || status == 302) {
            int has_login = lantern_body_contains_ci(buf, "password") ||
                            lantern_body_contains_ci(buf, "login") ||
                            lantern_body_contains_ci(buf, "sign in") ||
                            lantern_body_contains_ci(buf, "authenticate");

            if (has_login) {
                printf("  " C_YELLOW "WARNING" C_RESET "  Admin login page found at "
                       C_CYAN "http://%s%s" C_RESET "\n", target, paths[i]);
                printf("           " C_DIM "HTTP %d — login form detected" C_RESET "\n", status);
                found_panel = 1;
                break;
            } else if (status == 200) {
                printf("  " C_RED "CRITICAL" C_RESET " Admin panel responds at "
                       C_CYAN "http://%s%s" C_RESET "\n", target, paths[i]);
                printf("           " C_DIM "HTTP %d — no login form detected (may be open!)" C_RESET "\n", status);
                found_panel = 1;
                break;
            }
        }
    }

    /* Check HTTPS (443) */
    /* Note: we can't do TLS in plain C without a library.
       We just check if port 443 is open. */
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s != INVALID_SOCKET) {
            struct sockaddr_in addr;
            lantern_fill_sockaddr(&addr, target, 443);
            DWORD timeout_ms = 2000;
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms));
            if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                printf("  " C_GREEN "INFO    " C_RESET " HTTPS admin panel on port 443 "
                       C_DIM "(TLS — good)" C_RESET "\n");
            }
            closesocket(s);
        }
    }

    if (!found_panel) {
        printf("  " C_GREEN "OK      " C_RESET " No open admin panel found on HTTP\n");
    }
}

/* ── Check: Default credentials ──────────────────────────────────── */

static void check_default_creds(const char *target) {
    lantern_section("DEFAULT CREDENTIALS");

    /* Test HTTP Basic Auth against common paths.
       First fetch each path WITHOUT auth — only test credentials if the
       endpoint returns 401/403 (RFC 7235 Basic Auth challenge).  Routers
       that use form-based login return 200 regardless of Basic Auth
       headers, which caused false-positive CRITICAL findings. */
    static const char *paths[] = { "/", "/status", "/admin", "/management" };
    int path_count = sizeof(paths) / sizeof(paths[0]);

    char buf[4096];
    int tested = 0, found = 0, any_auth_required = 0;

    for (int p = 0; p < path_count && !found; p++) {
        /* Baseline: fetch without credentials */
        int bn = lantern_http_get(target, 80, paths[p], NULL, buf, sizeof(buf));
        if (bn <= 0) continue;

        int baseline = lantern_http_status(buf);
        if (baseline != 401 && baseline != 403) continue;

        /* This path requires authentication — test credentials */
        any_auth_required = 1;
        for (int c = 0; c < (int)LANTERN_CRED_COUNT; c++) {
            int n = lantern_http_get_auth(target, 80, paths[p],
                                          LANTERN_DEFAULT_CREDS[c].user, LANTERN_DEFAULT_CREDS[c].pass,
                                          buf, sizeof(buf));
            tested++;
            if (n <= 0) continue;

            int status = lantern_http_status(buf);
            if (status == 200 || status == 301 || status == 302) {
                printf("  " C_RED "CRITICAL" C_RESET " Default credentials work: "
                       C_RED C_BOLD "%s/%s" C_RESET " on %s%s\n",
                       LANTERN_DEFAULT_CREDS[c].user, LANTERN_DEFAULT_CREDS[c].pass,
                       target, paths[p]);
                found = 1;
                break;
            }
        }
    }

    if (!found && any_auth_required) {
        printf("  " C_GREEN "OK      " C_RESET " Tested %d credential pairs — none worked\n", tested);
    } else if (!found) {
        printf("  " C_CYAN "INFO    " C_RESET " Router does not use HTTP Basic Auth (form-based login)\n");
        printf("           " C_DIM "Test credentials manually via the admin panel" C_RESET "\n");
    }

    /* Test SSH if port 22 is open */
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s != INVALID_SOCKET) {
            struct sockaddr_in addr;
            lantern_fill_sockaddr(&addr, target, 22);
            DWORD timeout_ms = 2000;
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms));
            if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                char banner[256] = "";
                DWORD rtimeout = 2000;
                setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&rtimeout, sizeof(rtimeout));
                int n = recv(s, banner, sizeof(banner) - 1, 0);
                if (n > 0) {
                    banner[n] = '\0';
                    for (int i = 0; i < n; i++)
                        if (banner[i] == '\r' || banner[i] == '\n') { banner[i] = '\0'; break; }
                    printf("  " C_YELLOW "WARNING" C_RESET "  SSH is open — banner: " C_DIM "%s" C_RESET "\n", banner);
                } else {
                    printf("  " C_YELLOW "WARNING" C_RESET "  SSH port 22 is open\n");
                }
                printf("           " C_DIM "Ensure SSH uses key auth, not password" C_RESET "\n");
            }
            closesocket(s);
        }
    }
}

/* ── Check: UPnP / SSDP ─────────────────────────────────────────── */

static void check_upnp(const char *target) {
    lantern_section("UPnP / SSDP");

    /* Send SSDP M-SEARCH to the router */
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        printf("  " C_DIM "Could not create UDP socket\n" C_RESET);
        return;
    }

    struct sockaddr_in addr;
    lantern_fill_sockaddr(&addr, target, 1900);

    DWORD timeout_ms = 3000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms));

    const char *msearch =
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n";

    /* Send directly to router, not multicast */
    sendto(s, msearch, (int)strlen(msearch), 0,
           (struct sockaddr *)&addr, sizeof(addr));

    /* Also send to multicast address */
    struct sockaddr_in mcast;
    lantern_fill_sockaddr(&mcast, "239.255.255.250", 1900);
    sendto(s, msearch, (int)strlen(msearch), 0,
           (struct sockaddr *)&mcast, sizeof(mcast));

    /* Collect responses */
    int response_count = 0;
    int has_igd = 0;      /* Internet Gateway Device = port forwarding capable */
    int has_wanip = 0;    /* WAN IP connection = can query external IP */
    char buf[2048];

    for (int attempt = 0; attempt < 10; attempt++) {
        struct sockaddr_in from;
        int fromlen = sizeof(from);
        int n = recvfrom(s, buf, sizeof(buf) - 1, 0,
                         (struct sockaddr *)&from, &fromlen);
        if (n <= 0) break;
        buf[n] = '\0';
        response_count++;

        /* Check for dangerous UPnP service types */
        if (strstr(buf, "InternetGatewayDevice")) has_igd = 1;
        if (strstr(buf, "WANIPConnection")) has_wanip = 1;
        if (strstr(buf, "WANPPPConnection")) has_wanip = 1;

        /* Extract SERVER header for info */
        if (response_count == 1) {
            const char *server = strstr(buf, "SERVER:");
            if (!server) server = strstr(buf, "Server:");
            if (server) {
                server += 7;
                while (*server == ' ') server++;
                char srvbuf[128];
                int si = 0;
                while (*server && *server != '\r' && *server != '\n' && si < 127)
                    srvbuf[si++] = *server++;
                srvbuf[si] = '\0';
                printf("  " C_CYAN "INFO    " C_RESET " UPnP device: " C_DIM "%s" C_RESET "\n", srvbuf);
            }
        }
    }

    closesocket(s);

    if (response_count == 0) {
        printf("  " C_GREEN "OK      " C_RESET " No UPnP responses — UPnP appears disabled\n");
    } else {
        printf("  " C_YELLOW "WARNING" C_RESET "  UPnP is enabled (%d responses)\n", response_count);
        if (has_igd) {
            printf("  " C_RED "CRITICAL" C_RESET " InternetGatewayDevice exposed — "
                   "any device can open ports\n");
        }
        if (has_wanip) {
            printf("  " C_YELLOW "WARNING" C_RESET "  WAN IP/PPP connection service exposed\n");
        }
        printf("           " C_DIM "Recommendation: disable UPnP in router settings" C_RESET "\n");
    }
}

/* ── Check: DNS configuration ────────────────────────────────────── */

static void check_dns(const char *target) {
    lantern_section("DNS CONFIGURATION");

    /* Send a DNS query to the router and see if it responds */
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return;

    struct sockaddr_in addr;
    lantern_fill_sockaddr(&addr, target, 53);

    DWORD timeout_ms = 3000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms));

    /* Minimal DNS query for example.com A record */
    uint8_t query[] = {
        0x12, 0x34,  /* Transaction ID */
        0x01, 0x00,  /* Standard query, recursion desired */
        0x00, 0x01,  /* 1 question */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* no answers/auth/additional */
        /* QNAME: example.com */
        7, 'e','x','a','m','p','l','e',
        3, 'c','o','m',
        0,           /* root label */
        0x00, 0x01,  /* Type A */
        0x00, 0x01,  /* Class IN */
    };

    sendto(s, (const char *)query, sizeof(query), 0,
           (struct sockaddr *)&addr, sizeof(addr));

    char buf[512];
    struct sockaddr_in from;
    int fromlen = sizeof(from);
    int n = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
    closesocket(s);

    if (n > 0) {
        printf("  " C_CYAN "INFO    " C_RESET " Router is acting as DNS resolver\n");

        /* Check if the router's DNS is likely forwarding to a known public resolver
           by looking at response time (heuristic) or just reporting the fact */
        printf("           " C_DIM "The router resolves DNS queries on port 53" C_RESET "\n");
        printf("           " C_DIM "Verify it forwards to a trusted upstream (8.8.8.8, 1.1.1.1, etc.)" C_RESET "\n");
    } else {
        printf("  " C_CYAN "INFO    " C_RESET " Router does not respond to DNS queries\n");
        printf("           " C_DIM "DNS is handled by ISP or another resolver" C_RESET "\n");
    }
}

/* ── Check: Open services summary ────────────────────────────────── */

typedef struct {
    const char *host;
    uint16_t    port;
    int        *flag;
} SvcCheckArg;

static DWORD WINAPI svc_check_thread(LPVOID param) {
    SvcCheckArg *arg = (SvcCheckArg *)param;
    *arg->flag = lantern_tcp_open(arg->host, arg->port, 1500);
    return 0;
}

#define SVC_SEVERITY_OK   0
#define SVC_SEVERITY_WARN 1
#define SVC_SEVERITY_CRIT 2

static void check_services(const char *target) {
    lantern_section("OPEN SERVICES");

    static const struct {
        uint16_t    port;
        const char *name;
        const char *risk;
        int         severity;
        int         is_udp;    /* 1 = UDP check (SNMP), 0 = TCP */
    } checks[] = {
        {22,   "SSH",       "Remote shell access — ensure key-based auth",      SVC_SEVERITY_WARN, 0},
        {23,   "Telnet",    "Plaintext remote shell — DISABLE IMMEDIATELY",     SVC_SEVERITY_CRIT, 0},
        {80,   "HTTP",      "Unencrypted admin panel",                          SVC_SEVERITY_WARN, 0},
        {443,  "HTTPS",     "Encrypted admin panel (good)",                     SVC_SEVERITY_OK,   0},
        {5000, "SSDP",      "UPnP/SSDP service",                               SVC_SEVERITY_WARN, 0},
        {8080, "HTTP-Alt",  "Alternate HTTP — may be management interface",     SVC_SEVERITY_WARN, 0},
        {8443, "HTTPS-Mgmt","HTTPS management",                                SVC_SEVERITY_OK,   0},
        {53,   "DNS",       "DNS resolver",                                     SVC_SEVERITY_OK,   0},
        {161,  "SNMP",      "Network management — often default community string", SVC_SEVERITY_CRIT, 1},
    };
    int check_count = sizeof(checks) / sizeof(checks[0]);
    int open_flags[sizeof(checks) / sizeof(checks[0])];
    memset(open_flags, 0, sizeof(open_flags));

    /* Parallel TCP checks (skip UDP entries — handled below) */
    SvcCheckArg args[sizeof(checks) / sizeof(checks[0])];
    HANDLE threads[sizeof(checks) / sizeof(checks[0])];
    DWORD tc = 0;

    for (int i = 0; i < check_count; i++) {
        if (checks[i].is_udp) continue;
        args[i].host = target;
        args[i].port = checks[i].port;
        args[i].flag = &open_flags[i];
        HANDLE h = CreateThread(NULL, 0, svc_check_thread, &args[i], 0, NULL);
        if (h) threads[tc++] = h;
    }
    if (tc > 0) lantern_wait_threads(threads, tc, 3000);

    /* SNMP (UDP) probe */
    for (int i = 0; i < check_count; i++) {
        if (checks[i].is_udp && checks[i].port == 161)
            open_flags[i] = lantern_snmp_probe(target, 2000);
    }

    int open_count = 0;
    for (int i = 0; i < check_count; i++) {
        if (!open_flags[i]) continue;
        open_count++;

        const char *color = C_GREEN;
        if (checks[i].severity == SVC_SEVERITY_CRIT) color = C_RED;
        else if (checks[i].severity == SVC_SEVERITY_WARN) color = C_YELLOW;

        printf("  %s%-8s" C_RESET " Port %-5d — %s\n",
               color, checks[i].name, checks[i].port, checks[i].risk);
    }

    if (open_count == 0)
        printf("  " C_GREEN "OK      " C_RESET " No common services detected\n");
    else
        printf("\n  %d services open on router\n", open_count);
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    if (lantern_check_flags(argc, argv, "routercheck",
            "test your router for misconfigurations",
            "Usage: routercheck [ip] [--help] [--version]\n"
            "\n"
            "Probes your gateway for common security issues: open admin panels,\n"
            "default credentials, UPnP exposure, SSH, DNS, and dangerous services.\n"
            "Auto-detects gateway if no IP is given."))
        return 0;

    lantern_init();

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    lantern_banner("routercheck", "test your router for misconfigurations");

    char target[64];
    if (argc >= 2 && argv[1][0] != '-') {
        snprintf(target, sizeof(target), "%s", argv[1]);
    } else {
        if (!lantern_get_gateway(target, sizeof(target))) {
            printf(C_RED "  [!] Could not auto-detect gateway\n" C_RESET);
            printf(C_DIM "  Usage: routercheck <router-ip>\n" C_RESET);
            WSACleanup();
            return 1;
        }
    }

    /* Validate IP format */
    uint32_t ip = inet_addr(target);
    if (ip == INADDR_NONE) {
        printf(C_RED "  [!] Invalid IP address: %s\n" C_RESET, target);
        WSACleanup();
        return 1;
    }
    ULONG mac[2]; ULONG mac_len = 6;
    printf("  Router: " C_CYAN C_BOLD "%s" C_RESET, target);
    if (SendARP(ip, 0, mac, &mac_len) == NO_ERROR) {
        uint8_t *m = (uint8_t *)mac;
        char mac_str[20];
        lantern_format_mac(m, mac_str, sizeof(mac_str));
        printf(" (" C_CYAN "%s" C_RESET " — %s)", mac_str, lantern_lookup_vendor(m));
    }
    printf("\n");

    check_services(target);
    check_admin_panel(target);
    check_default_creds(target);
    check_upnp(target);
    check_dns(target);

    printf("\n");
    WSACleanup();
    return 0;
}
