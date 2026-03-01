/*
 * portscan — Scan a target host for open TCP ports with banner grabbing
 * Part of the Lantern network toolkit
 *
 * Usage:
 *   portscan <ip>
 *
 * Compile:
 *   gcc -O2 -Wall -Wextra -o portscan.exe portscan.c -lws2_32 -liphlpapi
 */

#include "lantern.h"

/* ── Port table ──────────────────────────────────────────────────── */

#define PORTFLAG_HTTP_PROBE  0x01   /* needs GET request for banner */
#define PORTFLAG_DANGEROUS   0x02   /* highlight as insecure */

typedef struct {
    const char *name;
    uint16_t    port;
    const char *desc;
    uint8_t     flags;
} PortInfo;

static const PortInfo PORTS[] = {
    {"ftp",         21,    "FTP file transfer",       PORTFLAG_DANGEROUS},
    {"ssh",         22,    "SSH remote shell",        0},
    {"telnet",      23,    "Telnet (insecure!)",      PORTFLAG_DANGEROUS},
    {"dns",         53,    "DNS",                     0},
    {"http",        80,    "HTTP web server",         PORTFLAG_HTTP_PROBE},
    {"https",       443,   "HTTPS web server",        0},
    {"smb",         445,   "SMB file sharing",        0},
    {"rtsp",        554,   "RTSP media streaming",    0},
    {"ipp",         631,   "Printing (IPP)",          PORTFLAG_HTTP_PROBE},
    {"mqtt",        1883,  "MQTT IoT messaging",      0},
    {"upnp",        1900,  "UPnP/SSDP discovery",     0},
    {"dlna",        2869,  "DLNA / UPnP events",      PORTFLAG_HTTP_PROBE},
    {"lgtv",        3000,  "LG TV API",               PORTFLAG_HTTP_PROBE},
    {"lgtv2",       3001,  "LG TV API TLS",           PORTFLAG_HTTP_PROBE},
    {"api",         3030,  "API server",              PORTFLAG_HTTP_PROBE},
    {"rdp",         3389,  "RDP remote desktop",      0},
    {"ssdp",        5000,  "SSDP / misc",             PORTFLAG_HTTP_PROBE},
    {"mdns",        5353,  "mDNS discovery",          0},
    {"api2",        5500,  "API server",              PORTFLAG_HTTP_PROBE},
    {"adb",         5555,  "Android Debug Bridge",    PORTFLAG_DANGEROUS},
    {"vnc",         5900,  "VNC remote desktop",      0},
    {"airplay",     7000,  "AirPlay",                 PORTFLAG_HTTP_PROBE},
    {"airplay2",    7100,  "AirPlay 2",               PORTFLAG_HTTP_PROBE},
    {"samsung-tv",  8001,  "Samsung SmartTV WS",      PORTFLAG_HTTP_PROBE},
    {"samsung-tv2", 8002,  "Samsung SmartTV WSS",     PORTFLAG_HTTP_PROBE},
    {"cast",        8008,  "Google Cast",             PORTFLAG_HTTP_PROBE},
    {"cast-tls",    8009,  "Google Cast TLS",         0},
    {"roku",        8060,  "Roku ECP",                PORTFLAG_HTTP_PROBE},
    {"http-alt",    8080,  "HTTP alternate",          PORTFLAG_HTTP_PROBE},
    {"http-mgmt",   8443,  "HTTPS management",        0},
    {"http-alt2",   8888,  "HTTP alternate",          PORTFLAG_HTTP_PROBE},
    {"mqtt-tls",    8883,  "MQTT TLS",                0},
    {"ws",          9000,  "WebSocket / misc",        PORTFLAG_HTTP_PROBE},
    {"hisense",     36790, "Hisense RemoteNow",       PORTFLAG_HTTP_PROBE},
};

#define PORT_COUNT (sizeof(PORTS) / sizeof(PORTS[0]))

/* ── Threaded port scan ──────────────────────────────────────────── */

typedef struct {
    const char *target;
    uint16_t    port;
    int         open;
} PortThreadArg;

static PortThreadArg g_port_results[PORT_COUNT];

static DWORD WINAPI port_thread(LPVOID param) {
    PortThreadArg *arg = (PortThreadArg *)param;

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        arg->open = 0;
        return 0;
    }

    u_long nonblock = 1;
    ioctlsocket(s, FIONBIO, &nonblock);

    struct sockaddr_in addr;
    lantern_fill_sockaddr(&addr, arg->target, arg->port);

    connect(s, (struct sockaddr *)&addr, sizeof(addr));

    fd_set wset, eset;
    FD_ZERO(&wset); FD_SET(s, &wset);
    FD_ZERO(&eset); FD_SET(s, &eset);
    struct timeval tv = {1, 500000};

    int sel = select(0, NULL, &wset, &eset, &tv);
    if (sel > 0 && FD_ISSET(s, &wset) && !FD_ISSET(s, &eset)) {
        int err = 0;
        int errlen = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen);
        arg->open = (err == 0) ? 1 : 0;
    } else {
        arg->open = 0;
    }

    closesocket(s);
    return 0;
}

/* ── Banner grabbing ─────────────────────────────────────────────── */

typedef struct {
    const char *target;
    uint16_t    port;
    uint8_t     flags;
    char        banner[256];
} BannerThreadArg;

static DWORD WINAPI banner_thread(LPVOID param) {
    BannerThreadArg *arg = (BannerThreadArg *)param;
    arg->banner[0] = '\0';

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;

    struct sockaddr_in addr;
    lantern_fill_sockaddr(&addr, arg->target, arg->port);

    DWORD timeout_ms = 2000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms));

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(s);
        return 0;
    }

    if (arg->flags & PORTFLAG_HTTP_PROBE) {
        const char *req = "GET / HTTP/1.0\r\nHost: device\r\n\r\n";
        send(s, req, (int)strlen(req), 0);
    }

    int n = recv(s, arg->banner, (int)(sizeof(arg->banner) - 1), 0);
    closesocket(s);

    if (n > 0) {
        arg->banner[n] = '\0';
        for (int i = 0; i < n; i++) {
            if (arg->banner[i] == '\r' || arg->banner[i] == '\n') {
                arg->banner[i] = '\0';
                break;
            }
            if ((unsigned char)arg->banner[i] < 32 && arg->banner[i] != '\t')
                arg->banner[i] = '.';
        }
        /* Truncate for display */
        if (strlen(arg->banner) > 50) {
            arg->banner[47] = '.';
            arg->banner[48] = '.';
            arg->banner[49] = '.';
            arg->banner[50] = '\0';
        }
    }

    return 0;
}

/* ── Main scan ───────────────────────────────────────────────────── */

static void scan_ports(const char *target) {
    /* Show target info */
    uint32_t ip = inet_addr(target);
    ULONG mac[2]; ULONG mac_len = 6;
    printf("  Target: " C_CYAN C_BOLD "%s" C_RESET "\n", target);

    if (SendARP(ip, 0, mac, &mac_len) == NO_ERROR) {
        uint8_t *m = (uint8_t *)mac;
        char mac_str[20];
        lantern_format_mac(m, mac_str, sizeof(mac_str));
        printf("  MAC:    " C_CYAN "%s" C_RESET " (%s)\n",
               mac_str, lantern_lookup_vendor(m));
    }

    printf("  Scanning %d ports...\n\n", (int)PORT_COUNT);

    /* Phase 1: parallel connect scan */
    HANDLE threads[PORT_COUNT];
    DWORD  thread_count = 0;

    for (size_t i = 0; i < PORT_COUNT; i++) {
        g_port_results[i].target = target;
        g_port_results[i].port   = PORTS[i].port;
        g_port_results[i].open   = 0;

        HANDLE h = CreateThread(NULL, 0, port_thread, &g_port_results[i], 0, NULL);
        if (h)
            threads[thread_count++] = h;
    }

    if (thread_count > 0)
        lantern_wait_threads(threads, thread_count, 10000);

    /* Phase 2: parallel banner grab on open ports */
    int open_count = 0;
    size_t open_indices[PORT_COUNT];
    for (size_t i = 0; i < PORT_COUNT; i++) {
        if (g_port_results[i].open)
            open_indices[open_count++] = i;
    }

    BannerThreadArg *banners = NULL;
    if (open_count > 0) {
        banners = (BannerThreadArg *)calloc((size_t)open_count, sizeof(BannerThreadArg));
        DWORD banner_tc = 0;

        for (int j = 0; j < open_count; j++) {
            size_t idx = open_indices[j];
            banners[j].target = target;
            banners[j].port   = PORTS[idx].port;
            banners[j].flags  = PORTS[idx].flags;

            HANDLE h = CreateThread(NULL, 0, banner_thread, &banners[j], 0, NULL);
            if (h)
                threads[banner_tc++] = h;
        }

        if (banner_tc > 0)
            lantern_wait_threads(threads, banner_tc, 10000);
    }

    /* Results */
    printf(C_DIM "  %-7s %-14s %-28s %s\n" C_RESET,
           "Port", "Service", "Description", "Banner");
    printf(C_DIM "  %-7s %-14s %-28s %s\n" C_RESET,
           "-------", "--------------", "----------------------------",
           "----------------------------------------");

    for (int j = 0; j < open_count; j++) {
        size_t idx = open_indices[j];
        const char *color = (PORTS[idx].flags & PORTFLAG_DANGEROUS) ? C_RED : C_GREEN;
        const char *banner = (banners && banners[j].banner[0]) ? banners[j].banner : "";

        printf("  %s%-7d %-14s" C_RESET " %-28s " C_DIM "%s" C_RESET "\n",
               color, PORTS[idx].port, PORTS[idx].name, PORTS[idx].desc, banner);
    }

    free(banners);

    if (open_count == 0)
        printf(C_DIM "  No open ports found.\n" C_RESET);
    else
        printf("\n  " C_BOLD "%d" C_RESET " open ports.\n", open_count);
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    lantern_init();

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    lantern_banner("portscan", "scan a host for open TCP ports");

    if (argc < 2) {
        printf("  " C_RED "Usage:" C_RESET " portscan <ip>\n");
        printf("  " C_DIM "Example: portscan 192.168.0.1" C_RESET "\n\n");
        WSACleanup();
        return 1;
    }

    scan_ports(argv[1]);

    printf("\n");
    WSACleanup();
    return 0;
}
