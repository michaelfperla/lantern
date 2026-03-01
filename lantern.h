/*
 * lantern.h — Shared utilities for the Lantern network toolkit
 * Include this in each tool. Header-only — no separate compilation needed.
 */

#ifndef LANTERN_H
#define LANTERN_H

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

/* ── MinGW compat ────────────────────────────────────────────────── */

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

#ifndef ERROR_SERVICE_NOT_RUNNING
#define ERROR_SERVICE_NOT_RUNNING 2186L
#endif

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

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

#endif /* LANTERN_H */
