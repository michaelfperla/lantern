/*
 * netwatch — Continuous network sentry
 * Watches your local network and alerts when devices join or leave.
 * Part of the Lantern network toolkit
 *
 * Usage:
 *   netwatch              (scan every 30s)
 *   netwatch <seconds>    (custom interval)
 *
 * Compile:
 *   gcc -O2 -Wall -Wextra -o netwatch.exe netwatch.c -lws2_32 -liphlpapi
 */

#include "lantern.h"

/* ── Device tracking ─────────────────────────────────────────────── */

typedef struct {
    uint8_t  mac[6];
    uint32_t ip;
    int      present;      /* seen in current scan */
    int      prev_present; /* seen in previous scan */
    int      ever_seen;    /* slot is in use */
} Device;

#define MAX_DEVICES 254

static Device g_devices[MAX_DEVICES];
static int    g_device_count = 0;

/* Find device by MAC, return index or -1 */
static int find_device(const uint8_t mac[6]) {
    for (int i = 0; i < g_device_count; i++) {
        if (memcmp(g_devices[i].mac, mac, 6) == 0)
            return i;
    }
    return -1;
}

/* Add or update a device */
static int upsert_device(uint32_t ip, const uint8_t mac[6]) {
    int idx = find_device(mac);
    if (idx >= 0) {
        g_devices[idx].ip      = ip;
        g_devices[idx].present = 1;
        return idx;
    }
    if (g_device_count >= MAX_DEVICES) return -1;
    idx = g_device_count++;
    memcpy(g_devices[idx].mac, mac, 6);
    g_devices[idx].ip           = ip;
    g_devices[idx].present      = 1;
    g_devices[idx].prev_present = 0;
    g_devices[idx].ever_seen    = 1;
    return idx;
}

/* ARP scan results buffer (reused each scan cycle) */
static LanternHost g_scan_results[LANTERN_MAX_HOSTS];

/* ── Ctrl+C handler ──────────────────────────────────────────────── */

static volatile LONG g_running = 1;

static BOOL WINAPI ctrl_handler(DWORD type) {
    (void)type;
    InterlockedExchange(&g_running, 0);
    return TRUE;
}

/* ── Timestamp helper ────────────────────────────────────────────── */

static void print_time(void) {
    SYSTEMTIME t;
    GetLocalTime(&t);
    printf(C_DIM "[%02d:%02d:%02d]" C_RESET, t.wHour, t.wMinute, t.wSecond);
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    if (lantern_check_flags(argc, argv, "netwatch",
            "continuous network sentry",
            "Usage: netwatch [seconds] [--help] [--version]\n"
            "\n"
            "Watches your network and alerts when devices join or leave.\n"
            "Default scan interval is 30 seconds (range: 5-3600)."))
        return 0;

    lantern_init();

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    int interval = 30;
    if (argc >= 2 && argv[1][0] != '-') {
        int v = atoi(argv[1]);
        if (v >= 5 && v <= 3600) interval = v;
    }

    lantern_banner("netwatch", "continuous network sentry");

    uint32_t base_ip, mask;
    if (!lantern_get_local_network(&base_ip, &mask)) {
        printf(C_RED "  [!] No active network adapter found\n" C_RESET);
        WSACleanup();
        return 1;
    }

    uint32_t network = base_ip & mask;
    char net_str[INET_ADDRSTRLEN], mask_str[INET_ADDRSTRLEN];
    lantern_ip_to_str(network, net_str, sizeof(net_str));
    lantern_ip_to_str(mask, mask_str, sizeof(mask_str));

    /* Calculate CIDR prefix length for display */
    uint32_t mask_hbo = ntohl(mask);
    int cidr = 0;
    for (uint32_t m = mask_hbo; m & 0x80000000; m <<= 1) cidr++;

    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    /* First scan — establish baseline */
    printf("  Scanning " C_CYAN "%s/%d" C_RESET " ...\n", net_str, cidr);

    int found = lantern_arp_scan(network, mask, g_scan_results, 5000);
    for (int i = 0; i < found; i++)
        upsert_device(g_scan_results[i].ip, g_scan_results[i].mac);

    int present_count = 0;
    for (int i = 0; i < g_device_count; i++) {
        if (g_devices[i].present) present_count++;
    }

    printf("  Baseline: " C_BOLD "%d" C_RESET " devices\n", present_count);
    printf("  Watching every " C_CYAN "%ds" C_RESET "... (Ctrl+C to stop)\n\n", interval);

    /* Print baseline devices */
    for (int i = 0; i < g_device_count; i++) {
        if (!g_devices[i].present) continue;
        char ip_str[INET_ADDRSTRLEN], mac_str[20];
        lantern_ip_to_str(g_devices[i].ip, ip_str, sizeof(ip_str));
        lantern_format_mac(g_devices[i].mac, mac_str, sizeof(mac_str));
        const char *vendor = lantern_lookup_vendor(g_devices[i].mac);
        printf("  " C_DIM "       " C_RESET "     %-16s %-18s %s\n", ip_str, mac_str, vendor);
    }
    printf("\n");

    /* Watch loop */
    while (g_running) {
        /* Sleep in 1s increments so Ctrl+C is responsive */
        for (int s = 0; s < interval && g_running; s++)
            Sleep(1000);

        if (!g_running) break;

        /* Mark all devices as not-present before scan */
        for (int i = 0; i < g_device_count; i++) {
            g_devices[i].prev_present = g_devices[i].present;
            g_devices[i].present = 0;
        }

        found = lantern_arp_scan(network, mask, g_scan_results, 5000);
        for (int i = 0; i < found; i++)
            upsert_device(g_scan_results[i].ip, g_scan_results[i].mac);

        /* Check for changes */
        for (int i = 0; i < g_device_count; i++) {
            if (!g_devices[i].ever_seen) continue;

            char ip_str[INET_ADDRSTRLEN], mac_str[20];
            lantern_ip_to_str(g_devices[i].ip, ip_str, sizeof(ip_str));
            lantern_format_mac(g_devices[i].mac, mac_str, sizeof(mac_str));
            const char *vendor = lantern_lookup_vendor(g_devices[i].mac);

            if (g_devices[i].present && !g_devices[i].prev_present) {
                /* New device */
                printf("  ");
                print_time();
                printf(" " C_GREEN C_BOLD "[+] NEW " C_RESET " %-16s %-18s %s\n",
                       ip_str, mac_str, vendor);
            } else if (!g_devices[i].present && g_devices[i].prev_present) {
                /* Device left */
                printf("  ");
                print_time();
                printf(" " C_RED C_BOLD "[-] GONE" C_RESET " %-16s %-18s %s\n",
                       ip_str, mac_str, vendor);
            }
        }
    }

    /* Exit summary */
    printf("\n");
    lantern_section("SESSION SUMMARY");

    int total_seen = 0, still_present = 0;
    for (int i = 0; i < g_device_count; i++) {
        if (g_devices[i].ever_seen) total_seen++;
        if (g_devices[i].present) still_present++;
    }

    printf("  Devices seen:       " C_BOLD "%d" C_RESET "\n", total_seen);
    printf("  Currently present:  " C_BOLD "%d" C_RESET "\n", still_present);
    printf("\n");

    printf(C_DIM "  %-16s %-18s %-20s %s\n" C_RESET,
           "IP Address", "MAC Address", "Vendor", "Status");
    printf(C_DIM "  %-16s %-18s %-20s %s\n" C_RESET,
           "----------------", "------------------",
           "--------------------", "--------");

    for (int i = 0; i < g_device_count; i++) {
        if (!g_devices[i].ever_seen) continue;
        char ip_str[INET_ADDRSTRLEN], mac_str[20];
        lantern_ip_to_str(g_devices[i].ip, ip_str, sizeof(ip_str));
        lantern_format_mac(g_devices[i].mac, mac_str, sizeof(mac_str));
        const char *vendor = lantern_lookup_vendor(g_devices[i].mac);
        const char *status = g_devices[i].present ? C_GREEN "online" C_RESET : C_RED "gone" C_RESET;

        printf("  %-16s %-18s %-20s %s\n", ip_str, mac_str, vendor, status);
    }

    printf("\n");
    WSACleanup();
    return 0;
}
