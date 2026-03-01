/*
 * netscan — Discover all devices on the local network via ARP
 * Part of the Lantern network toolkit
 *
 * Compile:
 *   gcc -O2 -Wall -Wextra -o netscan.exe netscan.c -lws2_32 -liphlpapi
 */

#include "lantern.h"

/* ── Adapter display ─────────────────────────────────────────────── */

static void show_adapters(void) {
    lantern_section("NETWORK ADAPTERS");

    IP_ADAPTER_INFO *info = lantern_get_adapters();
    if (!info) {
        printf(C_RED "  [!] Failed to get adapter info\n" C_RESET);
        return;
    }

    printf(C_DIM "  %-30s %-18s %-16s %-16s %-16s\n" C_RESET,
           "Adapter", "MAC", "IP", "Gateway", "Subnet");
    printf(C_DIM "  %-30s %-18s %-16s %-16s %-16s\n" C_RESET,
           "------------------------------", "------------------",
           "----------------", "----------------", "----------------");

    for (IP_ADAPTER_INFO *a = info; a; a = a->Next) {
        char mac_str[20];
        lantern_format_mac(a->Address, mac_str, sizeof(mac_str));

        const char *ip   = a->IpAddressList.IpAddress.String;
        const char *gw   = a->GatewayList.IpAddress.String;
        const char *mask = a->IpAddressList.IpMask.String;

        if (strcmp(ip, "0.0.0.0") == 0) continue;

        char name[31];
        snprintf(name, sizeof(name), "%.30s", a->Description);

        printf("  " C_GREEN "%-30s" C_RESET " " C_CYAN "%-18s" C_RESET
               " %-16s %-16s %-16s\n",
               name, mac_str, ip, gw, mask);
    }

    free(info);
}

/* ── ARP scan ────────────────────────────────────────────────────── */

typedef struct {
    uint32_t ip;
    uint8_t  mac[6];
} ArpResult;

#define MAX_HOSTS 254

static ArpResult       g_results[MAX_HOSTS];
static volatile LONG   g_found = 0;

typedef struct {
    uint32_t target_ip;
} ArpThreadArg;

static DWORD WINAPI arp_thread(LPVOID param) {
    ArpThreadArg *arg = (ArpThreadArg *)param;
    ULONG mac[2];
    ULONG mac_len = 6;

    DWORD ret = SendARP(arg->target_ip, 0, mac, &mac_len);
    if (ret == NO_ERROR && mac_len > 0) {
        uint8_t *m = (uint8_t *)mac;
        LONG idx = InterlockedIncrement(&g_found) - 1;
        if (idx < MAX_HOSTS) {
            g_results[idx].ip = arg->target_ip;
            memcpy(g_results[idx].mac, m, 6);
        }
    }

    free(arg);
    return 0;
}

static int cmp_arp(const void *a, const void *b) {
    uint32_t ia = ntohl(((const ArpResult *)a)->ip);
    uint32_t ib = ntohl(((const ArpResult *)b)->ip);
    return (ia > ib) - (ia < ib);
}

static void scan_arp(void) {
    lantern_section("ARP SCAN");

    uint32_t base_ip, mask;
    if (!lantern_get_local_network(&base_ip, &mask)) {
        printf(C_RED "  [!] No active network adapter found\n" C_RESET);
        return;
    }

    uint32_t network   = base_ip & mask;
    uint32_t net_hbo   = ntohl(network);
    uint32_t mask_hbo  = ntohl(mask);
    uint32_t num_hosts = (~mask_hbo) - 1;

    if (num_hosts > MAX_HOSTS) num_hosts = MAX_HOSTS;
    if (num_hosts == 0) {
        printf(C_RED "  [!] Subnet too small to scan\n" C_RESET);
        return;
    }

    char net_str[INET_ADDRSTRLEN], mask_str[INET_ADDRSTRLEN];
    lantern_ip_to_str(network, net_str, sizeof(net_str));
    lantern_ip_to_str(mask, mask_str, sizeof(mask_str));

    printf("  Scanning " C_CYAN "%s" C_RESET "/" C_CYAN "%s" C_RESET
           " (%lu hosts)...\n\n",
           net_str, mask_str, (unsigned long)num_hosts);

    HANDLE threads[MAX_HOSTS];
    DWORD  thread_count = 0;

    g_found = 0;
    memset(g_results, 0, sizeof(g_results));

    for (uint32_t i = 1; i <= num_hosts; i++) {
        uint32_t target = htonl(net_hbo + i);

        ArpThreadArg *arg = (ArpThreadArg *)malloc(sizeof(ArpThreadArg));
        if (!arg) continue;
        arg->target_ip = target;

        HANDLE h = CreateThread(NULL, 0, arp_thread, arg, 0, NULL);
        if (h) {
            threads[thread_count++] = h;
        } else {
            free(arg);
        }
    }

    if (thread_count > 0)
        lantern_wait_threads(threads, thread_count, 5000);

    LONG found = g_found;
    if (found > MAX_HOSTS) found = MAX_HOSTS;

    if (found == 0) {
        printf(C_DIM "  No hosts found.\n" C_RESET);
        return;
    }

    qsort(g_results, (size_t)found, sizeof(ArpResult), cmp_arp);

    printf(C_DIM "  %-16s %-18s %s\n" C_RESET,
           "IP Address", "MAC Address", "Vendor");
    printf(C_DIM "  %-16s %-18s %s\n" C_RESET,
           "----------------", "------------------", "--------------------");

    for (LONG i = 0; i < found; i++) {
        char ip_str[INET_ADDRSTRLEN], mac_str[20];
        lantern_ip_to_str(g_results[i].ip, ip_str, sizeof(ip_str));
        lantern_format_mac(g_results[i].mac, mac_str, sizeof(mac_str));
        const char *vendor = lantern_lookup_vendor(g_results[i].mac);

        printf("  " C_GREEN "%-16s" C_RESET " " C_CYAN "%-18s" C_RESET " %s\n",
               ip_str, mac_str, vendor);
    }

    printf("\n  " C_BOLD "%ld" C_RESET " hosts found.\n", (long)found);
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void) {
    lantern_init();

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    lantern_banner("netscan", "discover devices on your local network");

    show_adapters();
    scan_arp();

    printf("\n");
    WSACleanup();
    return 0;
}
