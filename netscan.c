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

static void scan_arp(void) {
    lantern_section("ARP SCAN");

    uint32_t base_ip, mask;
    if (!lantern_get_local_network(&base_ip, &mask)) {
        printf(C_RED "  [!] No active network adapter found\n" C_RESET);
        return;
    }

    uint32_t network   = base_ip & mask;
    uint32_t mask_hbo  = ntohl(mask);
    uint32_t num_hosts = (~mask_hbo) - 1;

    if (num_hosts > LANTERN_MAX_HOSTS) num_hosts = LANTERN_MAX_HOSTS;
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

    LanternHost results[LANTERN_MAX_HOSTS];
    int found = lantern_arp_scan(network, mask, results, 5000);

    if (found == 0) {
        printf(C_DIM "  No hosts found.\n" C_RESET);
        return;
    }

    printf(C_DIM "  %-16s %-18s %s\n" C_RESET,
           "IP Address", "MAC Address", "Vendor");
    printf(C_DIM "  %-16s %-18s %s\n" C_RESET,
           "----------------", "------------------", "--------------------");

    for (int i = 0; i < found; i++) {
        char ip_str[INET_ADDRSTRLEN], mac_str[20];
        lantern_ip_to_str(results[i].ip, ip_str, sizeof(ip_str));
        lantern_format_mac(results[i].mac, mac_str, sizeof(mac_str));
        const char *vendor = lantern_lookup_vendor(results[i].mac);

        printf("  " C_GREEN "%-16s" C_RESET " " C_CYAN "%-18s" C_RESET " %s\n",
               ip_str, mac_str, vendor);
    }

    printf("\n  " C_BOLD "%d" C_RESET " hosts found.\n", found);
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    if (lantern_check_flags(argc, argv, "netscan",
            "discover devices on your local network",
            "Usage: netscan [--help] [--version]\n"
            "\n"
            "ARP scans your subnet and identifies every device by IP, MAC, and vendor."))
        return 0;

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
