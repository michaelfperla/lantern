/*
 * wifiscan — Enumerate nearby WiFi networks with signal, security, channel
 * Part of the Lantern network toolkit
 *
 * Compile:
 *   gcc -O2 -Wall -Wextra -o wifiscan.exe wifiscan.c -lws2_32 -lwlanapi -lole32
 */

#include "lantern.h"
#include <wlanapi.h>
#include "lantern.h"  /* re-include to activate WLAN extension */

/* ── Helpers ──────────────────────────────────────────────────────── */

/* Normalize frequency to MHz — driver may report kHz or MHz */
static ULONG normalize_freq_mhz(ULONG freq_khz) {
    return (freq_khz < 10000) ? freq_khz : freq_khz / 1000;
}

static int freq_to_channel(ULONG freq_khz) {
    ULONG freq = normalize_freq_mhz(freq_khz);

    if (freq >= 2412 && freq <= 2484) {
        if (freq == 2484) return 14;
        return (int)((freq - 2412) / 5) + 1;
    }
    if (freq >= 5180 && freq <= 5885)
        return (int)((freq - 5000) / 5);
    if (freq >= 5955 && freq <= 7115)
        return (int)((freq - 5950) / 5);
    return 0;
}

static const char *freq_band(ULONG freq_khz) {
    ULONG freq = normalize_freq_mhz(freq_khz);

    if (freq >= 2400 && freq <= 2500) return "2.4 GHz";
    if (freq >= 5100 && freq <= 5900) return "5 GHz";
    if (freq >= 5925 && freq <= 7125) return "6 GHz";
    return "?";
}

/* security_from_ies now shared via lantern_security_from_ies() in lantern.h */

static void signal_bars(long rssi, char *buf, size_t buflen) {
    int bars;
    if (rssi >= -50)      bars = 4;
    else if (rssi >= -60) bars = 3;
    else if (rssi >= -70) bars = 2;
    else if (rssi >= -80) bars = 1;
    else                  bars = 0;

    const char *full  = "\xe2\x96\x88"; /* █ */
    const char *empty = "\xe2\x96\x91"; /* ░ */

    char tmp[64] = "";
    for (int i = 0; i < 4; i++)
        strcat(tmp, i < bars ? full : empty);
    snprintf(buf, buflen, "%s %ld dBm", tmp, rssi);
}

/* ── Main scan ───────────────────────────────────────────────────── */

static void scan_wifi(void) {
    HANDLE wlan_handle = NULL;
    PWLAN_INTERFACE_INFO_LIST iface_list = NULL;
    PWLAN_BSS_LIST bss_list = NULL;

    DWORD negotiated_version;
    DWORD ret = WlanOpenHandle(2, NULL, &negotiated_version, &wlan_handle);
    if (ret != ERROR_SUCCESS) {
        if (ret == ERROR_SERVICE_NOT_RUNNING)
            printf(C_RED "  [!] WLAN service not running (wlansvc)\n" C_RESET);
        else
            printf(C_RED "  [!] WlanOpenHandle failed: %lu\n" C_RESET, ret);
        return;
    }

    ret = WlanEnumInterfaces(wlan_handle, NULL, &iface_list);
    if (ret != ERROR_SUCCESS || iface_list->dwNumberOfItems == 0) {
        printf(C_DIM "  No WiFi interfaces found.\n" C_RESET);
        goto cleanup;
    }

    GUID *iface_guid = &iface_list->InterfaceInfo[0].InterfaceGuid;
    printf("  Interface: " C_CYAN "%ls" C_RESET "\n",
           iface_list->InterfaceInfo[0].strInterfaceDescription);

    /* Trigger scan with event-driven wait */
    printf(C_DIM "  Waiting for scan results..." C_RESET);
    fflush(stdout);
    lantern_wlan_scan_wait(wlan_handle, iface_guid, 3000);
    printf("\r                                \r");

    /* BSS list (per-AP: BSSID, RSSI, frequency) */
    ret = WlanGetNetworkBssList(wlan_handle, iface_guid,
                                NULL, dot11_BSS_type_any, FALSE,
                                NULL, &bss_list);
    if (ret == ERROR_ACCESS_DENIED) {
        printf(C_RED "\n  [!] BSS list denied — location permission required.\n" C_RESET);
        printf(C_DIM "      Settings > Privacy & Security > Location > allow for apps.\n" C_RESET);
        goto cleanup;
    }

    if (bss_list && bss_list->dwNumberOfItems > 0) {
        printf("\n" C_DIM "  %-32s %-18s %-20s %-5s %-10s %s\n" C_RESET,
               "SSID", "BSSID", "Signal", "Ch", "Band", "Security");
        printf(C_DIM "  %-32s %-18s %-20s %-5s %-10s %s\n" C_RESET,
               "--------------------------------", "------------------",
               "--------------------", "-----", "----------", "----------");

        for (DWORD i = 0; i < bss_list->dwNumberOfItems; i++) {
            WLAN_BSS_ENTRY *bss = &bss_list->wlanBssEntries[i];

            char ssid[33] = {0};
            ULONG ssid_len = bss->dot11Ssid.uSSIDLength;
            if (ssid_len > 32) ssid_len = 32;
            memcpy(ssid, bss->dot11Ssid.ucSSID, ssid_len);
            ssid[ssid_len] = '\0';

            if (ssid_len == 0)
                snprintf(ssid, sizeof(ssid), "<hidden>");

            char bssid_str[20];
            lantern_format_mac(bss->dot11Bssid, bssid_str, sizeof(bssid_str));

            long rssi = bss->lRssi;
            char sig_buf[64];
            signal_bars(rssi, sig_buf, sizeof(sig_buf));

            int ch = freq_to_channel(bss->ulChCenterFrequency);
            const char *band = freq_band(bss->ulChCenterFrequency);

            /* Parse security directly from this BSS entry's beacon IEs */
            const uint8_t *ies = (const uint8_t *)bss + bss->ulIeOffset;
            const char *security = lantern_security_from_ies(ies, bss->ulIeSize);

            const char *sig_color;
            if (rssi >= -50)      sig_color = C_GREEN;
            else if (rssi >= -70) sig_color = C_YELLOW;
            else                  sig_color = C_RED;

            printf("  " C_BOLD "%-32s" C_RESET " " C_DIM "%-18s" C_RESET
                   " %s%-20s" C_RESET " %-5d %-10s %s\n",
                   ssid, bssid_str, sig_color, sig_buf, ch, band, security);
        }

        printf("\n  " C_BOLD "%lu" C_RESET " access points found.\n",
               bss_list->dwNumberOfItems);
    } else {
        printf(C_DIM "  No WiFi networks found.\n" C_RESET);
    }

cleanup:
    if (bss_list) WlanFreeMemory(bss_list);
    if (iface_list) WlanFreeMemory(iface_list);
    if (wlan_handle) WlanCloseHandle(wlan_handle, NULL);
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    if (lantern_check_flags(argc, argv, "wifiscan",
            "enumerate nearby WiFi networks",
            "Usage: wifiscan [--help] [--version]\n"
            "\n"
            "Lists all visible access points with signal, channel, band, and security."))
        return 0;

    lantern_init();

    lantern_banner("wifiscan", "enumerate nearby WiFi networks");

    scan_wifi();

    printf("\n");
    return 0;
}
