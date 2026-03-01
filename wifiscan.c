/*
 * wifiscan — Enumerate nearby WiFi networks with signal, security, channel
 * Part of the Lantern network toolkit
 *
 * Compile:
 *   gcc -O2 -Wall -Wextra -o wifiscan.exe wifiscan.c -lws2_32 -lwlanapi -lole32
 */

#include "lantern.h"
#include <wlanapi.h>

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

/* Parse security from raw Information Elements in BSS entry.
   RSN IE (tag 48) = WPA2/WPA3, WPA IE (tag 221 + MS OUI) = WPA1. */
static const char *security_from_ies(const uint8_t *ies, ULONG ie_len) {
    int has_rsn = 0, has_wpa = 0;
    int akm_type = 0; /* best AKM seen */

    const uint8_t *p = ies;
    const uint8_t *end = ies + ie_len;

    while (p + 2 <= end) {
        uint8_t tag = p[0];
        uint8_t len = p[1];
        const uint8_t *body = p + 2;

        if (body + len > end) break;

        if (tag == 48 && len >= 12) {
            /* RSN IE — WPA2/WPA3 */
            has_rsn = 1;
            /* Skip: version(2) + group cipher(4) + pairwise count(2) */
            ULONG off = 2 + 4;
            if (off + 2 > len) goto next;
            uint16_t pw_count = body[off] | ((uint16_t)body[off+1] << 8);
            off += 2 + (ULONG)pw_count * 4;
            if (off + 2 > len) goto next;
            uint16_t akm_count = body[off] | ((uint16_t)body[off+1] << 8);
            off += 2;
            for (uint16_t i = 0; i < akm_count && off + 4 <= len; i++, off += 4) {
                /* OUI 00-0F-AC, type in body[off+3] */
                if (body[off] == 0x00 && body[off+1] == 0x0F && body[off+2] == 0xAC) {
                    int t = body[off+3];
                    if (t > akm_type) akm_type = t;
                }
            }
        } else if (tag == 221 && len >= 10) {
            /* Vendor-specific — check for WPA OUI (00-50-F2 type 1) */
            if (body[0] == 0x00 && body[1] == 0x50 &&
                body[2] == 0xF2 && body[3] == 0x01) {
                has_wpa = 1;
            }
        }

    next:
        p = body + len;
    }

    if (has_rsn) {
        /* AKM type 8 = SAE (WPA3-Personal), 18 = SAE + transition */
        if (akm_type == 8 || akm_type == 18) return "WPA3-SAE";
        /* AKM type 1 = 802.1X, 5 = 802.1X-SHA256 */
        if (akm_type == 1 || akm_type == 5)  return "WPA2-Enterprise";
        /* AKM type 2 = PSK, 6 = PSK-SHA256 */
        return "WPA2-PSK";
    }
    if (has_wpa) return "WPA";
    return "Open";
}

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

    /* Trigger scan */
    ret = WlanScan(wlan_handle, iface_guid, NULL, NULL, NULL);
    if (ret == ERROR_ACCESS_DENIED) {
        printf(C_RED "\n  [!] WiFi scan denied — location permission required.\n" C_RESET);
        printf(C_DIM "      Settings > Privacy & Security > Location > allow for apps.\n" C_RESET);
        goto cleanup;
    }
    if (ret != ERROR_SUCCESS) {
        printf(C_RED "  [!] WlanScan failed: %lu\n" C_RESET, ret);
        goto cleanup;
    }

    printf(C_DIM "  Waiting for scan results..." C_RESET);
    fflush(stdout);
    Sleep(2000);
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
            const char *security = security_from_ies(ies, bss->ulIeSize);

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

int main(void) {
    lantern_init();

    lantern_banner("wifiscan", "enumerate nearby WiFi networks");

    scan_wifi();

    printf("\n");
    return 0;
}
