#include "command_router.h"
#include "transport_ble.h"
#include "scan_wifi.h"
#include "scan_ble.h"
#include "hacking_wifi.h"
#include "hacking_ble.h"
#include "attack_lan.h"
#include "sniff_wifi.h"
#include "evil_twin.h"
#include "captive_portal.h"
#include "watchdog.h"

#include <stdio.h>
#include <string.h>

#include "cJSON.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_idf_version.h"
#include "esp_chip_info.h"
#include "esp_heap_caps.h"
#include "esp_app_desc.h"

static const char *TAG = "cmd-router";

static void send_json(cJSON *obj)
{
    char *buf = cJSON_PrintUnformatted(obj);
    if (!buf) {
        ESP_LOGW(TAG, "json print failed");
        return;
    }
    transport_ble_send_cmd((const uint8_t *)buf, strlen(buf));
    cJSON_free(buf);
}

static void send_err(int seq, const char *err, const char *msg)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "err", err);
    cJSON_AddNumberToObject(root, "seq", seq);
    if (msg) cJSON_AddStringToObject(root, "msg", msg);
    send_json(root);
    cJSON_Delete(root);
}

static int seq_of(cJSON *root)
{
    cJSON *seq = cJSON_GetObjectItemCaseSensitive(root, "seq");
    return (cJSON_IsNumber(seq)) ? seq->valueint : 0;
}

static void handle_ping(cJSON *root)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "resp", "pong");
    cJSON_AddNumberToObject(resp, "seq", seq_of(root));
    cJSON_AddNumberToObject(resp, "uptime_ms",
                            (double)(esp_timer_get_time() / 1000));
    send_json(resp);
    cJSON_Delete(resp);
}

static void handle_hello(cJSON *root)
{
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    const esp_app_desc_t *app = esp_app_get_description();

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "resp", "hello");
    cJSON_AddNumberToObject(resp, "seq", seq_of(root));
    cJSON_AddStringToObject(resp, "fw", app->version);
    cJSON_AddStringToObject(resp, "idf", esp_get_idf_version());
    cJSON_AddStringToObject(resp, "chip", "esp32s3");
    cJSON_AddNumberToObject(resp, "cores", chip.cores);
    cJSON_AddNumberToObject(resp, "rev", chip.revision);
    send_json(resp);
    cJSON_Delete(resp);
}

static void send_ack(int seq, const char *cmd)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "resp", cmd);
    cJSON_AddNumberToObject(resp, "seq", seq);
    cJSON_AddStringToObject(resp, "status", "started");
    send_json(resp);
    cJSON_Delete(resp);
}

static void handle_wifi_scan(cJSON *root)
{
    int seq = seq_of(root);
    cJSON *mode_j = cJSON_GetObjectItemCaseSensitive(root, "mode");
    cJSON *ch_j   = cJSON_GetObjectItemCaseSensitive(root, "channel");

    scan_wifi_mode_t mode = SCAN_WIFI_MODE_ACTIVE;
    if (cJSON_IsString(mode_j) && mode_j->valuestring) {
        if (strcmp(mode_j->valuestring, "passive") == 0)      mode = SCAN_WIFI_MODE_PASSIVE;
        else if (strcmp(mode_j->valuestring, "active") == 0)  mode = SCAN_WIFI_MODE_ACTIVE;
        else { send_err(seq, "bad_mode", "active|passive"); return; }
    }
    int ch = cJSON_IsNumber(ch_j) ? ch_j->valueint : 0;
    if (ch < 0 || ch > 13) { send_err(seq, "bad_channel", "0..13"); return; }

    esp_err_t err = scan_wifi_start(mode, (uint8_t)ch);
    if (err == ESP_OK) {
        send_ack(seq, "wifi_scan");
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "scan_busy", NULL);
    } else {
        send_err(seq, "scan_failed", esp_err_to_name(err));
    }
}

static void handle_ble_scan(cJSON *root)
{
    int seq = seq_of(root);
    cJSON *dur    = cJSON_GetObjectItemCaseSensitive(root, "duration_sec");
    cJSON *mode_j = cJSON_GetObjectItemCaseSensitive(root, "mode");

    uint16_t duration = 10; // default 10s
    if (cJSON_IsNumber(dur) && dur->valueint >= 0 && dur->valueint < 600) {
        duration = (uint16_t)dur->valueint;
    }
    scan_ble_mode_t mode = SCAN_BLE_MODE_PASSIVE;
    if (cJSON_IsString(mode_j) && mode_j->valuestring) {
        if (strcmp(mode_j->valuestring, "active") == 0)        mode = SCAN_BLE_MODE_ACTIVE;
        else if (strcmp(mode_j->valuestring, "passive") == 0)  mode = SCAN_BLE_MODE_PASSIVE;
        else { send_err(seq, "bad_mode", "active|passive"); return; }
    }

    esp_err_t err = scan_ble_start_ex(mode, duration);
    if (err == ESP_OK) {
        send_ack(seq, "ble_scan");
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "scan_busy", NULL);
    } else {
        send_err(seq, "scan_failed", esp_err_to_name(err));
    }
}

static int parse_mac(const char *s, uint8_t out[6])
{
    if (!s) return -1;
    unsigned b[6];
    if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
        return -1;
    }
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)(b[i] & 0xFF);
    return 0;
}

static int parse_ipv4(const char *s, uint8_t out[4])
{
    if (!s) return -1;
    unsigned b[4];
    if (sscanf(s, "%u.%u.%u.%u", &b[0], &b[1], &b[2], &b[3]) != 4) return -1;
    for (int i = 0; i < 4; i++) {
        if (b[i] > 255) return -1;
        out[i] = (uint8_t)b[i];
    }
    return 0;
}

static void handle_wifi_connect(cJSON *root)
{
    int seq = seq_of(root);
    cJSON *ssid_j = cJSON_GetObjectItemCaseSensitive(root, "ssid");
    cJSON *psk_j  = cJSON_GetObjectItemCaseSensitive(root, "password");
    cJSON *to_j   = cJSON_GetObjectItemCaseSensitive(root, "timeout_ms");

    if (!cJSON_IsString(ssid_j) || !ssid_j->valuestring[0]) {
        send_err(seq, "bad_ssid", NULL);
        return;
    }
    const char *psk = cJSON_IsString(psk_j) ? psk_j->valuestring : NULL;
    int to_raw = cJSON_IsNumber(to_j) ? to_j->valueint : 15000;
    if (to_raw < 1000) to_raw = 1000;
    if (to_raw > 60000) to_raw = 60000;
    uint16_t to = (uint16_t)to_raw;

    uint8_t ip[4], gw[4], mac[6];
    esp_err_t err = attack_lan_wifi_connect(ssid_j->valuestring, psk, to, ip, gw, mac);
    if (err == ESP_OK) {
        char ip_s[16], gw_s[16], mac_s[18];
        snprintf(ip_s, sizeof(ip_s), "%u.%u.%u.%u", ip[0],ip[1],ip[2],ip[3]);
        snprintf(gw_s, sizeof(gw_s), "%u.%u.%u.%u", gw[0],gw[1],gw[2],gw[3]);
        snprintf(mac_s, sizeof(mac_s), "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "resp", "wifi_connect");
        cJSON_AddNumberToObject(resp, "seq", seq);
        cJSON_AddStringToObject(resp, "status", "connected");
        cJSON_AddStringToObject(resp, "ip", ip_s);
        cJSON_AddStringToObject(resp, "gateway", gw_s);
        cJSON_AddStringToObject(resp, "mac", mac_s);
        send_json(resp);
        cJSON_Delete(resp);
    } else if (err == ESP_ERR_TIMEOUT) {
        send_err(seq, "wifi_timeout", NULL);
    } else {
        send_err(seq, "wifi_failed", esp_err_to_name(err));
    }
}

static void handle_wifi_disconnect(cJSON *root)
{
    int seq = seq_of(root);
    attack_lan_wifi_disconnect();
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "resp", "wifi_disconnect");
    cJSON_AddNumberToObject(resp, "seq", seq);
    cJSON_AddStringToObject(resp, "status", "disconnected");
    send_json(resp);
    cJSON_Delete(resp);
}

static void handle_arp_cut(cJSON *root)
{
    int seq = seq_of(root);
    if (!attack_lan_is_connected()) {
        send_err(seq, "wifi_not_connected", NULL);
        return;
    }

    cJSON *t_ip_j   = cJSON_GetObjectItemCaseSensitive(root, "target_ip");
    cJSON *t_mac_j  = cJSON_GetObjectItemCaseSensitive(root, "target_mac");
    cJSON *gw_ip_j  = cJSON_GetObjectItemCaseSensitive(root, "gateway_ip");
    cJSON *gw_mac_j = cJSON_GetObjectItemCaseSensitive(root, "gateway_mac");
    cJSON *iv_j     = cJSON_GetObjectItemCaseSensitive(root, "interval_ms");
    cJSON *dur_j    = cJSON_GetObjectItemCaseSensitive(root, "duration_sec");

    uint8_t t_ip[4], t_mac[6], gw_ip[4], gw_mac[6];
    if (!cJSON_IsString(t_ip_j)   || parse_ipv4(t_ip_j->valuestring, t_ip)   != 0)
        { send_err(seq, "bad_target_ip", NULL); return; }
    if (!cJSON_IsString(t_mac_j)  || parse_mac(t_mac_j->valuestring, t_mac)  != 0)
        { send_err(seq, "bad_target_mac", NULL); return; }
    if (!cJSON_IsString(gw_ip_j)  || parse_ipv4(gw_ip_j->valuestring, gw_ip) != 0)
        { send_err(seq, "bad_gateway_ip", NULL); return; }
    if (!cJSON_IsString(gw_mac_j) || parse_mac(gw_mac_j->valuestring, gw_mac)!= 0)
        { send_err(seq, "bad_gateway_mac", NULL); return; }

    uint16_t iv = cJSON_IsNumber(iv_j) ? (uint16_t)iv_j->valueint : 1000;
    uint16_t dur = cJSON_IsNumber(dur_j) ? (uint16_t)dur_j->valueint : 60;

    esp_err_t err = attack_lan_arp_cut_start(t_ip, t_mac, gw_ip, gw_mac, iv, dur);
    if (err == ESP_OK) {
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "resp", "arp_cut");
        cJSON_AddNumberToObject(resp, "seq", seq);
        cJSON_AddStringToObject(resp, "status", "started");
        cJSON_AddNumberToObject(resp, "interval_ms", iv);
        cJSON_AddNumberToObject(resp, "duration_sec", dur);
        send_json(resp);
        cJSON_Delete(resp);
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "cut_busy_or_offline", NULL);
    } else {
        send_err(seq, "cut_failed", esp_err_to_name(err));
    }
}

static void handle_arp_cut_stop(cJSON *root)
{
    int seq = seq_of(root);
    esp_err_t err = attack_lan_arp_cut_stop();
    if (err == ESP_OK) {
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "resp", "arp_cut_stop");
        cJSON_AddNumberToObject(resp, "seq", seq);
        cJSON_AddStringToObject(resp, "status", "stopping");
        send_json(resp);
        cJSON_Delete(resp);
    } else {
        send_err(seq, "cut_idle", NULL);
    }
}

static void handle_probe_sniff(cJSON *root)
{
    int seq = seq_of(root);
    if (attack_lan_is_connected()) {
        send_err(seq, "wifi_busy", "disconnect first (channel hop conflicts with STA)");
        return;
    }

    cJSON *cmin_j = cJSON_GetObjectItemCaseSensitive(root, "ch_min");
    cJSON *cmax_j = cJSON_GetObjectItemCaseSensitive(root, "ch_max");
    cJSON *dw_j   = cJSON_GetObjectItemCaseSensitive(root, "dwell_ms");
    cJSON *dur_j  = cJSON_GetObjectItemCaseSensitive(root, "duration_sec");

    int cmin = cJSON_IsNumber(cmin_j) ? cmin_j->valueint : 1;
    int cmax = cJSON_IsNumber(cmax_j) ? cmax_j->valueint : 13;
    int dw   = cJSON_IsNumber(dw_j)   ? dw_j->valueint   : 500;
    int dur  = cJSON_IsNumber(dur_j)  ? dur_j->valueint  : 30;

    if (cmin < 1 || cmin > 13 || cmax < 1 || cmax > 13 || cmax < cmin) {
        send_err(seq, "bad_channel", "ch_min/ch_max out of 1..13");
        return;
    }
    if (dw < 100)  dw = 100;
    if (dw > 5000) dw = 5000;
    if (dur < 1)   dur = 1;
    if (dur > 300) dur = 300;

    esp_err_t err = sniff_wifi_probe_start(
        (uint8_t)cmin, (uint8_t)cmax, (uint16_t)dw, (uint16_t)dur);
    if (err == ESP_OK) {
        send_ack(seq, "probe_sniff");
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "sniff_busy", NULL);
    } else {
        send_err(seq, "sniff_failed", esp_err_to_name(err));
    }
}

static void handle_probe_sniff_stop(cJSON *root)
{
    int seq = seq_of(root);
    esp_err_t err = sniff_wifi_probe_stop();
    if (err == ESP_OK) {
        send_ack(seq, "probe_sniff_stop");
    } else {
        send_err(seq, "sniff_idle", NULL);
    }
}

static void handle_wpa_capture(cJSON *root)
{
    int seq = seq_of(root);
    if (attack_lan_is_connected()) {
        send_err(seq, "wifi_busy", "disconnect first (channel hop conflicts with STA)");
        return;
    }

    cJSON *bssid_j = cJSON_GetObjectItemCaseSensitive(root, "bssid");
    cJSON *ch_j    = cJSON_GetObjectItemCaseSensitive(root, "channel");
    cJSON *dur_j   = cJSON_GetObjectItemCaseSensitive(root, "duration_sec");

    uint8_t bssid[6];
    if (!cJSON_IsString(bssid_j) || parse_mac(bssid_j->valuestring, bssid) != 0) {
        send_err(seq, "bad_bssid", NULL);
        return;
    }
    if (!cJSON_IsNumber(ch_j) || ch_j->valueint < 1 || ch_j->valueint > 13) {
        send_err(seq, "bad_channel", NULL);
        return;
    }
    int dur = cJSON_IsNumber(dur_j) ? dur_j->valueint : 60;
    if (dur < 1)   dur = 1;
    if (dur > 600) dur = 600;

    esp_err_t err = sniff_wifi_eapol_start(bssid, (uint8_t)ch_j->valueint,
                                            (uint16_t)dur);
    if (err == ESP_OK) {
        send_ack(seq, "wpa_capture");
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "sniff_busy", NULL);
    } else {
        send_err(seq, "sniff_failed", esp_err_to_name(err));
    }
}

static void handle_wpa_capture_stop(cJSON *root)
{
    int seq = seq_of(root);
    esp_err_t err = sniff_wifi_eapol_stop();
    if (err == ESP_OK) {
        send_ack(seq, "wpa_capture_stop");
    } else {
        send_err(seq, "sniff_idle", NULL);
    }
}

static void handle_pmkid_capture(cJSON *root)
{
    int seq = seq_of(root);
    if (attack_lan_is_connected()) {
        send_err(seq, "wifi_busy", "disconnect first");
        return;
    }

    cJSON *bssid_j = cJSON_GetObjectItemCaseSensitive(root, "bssid");
    cJSON *ch_j    = cJSON_GetObjectItemCaseSensitive(root, "channel");
    cJSON *dur_j   = cJSON_GetObjectItemCaseSensitive(root, "duration_sec");

    uint8_t bssid[6];
    if (!cJSON_IsString(bssid_j) || parse_mac(bssid_j->valuestring, bssid) != 0) {
        send_err(seq, "bad_bssid", NULL);
        return;
    }
    if (!cJSON_IsNumber(ch_j) || ch_j->valueint < 1 || ch_j->valueint > 13) {
        send_err(seq, "bad_channel", NULL);
        return;
    }
    int dur = cJSON_IsNumber(dur_j) ? dur_j->valueint : 60;
    if (dur < 1)   dur = 1;
    if (dur > 600) dur = 600;

    esp_err_t err = sniff_wifi_pmkid_start(bssid, (uint8_t)ch_j->valueint,
                                            (uint16_t)dur);
    if (err == ESP_OK) {
        send_ack(seq, "pmkid_capture");
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "sniff_busy", NULL);
    } else {
        send_err(seq, "sniff_failed", esp_err_to_name(err));
    }
}

static void handle_pmkid_capture_stop(cJSON *root)
{
    int seq = seq_of(root);
    esp_err_t err = sniff_wifi_pmkid_stop();
    if (err == ESP_OK) {
        send_ack(seq, "pmkid_capture_stop");
    } else {
        send_err(seq, "sniff_idle", NULL);
    }
}

static uint8_t parse_pcap_filter(const char *s)
{
    if (!s) return SNIFF_PCAP_FILTER_MGMT;
    if (strcmp(s, "all") == 0)  return SNIFF_PCAP_FILTER_ALL;
    if (strcmp(s, "mgmt") == 0) return SNIFF_PCAP_FILTER_MGMT;
    if (strcmp(s, "data") == 0) return SNIFF_PCAP_FILTER_DATA;
    if (strcmp(s, "ctrl") == 0) return SNIFF_PCAP_FILTER_CTRL;
    // Suporte a "mgmt+data" etc.
    uint8_t mask = 0;
    if (strstr(s, "mgmt")) mask |= SNIFF_PCAP_FILTER_MGMT;
    if (strstr(s, "data")) mask |= SNIFF_PCAP_FILTER_DATA;
    if (strstr(s, "ctrl")) mask |= SNIFF_PCAP_FILTER_CTRL;
    return mask;
}

static void handle_pcap_start(cJSON *root)
{
    int seq = seq_of(root);
    if (attack_lan_is_connected()) {
        send_err(seq, "wifi_busy", "disconnect first");
        return;
    }

    cJSON *ch_j     = cJSON_GetObjectItemCaseSensitive(root, "channel");
    cJSON *filter_j = cJSON_GetObjectItemCaseSensitive(root, "filter");
    cJSON *bssid_j  = cJSON_GetObjectItemCaseSensitive(root, "bssid");
    cJSON *dur_j    = cJSON_GetObjectItemCaseSensitive(root, "duration_sec");

    if (!cJSON_IsNumber(ch_j) || ch_j->valueint < 1 || ch_j->valueint > 13) {
        send_err(seq, "bad_channel", NULL);
        return;
    }
    uint8_t filter = SNIFF_PCAP_FILTER_MGMT;
    if (cJSON_IsString(filter_j)) {
        filter = parse_pcap_filter(filter_j->valuestring);
        if (filter == 0) {
            send_err(seq, "bad_filter", "mgmt|data|ctrl|all|mgmt+data|...");
            return;
        }
    }
    uint8_t bssid[6];
    bool has_bssid = false;
    if (cJSON_IsString(bssid_j) && bssid_j->valuestring[0]) {
        if (parse_mac(bssid_j->valuestring, bssid) != 0) {
            send_err(seq, "bad_bssid", NULL);
            return;
        }
        has_bssid = true;
    }
    int dur = cJSON_IsNumber(dur_j) ? dur_j->valueint : 60;
    if (dur < 1)   dur = 1;
    if (dur > 300) dur = 300;

    esp_err_t err = sniff_wifi_pcap_start((uint8_t)ch_j->valueint, filter,
                                           has_bssid ? bssid : NULL,
                                           (uint16_t)dur);
    if (err == ESP_OK) {
        send_ack(seq, "pcap_start");
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "sniff_busy", NULL);
    } else {
        send_err(seq, "sniff_failed", esp_err_to_name(err));
    }
}

static void handle_pcap_stop(cJSON *root)
{
    int seq = seq_of(root);
    esp_err_t err = sniff_wifi_pcap_stop();
    if (err == ESP_OK) {
        send_ack(seq, "pcap_stop");
    } else {
        send_err(seq, "sniff_idle", NULL);
    }
}

static void handle_karma_start(cJSON *root)
{
    int seq = seq_of(root);
    if (attack_lan_is_connected()) {
        send_err(seq, "wifi_busy", "disconnect first");
        return;
    }

    cJSON *ch_j  = cJSON_GetObjectItemCaseSensitive(root, "channel");
    cJSON *dur_j = cJSON_GetObjectItemCaseSensitive(root, "duration_sec");

    if (!cJSON_IsNumber(ch_j) || ch_j->valueint < 1 || ch_j->valueint > 13) {
        send_err(seq, "bad_channel", NULL);
        return;
    }
    int dur = cJSON_IsNumber(dur_j) ? dur_j->valueint : 60;
    if (dur < 1)   dur = 1;
    if (dur > 300) dur = 300;

    esp_err_t err = sniff_wifi_karma_start((uint8_t)ch_j->valueint,
                                            (uint16_t)dur);
    if (err == ESP_OK) {
        send_ack(seq, "karma_start");
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "sniff_busy", NULL);
    } else {
        send_err(seq, "sniff_failed", esp_err_to_name(err));
    }
}

static void handle_karma_stop(cJSON *root)
{
    int seq = seq_of(root);
    esp_err_t err = sniff_wifi_karma_stop();
    if (err == ESP_OK) {
        send_ack(seq, "karma_stop");
    } else {
        send_err(seq, "sniff_idle", NULL);
    }
}

static void handle_defense_start(cJSON *root)
{
    int seq = seq_of(root);
    if (attack_lan_is_connected()) {
        send_err(seq, "wifi_busy", "disconnect first");
        return;
    }

    cJSON *mask_j  = cJSON_GetObjectItemCaseSensitive(root, "mask");
    cJSON *ch_j    = cJSON_GetObjectItemCaseSensitive(root, "channel");
    cJSON *cmin_j  = cJSON_GetObjectItemCaseSensitive(root, "ch_min");
    cJSON *cmax_j  = cJSON_GetObjectItemCaseSensitive(root, "ch_max");
    cJSON *dw_j    = cJSON_GetObjectItemCaseSensitive(root, "dwell_ms");
    cJSON *dur_j   = cJSON_GetObjectItemCaseSensitive(root, "duration_sec");

    int mask_val = cJSON_IsNumber(mask_j) ? mask_j->valueint : DEFENSE_DETECT_ALL;
    if (mask_val < 1 || mask_val > 0x0F) {
        send_err(seq, "bad_mask", "1..15 (bitmask)");
        return;
    }
    int ch = cJSON_IsNumber(ch_j) ? ch_j->valueint : 0;
    if (ch < 0 || ch > 13) { send_err(seq, "bad_channel", NULL); return; }

    int cmin = cJSON_IsNumber(cmin_j) ? cmin_j->valueint : 1;
    int cmax = cJSON_IsNumber(cmax_j) ? cmax_j->valueint : 13;
    int dw   = cJSON_IsNumber(dw_j)   ? dw_j->valueint   : 500;
    int dur  = cJSON_IsNumber(dur_j)  ? dur_j->valueint  : 60;
    if (dur < 0)    dur = 0;     // 0 = sem timeout (até 1h cap interno)
    if (dur > 3600) dur = 3600;

    esp_err_t err = sniff_wifi_defense_start(
        (uint8_t)mask_val, (uint8_t)ch,
        (uint8_t)cmin, (uint8_t)cmax,
        (uint16_t)dw, (uint16_t)dur);
    if (err == ESP_OK) {
        send_ack(seq, "defense_start");
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "sniff_busy", NULL);
    } else if (err == ESP_ERR_INVALID_ARG) {
        send_err(seq, "bad_args", NULL);
    } else {
        send_err(seq, "sniff_failed", esp_err_to_name(err));
    }
}

static void handle_defense_stop(cJSON *root)
{
    int seq = seq_of(root);
    esp_err_t err = sniff_wifi_defense_stop();
    if (err == ESP_OK) {
        send_ack(seq, "defense_stop");
    } else {
        send_err(seq, "sniff_idle", NULL);
    }
}

static void handle_ble_defense_start(cJSON *root)
{
    int seq = seq_of(root);
    cJSON *dur_j = cJSON_GetObjectItemCaseSensitive(root, "duration_sec");
    int dur = cJSON_IsNumber(dur_j) ? dur_j->valueint : 60;
    if (dur < 0)    dur = 0;
    if (dur > 3600) dur = 3600;

    esp_err_t err = scan_ble_defense_start((uint16_t)dur);
    if (err == ESP_OK) {
        send_ack(seq, "ble_defense_start");
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "scan_busy", NULL);
    } else {
        send_err(seq, "scan_failed", esp_err_to_name(err));
    }
}

static void handle_ble_defense_stop(cJSON *root)
{
    int seq = seq_of(root);
    esp_err_t err = scan_ble_defense_stop();
    if (err == ESP_OK) {
        send_ack(seq, "ble_defense_stop");
    } else {
        send_err(seq, "scan_idle", NULL);
    }
}

static void handle_watchdog_start(cJSON *root)
{
    int seq = seq_of(root);
    cJSON *act_j   = cJSON_GetObjectItemCaseSensitive(root, "actions");
    cJSON *wl_j    = cJSON_GetObjectItemCaseSensitive(root, "whitelist");
    cJSON *cool_j  = cJSON_GetObjectItemCaseSensitive(root, "cooldown_ms");
    cJSON *max_j   = cJSON_GetObjectItemCaseSensitive(root, "max_actions");

    int actions = cJSON_IsNumber(act_j) ? act_j->valueint : WATCHDOG_ACTION_ALL;
    if (actions < 1 || actions > WATCHDOG_ACTION_ALL) {
        send_err(seq, "bad_actions", "1..3 (bitmask)");
        return;
    }

    uint8_t whitelist[16 * 6];
    size_t n_wl = 0;
    if (cJSON_IsArray(wl_j)) {
        int n = cJSON_GetArraySize(wl_j);
        if (n > 16) {
            send_err(seq, "bad_whitelist", "max 16");
            return;
        }
        for (int i = 0; i < n; i++) {
            cJSON *bi = cJSON_GetArrayItem(wl_j, i);
            if (!cJSON_IsString(bi)) {
                send_err(seq, "bad_whitelist", "must be array of MAC strings");
                return;
            }
            uint8_t mac[6];
            if (parse_mac(bi->valuestring, mac) != 0) {
                send_err(seq, "bad_whitelist", bi->valuestring);
                return;
            }
            memcpy(&whitelist[i * 6], mac, 6);
            n_wl++;
        }
    }
    int cool = cJSON_IsNumber(cool_j) ? cool_j->valueint : 10000;
    int max  = cJSON_IsNumber(max_j)  ? max_j->valueint  : 5;
    if (cool < 100)    cool = 100;
    if (cool > 600000) cool = 600000;
    if (max < 1)   max = 1;
    if (max > 100) max = 100;

    esp_err_t err = watchdog_start((uint8_t)actions,
                                    n_wl ? whitelist : NULL, n_wl,
                                    (uint32_t)cool, (uint16_t)max);
    if (err == ESP_OK) {
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "resp", "watchdog_start");
        cJSON_AddNumberToObject(resp, "seq", seq);
        cJSON_AddStringToObject(resp, "status", "started");
        cJSON_AddNumberToObject(resp, "actions", actions);
        cJSON_AddNumberToObject(resp, "whitelist_count", n_wl);
        send_json(resp);
        cJSON_Delete(resp);
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "watchdog_busy", NULL);
    } else {
        send_err(seq, "bad_args", esp_err_to_name(err));
    }
}

static void handle_watchdog_stop(cJSON *root)
{
    int seq = seq_of(root);
    esp_err_t err = watchdog_stop();
    if (err == ESP_OK) {
        send_ack(seq, "watchdog_stop");
    } else {
        send_err(seq, "watchdog_idle", NULL);
    }
}

static void handle_evil_twin_start(cJSON *root)
{
    int seq = seq_of(root);
    if (attack_lan_is_connected()) {
        send_err(seq, "wifi_busy", "disconnect first");
        return;
    }

    cJSON *ssid_j = cJSON_GetObjectItemCaseSensitive(root, "ssid");
    cJSON *psk_j  = cJSON_GetObjectItemCaseSensitive(root, "password");
    cJSON *ch_j   = cJSON_GetObjectItemCaseSensitive(root, "channel");
    cJSON *mc_j   = cJSON_GetObjectItemCaseSensitive(root, "max_conn");

    if (!cJSON_IsString(ssid_j) || !ssid_j->valuestring[0]) {
        send_err(seq, "bad_ssid", NULL);
        return;
    }
    if (!cJSON_IsNumber(ch_j) || ch_j->valueint < 1 || ch_j->valueint > 13) {
        send_err(seq, "bad_channel", NULL);
        return;
    }
    const char *psk = cJSON_IsString(psk_j) ? psk_j->valuestring : NULL;
    int mc = cJSON_IsNumber(mc_j) ? mc_j->valueint : 4;
    if (mc < 1)  mc = 1;
    if (mc > 10) mc = 10;

    esp_err_t err = evil_twin_start(ssid_j->valuestring, psk,
                                     (uint8_t)ch_j->valueint, (uint8_t)mc);
    if (err == ESP_OK) {
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "resp", "evil_twin_start");
        cJSON_AddNumberToObject(resp, "seq", seq);
        cJSON_AddStringToObject(resp, "status", "started");
        cJSON_AddStringToObject(resp, "ssid", ssid_j->valuestring);
        cJSON_AddNumberToObject(resp, "channel", ch_j->valueint);
        cJSON_AddStringToObject(resp, "auth", psk && psk[0] ? "wpa2" : "open");
        send_json(resp);
        cJSON_Delete(resp);
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "twin_busy", NULL);
    } else if (err == ESP_ERR_INVALID_ARG) {
        send_err(seq, "bad_args", esp_err_to_name(err));
    } else {
        send_err(seq, "twin_failed", esp_err_to_name(err));
    }
}

static void handle_evil_twin_stop(cJSON *root)
{
    int seq = seq_of(root);
    esp_err_t err = evil_twin_stop();
    if (err == ESP_OK) {
        send_ack(seq, "evil_twin_stop");
    } else {
        send_err(seq, "twin_idle", NULL);
    }
}

static void handle_captive_portal_start(cJSON *root)
{
    int seq = seq_of(root);
    if (!evil_twin_busy()) {
        send_err(seq, "twin_idle", "evil_twin must be running");
        return;
    }
    cJSON *html_j = cJSON_GetObjectItemCaseSensitive(root, "html");
    cJSON *ip_j   = cJSON_GetObjectItemCaseSensitive(root, "redirect_ip");

    const char *html = cJSON_IsString(html_j) ? html_j->valuestring : NULL;
    uint8_t ip[4] = {192, 168, 4, 1};
    if (cJSON_IsString(ip_j) && parse_ipv4(ip_j->valuestring, ip) != 0) {
        send_err(seq, "bad_redirect_ip", NULL);
        return;
    }

    esp_err_t err = captive_portal_start(html, ip);
    if (err == ESP_OK) {
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "resp", "captive_portal_start");
        cJSON_AddNumberToObject(resp, "seq", seq);
        cJSON_AddStringToObject(resp, "status", "started");
        char ipbuf[16];
        snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u", ip[0],ip[1],ip[2],ip[3]);
        cJSON_AddStringToObject(resp, "redirect_ip", ipbuf);
        send_json(resp);
        cJSON_Delete(resp);
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "portal_busy", NULL);
    } else {
        send_err(seq, "portal_failed", esp_err_to_name(err));
    }
}

static void handle_captive_portal_stop(cJSON *root)
{
    int seq = seq_of(root);
    esp_err_t err = captive_portal_stop();
    if (err == ESP_OK) {
        send_ack(seq, "captive_portal_stop");
    } else {
        send_err(seq, "portal_idle", NULL);
    }
}

static void handle_arp_throttle(cJSON *root)
{
    int seq = seq_of(root);
    if (!attack_lan_is_connected()) {
        send_err(seq, "wifi_not_connected", NULL);
        return;
    }

    cJSON *t_ip_j   = cJSON_GetObjectItemCaseSensitive(root, "target_ip");
    cJSON *t_mac_j  = cJSON_GetObjectItemCaseSensitive(root, "target_mac");
    cJSON *gw_ip_j  = cJSON_GetObjectItemCaseSensitive(root, "gateway_ip");
    cJSON *gw_mac_j = cJSON_GetObjectItemCaseSensitive(root, "gateway_mac");
    cJSON *on_j     = cJSON_GetObjectItemCaseSensitive(root, "on_ms");
    cJSON *off_j    = cJSON_GetObjectItemCaseSensitive(root, "off_ms");
    cJSON *dur_j    = cJSON_GetObjectItemCaseSensitive(root, "duration_sec");

    uint8_t t_ip[4], t_mac[6], gw_ip[4], gw_mac[6];
    if (!cJSON_IsString(t_ip_j)   || parse_ipv4(t_ip_j->valuestring, t_ip)   != 0)
        { send_err(seq, "bad_target_ip", NULL); return; }
    if (!cJSON_IsString(t_mac_j)  || parse_mac(t_mac_j->valuestring, t_mac)  != 0)
        { send_err(seq, "bad_target_mac", NULL); return; }
    if (!cJSON_IsString(gw_ip_j)  || parse_ipv4(gw_ip_j->valuestring, gw_ip) != 0)
        { send_err(seq, "bad_gateway_ip", NULL); return; }
    if (!cJSON_IsString(gw_mac_j) || parse_mac(gw_mac_j->valuestring, gw_mac)!= 0)
        { send_err(seq, "bad_gateway_mac", NULL); return; }

    uint16_t on  = cJSON_IsNumber(on_j)  ? (uint16_t)on_j->valueint  : 5000;
    uint16_t off = cJSON_IsNumber(off_j) ? (uint16_t)off_j->valueint : 5000;
    uint16_t dur = cJSON_IsNumber(dur_j) ? (uint16_t)dur_j->valueint : 60;

    esp_err_t err = attack_lan_arp_throttle_start(t_ip, t_mac, gw_ip, gw_mac,
                                                   on, off, dur);
    if (err == ESP_OK) {
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "resp", "arp_throttle");
        cJSON_AddNumberToObject(resp, "seq", seq);
        cJSON_AddStringToObject(resp, "status", "started");
        cJSON_AddNumberToObject(resp, "on_ms", on);
        cJSON_AddNumberToObject(resp, "off_ms", off);
        cJSON_AddNumberToObject(resp, "duration_sec", dur);
        send_json(resp);
        cJSON_Delete(resp);
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "cut_busy_or_offline", NULL);
    } else {
        send_err(seq, "cut_failed", esp_err_to_name(err));
    }
}

static void handle_arp_throttle_stop(cJSON *root)
{
    int seq = seq_of(root);
    esp_err_t err = attack_lan_arp_throttle_stop();
    if (err == ESP_OK) {
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "resp", "arp_throttle_stop");
        cJSON_AddNumberToObject(resp, "seq", seq);
        cJSON_AddStringToObject(resp, "status", "stopping");
        send_json(resp);
        cJSON_Delete(resp);
    } else {
        send_err(seq, "cut_idle", NULL);
    }
}

static void handle_lan_scan(cJSON *root)
{
    int seq = seq_of(root);
    if (!attack_lan_is_connected()) {
        send_err(seq, "wifi_not_connected", NULL);
        return;
    }
    cJSON *to_j = cJSON_GetObjectItemCaseSensitive(root, "timeout_ms");
    int to_raw = cJSON_IsNumber(to_j) ? to_j->valueint : 3000;
    if (to_raw < 500)   to_raw = 500;
    if (to_raw > 30000) to_raw = 30000;

    esp_err_t err = attack_lan_lan_scan_start((uint16_t)to_raw);
    if (err == ESP_OK) {
        send_ack(seq, "lan_scan");
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "scan_busy", NULL);
    } else {
        send_err(seq, "scan_failed", esp_err_to_name(err));
    }
}

static void handle_deauth(cJSON *root)
{
    int seq = seq_of(root);

    cJSON *bssid_j  = cJSON_GetObjectItemCaseSensitive(root, "bssid");
    cJSON *target_j = cJSON_GetObjectItemCaseSensitive(root, "target");
    cJSON *ch_j     = cJSON_GetObjectItemCaseSensitive(root, "channel");
    cJSON *count_j  = cJSON_GetObjectItemCaseSensitive(root, "count");
    cJSON *reason_j = cJSON_GetObjectItemCaseSensitive(root, "reason");

    uint8_t bssid[6];
    if (!cJSON_IsString(bssid_j) || parse_mac(bssid_j->valuestring, bssid) != 0) {
        send_err(seq, "bad_bssid", NULL);
        return;
    }

    uint8_t target[6];
    if (cJSON_IsString(target_j)) {
        if (parse_mac(target_j->valuestring, target) != 0) {
            send_err(seq, "bad_target", NULL);
            return;
        }
    } else {
        memset(target, 0xFF, 6); // broadcast
    }

    if (!cJSON_IsNumber(ch_j) || ch_j->valueint < 1 || ch_j->valueint > 14) {
        send_err(seq, "bad_channel", NULL);
        return;
    }
    uint8_t channel = (uint8_t)ch_j->valueint;
    uint16_t count  = cJSON_IsNumber(count_j)  ? (uint16_t)count_j->valueint  : 10;
    uint16_t reason = cJSON_IsNumber(reason_j) ? (uint16_t)reason_j->valueint : 7;

    esp_err_t err = hacking_wifi_deauth(target, bssid, channel, count, reason);
    if (err == ESP_OK) {
        send_ack(seq, "deauth");
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "hack_busy", NULL);
    } else {
        send_err(seq, "deauth_failed", esp_err_to_name(err));
    }
}

static void handle_channel_jam(cJSON *root)
{
    int seq = seq_of(root);
    cJSON *ch_j  = cJSON_GetObjectItemCaseSensitive(root, "channel");
    cJSON *dur_j = cJSON_GetObjectItemCaseSensitive(root, "duration_sec");

    if (!cJSON_IsNumber(ch_j) || ch_j->valueint < 1 || ch_j->valueint > 14) {
        send_err(seq, "bad_channel", NULL);
        return;
    }
    int dur = cJSON_IsNumber(dur_j) ? dur_j->valueint : 10;
    if (dur < 1)   dur = 1;
    if (dur > 120) dur = 120;

    esp_err_t err = hacking_wifi_channel_jam((uint8_t)ch_j->valueint,
                                              (uint16_t)dur);
    if (err == ESP_OK) {
        send_ack(seq, "channel_jam");
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "hack_busy", NULL);
    } else {
        send_err(seq, "jam_failed", esp_err_to_name(err));
    }
}

static void handle_channel_jam_stop(cJSON *root)
{
    int seq = seq_of(root);
    esp_err_t err = hacking_wifi_channel_jam_stop();
    if (err == ESP_OK) {
        send_ack(seq, "channel_jam_stop");
    } else {
        send_err(seq, "hack_idle", NULL);
    }
}

static void handle_wps_pin_test(cJSON *root)
{
    int seq = seq_of(root);
    if (attack_lan_is_connected()) {
        send_err(seq, "wifi_busy", "disconnect first");
        return;
    }

    cJSON *bssid_j = cJSON_GetObjectItemCaseSensitive(root, "bssid");
    cJSON *pin_j   = cJSON_GetObjectItemCaseSensitive(root, "pin");
    cJSON *to_j    = cJSON_GetObjectItemCaseSensitive(root, "timeout_sec");

    uint8_t bssid[6];
    if (!cJSON_IsString(bssid_j) || parse_mac(bssid_j->valuestring, bssid) != 0) {
        send_err(seq, "bad_bssid", NULL);
        return;
    }
    if (!cJSON_IsString(pin_j) || strlen(pin_j->valuestring) != 8) {
        send_err(seq, "bad_pin", "8 dígitos");
        return;
    }
    // Validar que são todos dígitos
    for (int i = 0; i < 8; i++) {
        char ch = pin_j->valuestring[i];
        if (ch < '0' || ch > '9') {
            send_err(seq, "bad_pin", "só dígitos");
            return;
        }
    }
    int to = cJSON_IsNumber(to_j) ? to_j->valueint : 60;
    if (to < 15)  to = 15;
    if (to > 120) to = 120;

    esp_err_t err = hacking_wifi_wps_pin_test(bssid, pin_j->valuestring,
                                              (uint16_t)to);
    if (err == ESP_OK) {
        send_ack(seq, "wps_pin_test");
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "hack_busy", NULL);
    } else {
        send_err(seq, "wps_failed", esp_err_to_name(err));
    }
}

// Helper genérico pra todos os ble_spam_* (apple, samsung, google, multi).
static void dispatch_ble_spam(cJSON *root, const char *cmd_name,
                               esp_err_t (*fn)(uint16_t))
{
    int seq = seq_of(root);
    cJSON *cyc_j = cJSON_GetObjectItemCaseSensitive(root, "cycles");
    uint16_t cycles = cJSON_IsNumber(cyc_j) ? (uint16_t)cyc_j->valueint : 50;

    esp_err_t err = fn(cycles);
    if (err == ESP_OK) {
        send_ack(seq, cmd_name);
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "spam_busy", NULL);
    } else {
        send_err(seq, "spam_failed", esp_err_to_name(err));
    }
}

static void handle_ble_spam_apple(cJSON *root)
{
    dispatch_ble_spam(root, "ble_spam_apple", hacking_ble_apple_spam);
}

static void handle_ble_spam_samsung(cJSON *root)
{
    dispatch_ble_spam(root, "ble_spam_samsung", hacking_ble_samsung_spam);
}

static void handle_ble_spam_google(cJSON *root)
{
    dispatch_ble_spam(root, "ble_spam_google", hacking_ble_google_spam);
}

static void handle_ble_spam_multi(cJSON *root)
{
    dispatch_ble_spam(root, "ble_spam_multi", hacking_ble_multi_spam);
}

static void handle_ble_adv_flood(cJSON *root)
{
    int seq = seq_of(root);
    cJSON *dur_j = cJSON_GetObjectItemCaseSensitive(root, "duration_sec");
    int dur = cJSON_IsNumber(dur_j) ? dur_j->valueint : 10;
    if (dur < 1)  dur = 1;
    if (dur > 60) dur = 60;

    esp_err_t err = hacking_ble_adv_flood((uint16_t)dur);
    if (err == ESP_OK) {
        send_ack(seq, "ble_adv_flood");
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "spam_busy", NULL);
    } else {
        send_err(seq, "spam_failed", esp_err_to_name(err));
    }
}

static void handle_beacon_flood(cJSON *root)
{
    int seq = seq_of(root);

    cJSON *ch_j     = cJSON_GetObjectItemCaseSensitive(root, "channel");
    cJSON *cyc_j    = cJSON_GetObjectItemCaseSensitive(root, "cycles");
    cJSON *ssids_j  = cJSON_GetObjectItemCaseSensitive(root, "ssids");

    if (!cJSON_IsNumber(ch_j) || ch_j->valueint < 1 || ch_j->valueint > 14) {
        send_err(seq, "bad_channel", NULL);
        return;
    }
    if (!cJSON_IsArray(ssids_j)) {
        send_err(seq, "bad_ssids", NULL);
        return;
    }
    int n = cJSON_GetArraySize(ssids_j);
    if (n == 0 || n > 32) {
        send_err(seq, "bad_ssids", "1..32 entries");
        return;
    }

    const char *ssids[32];
    for (int i = 0; i < n; i++) {
        cJSON *s = cJSON_GetArrayItem(ssids_j, i);
        if (!cJSON_IsString(s) || !s->valuestring || s->valuestring[0] == 0) {
            send_err(seq, "bad_ssid_entry", NULL);
            return;
        }
        ssids[i] = s->valuestring;
    }

    uint8_t channel = (uint8_t)ch_j->valueint;
    uint16_t cycles = cJSON_IsNumber(cyc_j) ? (uint16_t)cyc_j->valueint : 50;

    esp_err_t err = hacking_wifi_beacon_flood(channel, cycles,
                                              ssids, (size_t)n);
    if (err == ESP_OK) {
        send_ack(seq, "beacon_flood");
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "hack_busy", NULL);
    } else {
        send_err(seq, "beacon_failed", esp_err_to_name(err));
    }
}

static void handle_ble_scan_stop(cJSON *root)
{
    int seq = seq_of(root);
    esp_err_t err = scan_ble_stop();
    if (err == ESP_OK) {
        send_ack(seq, "ble_scan_stop");
    } else {
        send_err(seq, "scan_idle", NULL);
    }
}

static void handle_status(cJSON *root)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "resp", "status");
    cJSON_AddNumberToObject(resp, "seq", seq_of(root));
    cJSON_AddNumberToObject(resp, "uptime_ms",
                            (double)(esp_timer_get_time() / 1000));
    cJSON_AddNumberToObject(resp, "free_sram",
                            heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(resp, "free_psram",
                            heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    cJSON_AddNumberToObject(resp, "min_free_sram",
                            heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
    send_json(resp);
    cJSON_Delete(resp);
}

void command_router_handle_json(const uint8_t *data, size_t len)
{
    cJSON *root = cJSON_ParseWithLength((const char *)data, len);
    if (!root) {
        ESP_LOGW(TAG, "json parse failed");
        send_err(0, "bad_json", NULL);
        return;
    }

    cJSON *cmd = cJSON_GetObjectItemCaseSensitive(root, "cmd");
    if (!cJSON_IsString(cmd) || !cmd->valuestring) {
        send_err(seq_of(root), "missing_cmd", NULL);
        cJSON_Delete(root);
        return;
    }

    const char *c = cmd->valuestring;
    if (strcmp(c, "ping") == 0) {
        handle_ping(root);
    } else if (strcmp(c, "hello") == 0) {
        handle_hello(root);
    } else if (strcmp(c, "status") == 0) {
        handle_status(root);
    } else if (strcmp(c, "wifi_scan") == 0) {
        handle_wifi_scan(root);
    } else if (strcmp(c, "ble_scan") == 0) {
        handle_ble_scan(root);
    } else if (strcmp(c, "ble_scan_stop") == 0) {
        handle_ble_scan_stop(root);
    } else if (strcmp(c, "deauth") == 0) {
        handle_deauth(root);
    } else if (strcmp(c, "beacon_flood") == 0) {
        handle_beacon_flood(root);
    } else if (strcmp(c, "channel_jam") == 0) {
        handle_channel_jam(root);
    } else if (strcmp(c, "channel_jam_stop") == 0) {
        handle_channel_jam_stop(root);
    } else if (strcmp(c, "wps_pin_test") == 0) {
        handle_wps_pin_test(root);
    } else if (strcmp(c, "ble_spam_apple") == 0) {
        handle_ble_spam_apple(root);
    } else if (strcmp(c, "ble_spam_samsung") == 0) {
        handle_ble_spam_samsung(root);
    } else if (strcmp(c, "ble_spam_google") == 0) {
        handle_ble_spam_google(root);
    } else if (strcmp(c, "ble_spam_multi") == 0) {
        handle_ble_spam_multi(root);
    } else if (strcmp(c, "ble_adv_flood") == 0) {
        handle_ble_adv_flood(root);
    } else if (strcmp(c, "wifi_connect") == 0) {
        handle_wifi_connect(root);
    } else if (strcmp(c, "wifi_disconnect") == 0) {
        handle_wifi_disconnect(root);
    } else if (strcmp(c, "arp_cut") == 0) {
        handle_arp_cut(root);
    } else if (strcmp(c, "arp_cut_stop") == 0) {
        handle_arp_cut_stop(root);
    } else if (strcmp(c, "arp_throttle") == 0) {
        handle_arp_throttle(root);
    } else if (strcmp(c, "arp_throttle_stop") == 0) {
        handle_arp_throttle_stop(root);
    } else if (strcmp(c, "lan_scan") == 0) {
        handle_lan_scan(root);
    } else if (strcmp(c, "probe_sniff") == 0) {
        handle_probe_sniff(root);
    } else if (strcmp(c, "probe_sniff_stop") == 0) {
        handle_probe_sniff_stop(root);
    } else if (strcmp(c, "wpa_capture") == 0) {
        handle_wpa_capture(root);
    } else if (strcmp(c, "wpa_capture_stop") == 0) {
        handle_wpa_capture_stop(root);
    } else if (strcmp(c, "pmkid_capture") == 0) {
        handle_pmkid_capture(root);
    } else if (strcmp(c, "pmkid_capture_stop") == 0) {
        handle_pmkid_capture_stop(root);
    } else if (strcmp(c, "pcap_start") == 0) {
        handle_pcap_start(root);
    } else if (strcmp(c, "pcap_stop") == 0) {
        handle_pcap_stop(root);
    } else if (strcmp(c, "karma_start") == 0) {
        handle_karma_start(root);
    } else if (strcmp(c, "karma_stop") == 0) {
        handle_karma_stop(root);
    } else if (strcmp(c, "defense_start") == 0) {
        handle_defense_start(root);
    } else if (strcmp(c, "defense_stop") == 0) {
        handle_defense_stop(root);
    } else if (strcmp(c, "ble_defense_start") == 0) {
        handle_ble_defense_start(root);
    } else if (strcmp(c, "ble_defense_stop") == 0) {
        handle_ble_defense_stop(root);
    } else if (strcmp(c, "watchdog_start") == 0) {
        handle_watchdog_start(root);
    } else if (strcmp(c, "watchdog_stop") == 0) {
        handle_watchdog_stop(root);
    } else if (strcmp(c, "evil_twin_start") == 0) {
        handle_evil_twin_start(root);
    } else if (strcmp(c, "evil_twin_stop") == 0) {
        handle_evil_twin_stop(root);
    } else if (strcmp(c, "captive_portal_start") == 0) {
        handle_captive_portal_start(root);
    } else if (strcmp(c, "captive_portal_stop") == 0) {
        handle_captive_portal_stop(root);
    } else {
        send_err(seq_of(root), "unknown_cmd", c);
    }

    cJSON_Delete(root);
}

esp_err_t command_router_init(void)
{
    ESP_LOGI(TAG, "ready (cmds: ping, hello, status, wifi_scan, ble_scan, ble_scan_stop,"
                  " deauth, beacon_flood, channel_jam[_stop],"
                  " ble_spam_{apple,samsung,google,multi}, wifi_connect, wifi_disconnect,"
                  " arp_cut[_stop], arp_throttle[_stop], lan_scan, probe_sniff[_stop],"
                  " wpa_capture[_stop], pmkid_capture[_stop])");
    return ESP_OK;
}
