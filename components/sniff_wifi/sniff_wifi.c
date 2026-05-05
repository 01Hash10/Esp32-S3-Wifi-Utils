#include "sniff_wifi.h"
#include "tlv.h"
#include "transport_ble.h"

#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "sniff-wifi";

#define MAX_DEDUP_ENTRIES   256
#define MAX_SSID_LEN        32

typedef struct {
    uint8_t mac[6];
    uint8_t ssid_len;
    char    ssid[MAX_SSID_LEN];
} dedup_entry_t;

typedef struct {
    uint8_t  ch_min;
    uint8_t  ch_max;
    uint16_t dwell_ms;
    uint16_t duration_sec;
} sniff_ctx_t;

static volatile bool s_busy = false;
static volatile bool s_stop = false;
static TaskHandle_t s_task = NULL;
static uint8_t s_seq = 0;

// Estado compartilhado entre o promisc CB (wifi task) e o controller task
static dedup_entry_t *s_dedup = NULL;
static volatile size_t s_dedup_count = 0;
static volatile uint32_t s_total_frames = 0;
static volatile uint8_t s_current_channel = 0;

bool sniff_wifi_busy(void)
{
    return s_busy;
}

esp_err_t sniff_wifi_init(void)
{
    ESP_LOGI(TAG, "ready");
    return ESP_OK;
}

static bool dedup_check_and_add(const uint8_t mac[6],
                                 const uint8_t *ssid, uint8_t ssid_len)
{
    // Linear scan; dedup[] vive por toda a sessão de sniff.
    for (size_t i = 0; i < s_dedup_count; i++) {
        if (memcmp(s_dedup[i].mac, mac, 6) == 0 &&
            s_dedup[i].ssid_len == ssid_len &&
            memcmp(s_dedup[i].ssid, ssid, ssid_len) == 0) {
            return false; // já visto
        }
    }
    if (s_dedup_count >= MAX_DEDUP_ENTRIES) return false; // estourou
    memcpy(s_dedup[s_dedup_count].mac, mac, 6);
    s_dedup[s_dedup_count].ssid_len = ssid_len;
    if (ssid_len) memcpy(s_dedup[s_dedup_count].ssid, ssid, ssid_len);
    s_dedup_count++;
    return true;
}

static void emit_probe(const uint8_t mac[6], int8_t rssi, uint8_t channel,
                       const uint8_t *ssid, uint8_t ssid_len)
{
    uint8_t payload[9 + MAX_SSID_LEN];
    memcpy(&payload[0], mac, 6);
    payload[6] = (uint8_t)rssi;
    payload[7] = channel;
    payload[8] = ssid_len;
    if (ssid_len) memcpy(&payload[9], ssid, ssid_len);

    uint8_t frame[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(frame, sizeof(frame),
                           TLV_MSG_PROBE_REQ, s_seq++,
                           payload, 9 + ssid_len);
    if (total > 0) transport_ble_send_stream(frame, (size_t)total);
}

static void emit_done(uint16_t unique, uint16_t total_frames,
                       uint32_t scan_ms, uint8_t status)
{
    uint8_t payload[9];
    payload[0] = (uint8_t)(unique >> 8);
    payload[1] = (uint8_t)(unique & 0xFF);
    payload[2] = (uint8_t)(total_frames >> 8);
    payload[3] = (uint8_t)(total_frames & 0xFF);
    payload[4] = (uint8_t)(scan_ms >> 24);
    payload[5] = (uint8_t)(scan_ms >> 16);
    payload[6] = (uint8_t)(scan_ms >> 8);
    payload[7] = (uint8_t)(scan_ms & 0xFF);
    payload[8] = status;

    uint8_t frame[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(frame, sizeof(frame),
                           TLV_MSG_PROBE_DONE, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(frame, (size_t)total);
}

static void promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *payload = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 24 + 4) return; // header 802.11 + FCS

    // Frame Control byte 0: type=Mgmt(00) subtype=ProbeReq(0100) → 0x40
    if (payload[0] != 0x40) return;

    s_total_frames++;

    const uint8_t *src = &payload[10]; // addr2 = source

    // SSID IE em offset 24 (logo após o header). Tag 0, len, data.
    const uint8_t *ies = &payload[24];
    uint16_t ies_len = len - 24 - 4; // descontando FCS de 4 bytes
    if (ies_len < 2) return;
    if (ies[0] != 0x00) return;
    uint8_t ssid_len = ies[1];
    if (ssid_len > MAX_SSID_LEN) ssid_len = MAX_SSID_LEN;
    if (2 + ssid_len > ies_len) return;
    const uint8_t *ssid = &ies[2];

    // Probe broadcast (ssid_len=0) também é interessante — emite mas dedup
    // só por MAC (com ssid vazio).
    if (!dedup_check_and_add(src, ssid, ssid_len)) return;

    int8_t rssi = pkt->rx_ctrl.rssi;
    uint8_t channel = s_current_channel;

    emit_probe(src, rssi, channel, ssid, ssid_len);
}

static void sniff_task(void *arg)
{
    sniff_ctx_t *ctx = (sniff_ctx_t *)arg;
    int64_t start_us = esp_timer_get_time();
    int64_t deadline_us = start_us + (int64_t)ctx->duration_sec * 1000000LL;

    s_dedup = calloc(MAX_DEDUP_ENTRIES, sizeof(dedup_entry_t));
    if (!s_dedup) {
        ESP_LOGE(TAG, "dedup alloc failed");
        emit_done(0, 0, 0, 2);
        goto cleanup;
    }
    s_dedup_count = 0;
    s_total_frames = 0;

    // Filtro: só mgmt frames pra reduzir overhead
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT,
    };
    esp_wifi_set_promiscuous_filter(&filter);

    esp_err_t err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_promiscuous rc=%s", esp_err_to_name(err));
        emit_done(0, 0, 0, 2);
        goto cleanup_dedup;
    }
    esp_wifi_set_promiscuous_rx_cb(&promisc_cb);

    uint8_t ch = ctx->ch_min;
    while (!s_stop && esp_timer_get_time() < deadline_us) {
        s_current_channel = ch;
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(ctx->dwell_ms));
        ch = (ch >= ctx->ch_max) ? ctx->ch_min : (ch + 1);
    }

    esp_wifi_set_promiscuous(false);

    uint8_t status = (s_dedup_count >= MAX_DEDUP_ENTRIES) ? 1 : 0;
    uint32_t elapsed = (uint32_t)((esp_timer_get_time() - start_us) / 1000);
    emit_done((uint16_t)s_dedup_count, (uint16_t)s_total_frames,
              elapsed, status);
    ESP_LOGI(TAG, "probe_sniff done: %u unique / %u frames in %u ms (status=%u)",
             (unsigned)s_dedup_count, (unsigned)s_total_frames,
             (unsigned)elapsed, (unsigned)status);

cleanup_dedup:
    free(s_dedup);
    s_dedup = NULL;
cleanup:
    free(ctx);
    s_stop = false;
    s_task = NULL;
    s_busy = false;
    vTaskDelete(NULL);
}

esp_err_t sniff_wifi_probe_start(uint8_t ch_min, uint8_t ch_max,
                                 uint16_t dwell_ms, uint16_t duration_sec)
{
    if (s_busy) return ESP_ERR_INVALID_STATE;
    if (ch_min == 0 || ch_min > 13) return ESP_ERR_INVALID_ARG;
    if (ch_max == 0 || ch_max > 13) return ESP_ERR_INVALID_ARG;
    if (ch_max < ch_min) return ESP_ERR_INVALID_ARG;
    if (dwell_ms < 100)   dwell_ms = 100;
    if (dwell_ms > 5000)  dwell_ms = 5000;
    if (duration_sec == 0) duration_sec = 30;
    if (duration_sec > 300) duration_sec = 300;

    sniff_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return ESP_ERR_NO_MEM;
    ctx->ch_min = ch_min;
    ctx->ch_max = ch_max;
    ctx->dwell_ms = dwell_ms;
    ctx->duration_sec = duration_sec;

    s_busy = true;
    s_stop = false;
    if (xTaskCreate(sniff_task, "probe_sniff", 4096, ctx, 5, &s_task) != pdPASS) {
        free(ctx);
        s_busy = false;
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "probe_sniff started: ch=%u..%u dwell=%ums duration=%us",
             ch_min, ch_max, (unsigned)dwell_ms, (unsigned)duration_sec);
    return ESP_OK;
}

esp_err_t sniff_wifi_probe_stop(void)
{
    if (!s_busy) return ESP_ERR_INVALID_STATE;
    s_stop = true;
    return ESP_OK;
}
