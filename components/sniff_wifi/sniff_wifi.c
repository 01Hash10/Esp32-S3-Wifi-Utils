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

// EAPOL TLV: header(16) + frame bytes (até MTU-4-16 = 227 bytes).
// Frames EAPOL típicos: 121–189 bytes. Pode truncar M3 (~189–250B com KEK).
#define EAPOL_FRAME_MAX     227
#define EAPOL_TLV_HDR       16

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
} probe_ctx_t;

typedef struct {
    uint8_t  bssid[6];
    uint8_t  channel;
    uint16_t duration_sec;
} eapol_ctx_t;

static volatile sniff_mode_t s_mode = SNIFF_MODE_IDLE;
static volatile bool s_stop = false;
static TaskHandle_t s_task = NULL;
static uint8_t s_seq = 0;

// Estado promisc (probe)
static dedup_entry_t *s_dedup = NULL;
static volatile size_t s_dedup_count = 0;
static volatile uint32_t s_total_frames = 0;
static volatile uint8_t s_current_channel = 0;

// Estado promisc (eapol)
static volatile uint8_t s_eapol_target_bssid[6];
static volatile uint8_t s_eapol_count = 0;
static volatile uint8_t s_eapol_msg_mask = 0;

bool sniff_wifi_busy(void)
{
    return s_mode != SNIFF_MODE_IDLE;
}

sniff_mode_t sniff_wifi_mode(void)
{
    return s_mode;
}

esp_err_t sniff_wifi_init(void)
{
    ESP_LOGI(TAG, "ready");
    return ESP_OK;
}

// ----------------------------------------------------------------------
// Probe sniff
// ----------------------------------------------------------------------

static bool dedup_check_and_add(const uint8_t mac[6],
                                 const uint8_t *ssid, uint8_t ssid_len)
{
    for (size_t i = 0; i < s_dedup_count; i++) {
        if (memcmp(s_dedup[i].mac, mac, 6) == 0 &&
            s_dedup[i].ssid_len == ssid_len &&
            memcmp(s_dedup[i].ssid, ssid, ssid_len) == 0) {
            return false;
        }
    }
    if (s_dedup_count >= MAX_DEDUP_ENTRIES) return false;
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

static void emit_probe_done(uint16_t unique, uint16_t total_frames,
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

static void promisc_cb_probe(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *payload = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 24 + 4) return;
    if (payload[0] != 0x40) return; // probe request

    s_total_frames++;

    const uint8_t *src = &payload[10];
    const uint8_t *ies = &payload[24];
    uint16_t ies_len = len - 24 - 4;
    if (ies_len < 2) return;
    if (ies[0] != 0x00) return;
    uint8_t ssid_len = ies[1];
    if (ssid_len > MAX_SSID_LEN) ssid_len = MAX_SSID_LEN;
    if (2 + ssid_len > ies_len) return;
    const uint8_t *ssid = &ies[2];

    if (!dedup_check_and_add(src, ssid, ssid_len)) return;

    int8_t rssi = pkt->rx_ctrl.rssi;
    emit_probe(src, rssi, s_current_channel, ssid, ssid_len);
}

static void probe_task(void *arg)
{
    probe_ctx_t *ctx = (probe_ctx_t *)arg;
    int64_t start_us = esp_timer_get_time();
    int64_t deadline_us = start_us + (int64_t)ctx->duration_sec * 1000000LL;

    s_dedup = calloc(MAX_DEDUP_ENTRIES, sizeof(dedup_entry_t));
    if (!s_dedup) {
        ESP_LOGE(TAG, "dedup alloc failed");
        emit_probe_done(0, 0, 0, 2);
        goto cleanup;
    }
    s_dedup_count = 0;
    s_total_frames = 0;

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT,
    };
    esp_wifi_set_promiscuous_filter(&filter);

    esp_err_t err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_promiscuous rc=%s", esp_err_to_name(err));
        emit_probe_done(0, 0, 0, 2);
        goto cleanup_dedup;
    }
    esp_wifi_set_promiscuous_rx_cb(&promisc_cb_probe);

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
    emit_probe_done((uint16_t)s_dedup_count, (uint16_t)s_total_frames,
                    elapsed, status);
    ESP_LOGI(TAG, "probe_sniff done: %u unique / %u frames in %u ms",
             (unsigned)s_dedup_count, (unsigned)s_total_frames,
             (unsigned)elapsed);

cleanup_dedup:
    free(s_dedup);
    s_dedup = NULL;
cleanup:
    free(ctx);
    s_stop = false;
    s_task = NULL;
    s_mode = SNIFF_MODE_IDLE;
    vTaskDelete(NULL);
}

esp_err_t sniff_wifi_probe_start(uint8_t ch_min, uint8_t ch_max,
                                 uint16_t dwell_ms, uint16_t duration_sec)
{
    if (s_mode != SNIFF_MODE_IDLE) return ESP_ERR_INVALID_STATE;
    if (ch_min == 0 || ch_min > 13) return ESP_ERR_INVALID_ARG;
    if (ch_max == 0 || ch_max > 13) return ESP_ERR_INVALID_ARG;
    if (ch_max < ch_min) return ESP_ERR_INVALID_ARG;
    if (dwell_ms < 100)   dwell_ms = 100;
    if (dwell_ms > 5000)  dwell_ms = 5000;
    if (duration_sec == 0) duration_sec = 30;
    if (duration_sec > 300) duration_sec = 300;

    probe_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return ESP_ERR_NO_MEM;
    ctx->ch_min = ch_min;
    ctx->ch_max = ch_max;
    ctx->dwell_ms = dwell_ms;
    ctx->duration_sec = duration_sec;

    s_mode = SNIFF_MODE_PROBE;
    s_stop = false;
    if (xTaskCreate(probe_task, "probe_sniff", 4096, ctx, 5, &s_task) != pdPASS) {
        free(ctx);
        s_mode = SNIFF_MODE_IDLE;
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "probe_sniff started: ch=%u..%u dwell=%ums duration=%us",
             ch_min, ch_max, (unsigned)dwell_ms, (unsigned)duration_sec);
    return ESP_OK;
}

esp_err_t sniff_wifi_probe_stop(void)
{
    if (s_mode != SNIFF_MODE_PROBE) return ESP_ERR_INVALID_STATE;
    s_stop = true;
    return ESP_OK;
}

// ----------------------------------------------------------------------
// EAPOL capture (WPA 4-way handshake)
// ----------------------------------------------------------------------

// Tenta classificar a mensagem (1..4) pelo Key Information do EAPOL-Key.
// `key_info` é o campo de 16 bits em network byte order (já swap).
//   bit 8  (0x0100) = MIC
//   bit 7  (0x0080) = ACK
//   bit 6  (0x0040) = Install
//   bit 9  (0x0200) = Secure
//
// Detecção:
//   M1: ACK && !MIC
//   M2: !ACK && MIC && !Secure && !Install
//   M3: ACK && MIC && Install
//   M4: !ACK && MIC && Secure && !Install
static uint8_t classify_eapol_msg(uint16_t key_info)
{
    bool ack     = (key_info & 0x0080) != 0;
    bool mic     = (key_info & 0x0100) != 0;
    bool install = (key_info & 0x0040) != 0;
    bool secure  = (key_info & 0x0200) != 0;

    if (ack && !mic) return 1;
    if (!ack && mic && !secure && !install) return 2;
    if (ack && mic && install) return 3;
    if (!ack && mic && secure && !install) return 4;
    return 0;
}

static void emit_eapol(const uint8_t bssid[6], const uint8_t sta[6],
                       uint8_t msg_index, uint8_t flags,
                       uint16_t orig_frame_len,
                       const uint8_t *frame, size_t emit_len)
{
    uint8_t payload[EAPOL_TLV_HDR + EAPOL_FRAME_MAX];
    memcpy(&payload[0], bssid, 6);
    memcpy(&payload[6], sta,   6);
    payload[12] = msg_index;
    payload[13] = flags;
    payload[14] = (uint8_t)(orig_frame_len >> 8);
    payload[15] = (uint8_t)(orig_frame_len & 0xFF);
    if (emit_len > EAPOL_FRAME_MAX) emit_len = EAPOL_FRAME_MAX;
    memcpy(&payload[EAPOL_TLV_HDR], frame, emit_len);

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_WPA_EAPOL, s_seq++,
                           payload, EAPOL_TLV_HDR + emit_len);
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

static void emit_capture_done(const uint8_t bssid[6], uint8_t frames_count,
                               uint8_t msg_mask, uint32_t elapsed_ms,
                               uint8_t status)
{
    uint8_t payload[13];
    memcpy(&payload[0], bssid, 6);
    payload[6] = frames_count;
    payload[7] = msg_mask;
    payload[8]  = (uint8_t)(elapsed_ms >> 24);
    payload[9]  = (uint8_t)(elapsed_ms >> 16);
    payload[10] = (uint8_t)(elapsed_ms >> 8);
    payload[11] = (uint8_t)(elapsed_ms & 0xFF);
    payload[12] = status;

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_WPA_CAPTURE_DONE, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

static void promisc_cb_eapol(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_DATA) return;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *p = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 24 + 8 + 4) return;

    // Type bits no FC byte 0: bits 2..3. Data type = 0b10 → mask 0x0C == 0x08.
    if ((p[0] & 0x0C) != 0x08) return;

    // Protected frame? skip — EAPOL é sempre cleartext.
    if (p[1] & 0x40) return;

    // Header size: 24 bytes basic, +2 se QoS data (subtype bit 7 do byte 0).
    bool qos = (p[0] & 0x80) != 0;
    uint16_t hdr_len = qos ? 26 : 24;
    if (len < hdr_len + 8 + 4) return;

    // FC byte 1 bits: ToDS=0x01, FromDS=0x02
    uint8_t ds = p[1] & 0x03;
    const uint8_t *bssid;
    const uint8_t *sta;
    uint8_t direction; // 0=to_AP, 1=from_AP
    switch (ds) {
    case 0x01: // ToDS=1 FromDS=0 → addr1=BSSID, addr2=SA(STA), addr3=DA
        bssid = &p[4]; sta = &p[10]; direction = 0;
        break;
    case 0x02: // ToDS=0 FromDS=1 → addr1=DA(STA), addr2=BSSID, addr3=SA
        bssid = &p[10]; sta = &p[4]; direction = 1;
        break;
    default:
        return; // ad-hoc / WDS — ignora
    }

    // Filtra pelo BSSID alvo
    if (memcmp(bssid, (const void *)s_eapol_target_bssid, 6) != 0) return;

    // LLC/SNAP + EtherType: AA AA 03 00 00 00 88 8E
    const uint8_t *llc = &p[hdr_len];
    if (!(llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
          llc[3] == 0x00 && llc[4] == 0x00 && llc[5] == 0x00 &&
          llc[6] == 0x88 && llc[7] == 0x8E)) return;

    // EAPOL packet starts at hdr_len+8.
    // EAPOL header: version(1) + type(1) + length_be(2) = 4 bytes.
    // Type 0x03 = EAPOL-Key. Depois vem Key Information (2 bytes BE).
    if (len < hdr_len + 8 + 4 + 2 + 4) return; // sanity
    const uint8_t *eapol = &p[hdr_len + 8];
    if (eapol[1] != 0x03) return; // só interessa EAPOL-Key

    // Descriptor type (1 byte) + Key Information (2 bytes BE)
    uint16_t key_info = ((uint16_t)eapol[5] << 8) | eapol[6];
    uint8_t msg = classify_eapol_msg(key_info);

    // Marca o bit no msg_mask (bit0=M1, bit1=M2, ...)
    if (msg >= 1 && msg <= 4) {
        s_eapol_msg_mask |= (uint8_t)(1u << (msg - 1));
    }
    s_eapol_count++;

    // Tira FCS de 4 bytes do final pra emitir só o frame 802.11
    uint16_t orig_len = (len >= 4) ? (len - 4) : len;
    uint8_t flags = 0;
    size_t emit_len = orig_len;
    if (emit_len > EAPOL_FRAME_MAX) {
        emit_len = EAPOL_FRAME_MAX;
        flags |= 0x01; // truncated
    }

    uint8_t bssid_copy[6], sta_copy[6];
    memcpy(bssid_copy, bssid, 6);
    memcpy(sta_copy,   sta,   6);
    (void)direction;
    emit_eapol(bssid_copy, sta_copy, msg, flags, orig_len, p, emit_len);
}

static void eapol_task(void *arg)
{
    eapol_ctx_t *ctx = (eapol_ctx_t *)arg;
    int64_t start_us = esp_timer_get_time();
    int64_t deadline_us = start_us + (int64_t)ctx->duration_sec * 1000000LL;

    memcpy((void *)s_eapol_target_bssid, ctx->bssid, 6);
    s_eapol_count = 0;
    s_eapol_msg_mask = 0;

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA,
    };
    esp_wifi_set_promiscuous_filter(&filter);

    esp_err_t err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_promiscuous rc=%s", esp_err_to_name(err));
        emit_capture_done(ctx->bssid, 0, 0, 0, 2);
        goto cleanup;
    }
    esp_wifi_set_promiscuous_rx_cb(&promisc_cb_eapol);
    esp_wifi_set_channel(ctx->channel, WIFI_SECOND_CHAN_NONE);

    // Loop: encerra ao receber os 4 frames OU quando deadline expirar
    while (!s_stop && esp_timer_get_time() < deadline_us) {
        if (s_eapol_msg_mask == 0x0F) break; // M1..M4 todos vistos
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    esp_wifi_set_promiscuous(false);

    uint8_t status;
    if (s_eapol_msg_mask == 0x0F)      status = 0; // ok, 4-way completo
    else if (s_eapol_count > 0)        status = 1; // parcial
    else                                status = 1; // timeout sem nada
    uint32_t elapsed = (uint32_t)((esp_timer_get_time() - start_us) / 1000);
    emit_capture_done(ctx->bssid, s_eapol_count, s_eapol_msg_mask,
                      elapsed, status);
    ESP_LOGI(TAG, "wpa_capture done: %u frames, mask=0x%02x in %u ms",
             (unsigned)s_eapol_count, (unsigned)s_eapol_msg_mask,
             (unsigned)elapsed);

cleanup:
    free(ctx);
    s_stop = false;
    s_task = NULL;
    s_mode = SNIFF_MODE_IDLE;
    vTaskDelete(NULL);
}

esp_err_t sniff_wifi_eapol_start(const uint8_t bssid[6], uint8_t channel,
                                  uint16_t duration_sec)
{
    if (s_mode != SNIFF_MODE_IDLE) return ESP_ERR_INVALID_STATE;
    if (!bssid) return ESP_ERR_INVALID_ARG;
    if (channel == 0 || channel > 13) return ESP_ERR_INVALID_ARG;
    if (duration_sec == 0) duration_sec = 60;
    if (duration_sec > 600) duration_sec = 600;

    eapol_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return ESP_ERR_NO_MEM;
    memcpy(ctx->bssid, bssid, 6);
    ctx->channel = channel;
    ctx->duration_sec = duration_sec;

    s_mode = SNIFF_MODE_EAPOL;
    s_stop = false;
    if (xTaskCreate(eapol_task, "wpa_capture", 4096, ctx, 5, &s_task) != pdPASS) {
        free(ctx);
        s_mode = SNIFF_MODE_IDLE;
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "wpa_capture started: bssid=%02x:%02x:%02x:%02x:%02x:%02x ch=%u for %us",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
             channel, (unsigned)duration_sec);
    return ESP_OK;
}

esp_err_t sniff_wifi_eapol_stop(void)
{
    if (s_mode != SNIFF_MODE_EAPOL) return ESP_ERR_INVALID_STATE;
    s_stop = true;
    return ESP_OK;
}
