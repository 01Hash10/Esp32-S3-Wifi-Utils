#include "scan_ble.h"
#include "tlv.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"

static const char *TAG = "scan-ble";

#define MAX_UNIQUE_DEVS  64
#define MAX_NAME_LEN     32
#define MAX_MFG_LEN      30

// Layout do payload TLV_MSG_BLE_SCAN_DEV:
//   [0..5]   bssid (BLE address, 6 bytes)
//   [6]      addr_type (uint8 — ble addr type)
//   [7]      rssi (int8)
//   [8]      adv_flags (uint8)
//   [9]      name_len (uint8, max 32)
//   [10..]   name UTF-8
//   [10+nL]  mfg_data_len (uint8, max 30)
//   [11+nL..] mfg_data (raw, primeiros 2 bytes = company id LE)
//
// Layout TLV_MSG_BLE_SCAN_DONE (7 bytes):
//   [0..1]  dev_count (uint16 BE)
//   [2..5]  scan_time_ms (uint32 BE)
//   [6]     status (0=ok, 1=truncado/limit, 2=err)

static scan_ble_emit_t s_emit = NULL;
static bool s_busy = false;
static int64_t s_started_us = 0;
static uint8_t s_seq = 0;
static uint16_t s_dev_count = 0;

static uint8_t s_seen[MAX_UNIQUE_DEVS][6];
static size_t s_seen_count = 0;

static int gap_disc_event_cb(struct ble_gap_event *event, void *arg);

static bool seen(const uint8_t *mac)
{
    for (size_t i = 0; i < s_seen_count; i++) {
        if (memcmp(s_seen[i], mac, 6) == 0) return true;
    }
    return false;
}

static bool add_seen(const uint8_t *mac)
{
    if (s_seen_count >= MAX_UNIQUE_DEVS) return false;
    memcpy(s_seen[s_seen_count++], mac, 6);
    return true;
}

static void emit_done(uint8_t status)
{
    uint32_t scan_ms = (uint32_t)((esp_timer_get_time() - s_started_us) / 1000);
    uint8_t payload[7];
    payload[0] = (uint8_t)((s_dev_count >> 8) & 0xFF);
    payload[1] = (uint8_t)(s_dev_count & 0xFF);
    payload[2] = (uint8_t)((scan_ms >> 24) & 0xFF);
    payload[3] = (uint8_t)((scan_ms >> 16) & 0xFF);
    payload[4] = (uint8_t)((scan_ms >> 8) & 0xFF);
    payload[5] = (uint8_t)(scan_ms & 0xFF);
    payload[6] = status;

    uint8_t frame[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(frame, sizeof(frame),
                           TLV_MSG_BLE_SCAN_DONE, s_seq++,
                           payload, sizeof(payload));
    if (total > 0 && s_emit) s_emit(frame, (size_t)total);

    ESP_LOGI(TAG, "scan done: %u devs in %u ms (status=%u)",
             (unsigned)s_dev_count, (unsigned)scan_ms, (unsigned)status);
}

static void emit_dev(const uint8_t *mac, uint8_t addr_type, int8_t rssi,
                     const struct ble_hs_adv_fields *fields)
{
    uint8_t payload[10 + MAX_NAME_LEN + 1 + MAX_MFG_LEN];
    size_t off = 0;

    memcpy(&payload[off], mac, 6); off += 6;
    payload[off++] = addr_type;
    payload[off++] = (uint8_t)rssi;
    payload[off++] = fields->flags;

    size_t name_len = 0;
    if (fields->name && fields->name_len > 0) {
        name_len = fields->name_len > MAX_NAME_LEN ? MAX_NAME_LEN : fields->name_len;
    }
    payload[off++] = (uint8_t)name_len;
    if (name_len) {
        memcpy(&payload[off], fields->name, name_len);
        off += name_len;
    }

    size_t mfg_len = 0;
    if (fields->mfg_data && fields->mfg_data_len > 0) {
        mfg_len = fields->mfg_data_len > MAX_MFG_LEN ? MAX_MFG_LEN : fields->mfg_data_len;
    }
    payload[off++] = (uint8_t)mfg_len;
    if (mfg_len) {
        memcpy(&payload[off], fields->mfg_data, mfg_len);
        off += mfg_len;
    }

    uint8_t frame[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(frame, sizeof(frame),
                           TLV_MSG_BLE_SCAN_DEV, s_seq++,
                           payload, off);
    if (total > 0 && s_emit) s_emit(frame, (size_t)total);
}

static int gap_disc_event_cb(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_DISC: {
        const struct ble_gap_disc_desc *disc = &event->disc;

        // Reverse LE address bytes para BE de exibição.
        uint8_t mac_be[6];
        for (int i = 0; i < 6; i++) mac_be[i] = disc->addr.val[5 - i];

        if (seen(mac_be)) return 0;
        if (!add_seen(mac_be)) {
            // limite excedido — para o scan e marca como truncado
            ble_gap_disc_cancel();
            emit_done(1);
            s_busy = false;
            return 0;
        }
        s_dev_count++;

        struct ble_hs_adv_fields fields = {0};
        ble_hs_adv_parse_fields(&fields, disc->data, disc->length_data);

        emit_dev(mac_be, disc->addr.type, disc->rssi, &fields);
        return 0;
    }

    case BLE_GAP_EVENT_DISC_COMPLETE:
        emit_done(0);
        s_busy = false;
        return 0;

    default:
        return 0;
    }
}

esp_err_t scan_ble_start(uint16_t duration_sec)
{
    if (s_busy) return ESP_ERR_INVALID_STATE;

    s_busy = true;
    s_started_us = esp_timer_get_time();
    s_dev_count = 0;
    s_seen_count = 0;

    struct ble_gap_disc_params params = {0};
    params.itvl = 0;
    params.window = 0;
    params.filter_policy = 0;
    params.limited = 0;
    params.passive = 1;
    params.filter_duplicates = 0;

    int32_t duration_ms = duration_sec ? (int32_t)duration_sec * 1000 : BLE_HS_FOREVER;

    int rc = ble_gap_disc(BLE_OWN_ADDR_PUBLIC, duration_ms, &params,
                          gap_disc_event_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_disc rc=%d", rc);
        s_busy = false;
        emit_done(2);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "scan started (passive, duration=%us)",
             (unsigned)duration_sec);
    return ESP_OK;
}

esp_err_t scan_ble_stop(void)
{
    if (!s_busy) return ESP_ERR_INVALID_STATE;
    int rc = ble_gap_disc_cancel();
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        ESP_LOGW(TAG, "disc_cancel rc=%d", rc);
    }
    // emit_done será disparado por BLE_GAP_EVENT_DISC_COMPLETE
    return ESP_OK;
}

esp_err_t scan_ble_init(scan_ble_emit_t emit)
{
    s_emit = emit;
    ESP_LOGI(TAG, "ready");
    return ESP_OK;
}
