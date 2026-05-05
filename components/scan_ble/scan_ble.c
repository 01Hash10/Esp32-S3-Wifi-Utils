#include "scan_ble.h"
#include "tlv.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"

static const char *TAG = "scan-ble";

// Hook fraco do watchdog. Componente watchdog opcional; sem ele, no-op.
__attribute__((weak)) void watchdog_hook_ble_spam(uint8_t vendor)
{
    (void)vendor;
}

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
//   [11+nL+mL] tracker_flags (uint8) — NOVO em 2026-05-05:
//                  bit 0 = Apple Find My (mfg_data 4C 00 12 ...)
//                  bit 1 = Samsung SmartTag (svc_data UUID 0xFD5A)
//                  bit 2 = Tile (company id 0x0067)
//                  bit 3 = Chipolo (company id 0x07E6)
//                  bits 4..7 = reservado
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

// Defense mode (BLE spam detector)
#define BLE_SPAM_MAC_SET_CAP   32
#define BLE_SPAM_THRESHOLD     6      // MACs únicos/s por vendor
#define BLE_SPAM_WINDOW_MS     1000
#define BLE_SPAM_COOLDOWN_MS   3000
#define BLE_SPAM_VENDOR_COUNT  3      // 0=Apple, 1=Samsung, 2=Google

static volatile bool s_defense_mode = false;
static uint8_t s_spam_macs[BLE_SPAM_VENDOR_COUNT][BLE_SPAM_MAC_SET_CAP][6];
static volatile size_t s_spam_count[BLE_SPAM_VENDOR_COUNT] = {0};
static int64_t s_spam_window_start_us = 0;
static int64_t s_spam_last_alert_us[BLE_SPAM_VENDOR_COUNT] = {0};
static TaskHandle_t s_defense_check_task = NULL;
static volatile bool s_defense_stop_requested = false;

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

// Classifica o device como tracker conhecido com base em mfg_data e
// service_data parseados pelo NimBLE. Retorna bitmap (bits 0..3 atribuídos).
static uint8_t classify_tracker(const struct ble_hs_adv_fields *fields)
{
    uint8_t flags = 0;

    // Apple Find My: mfg_data Apple (4C 00) com subtype 0x12 (Offline Finding).
    // Layout típico: 4C 00 12 19 ... (subtype 0x12, length 0x19=25)
    if (fields->mfg_data && fields->mfg_data_len >= 4 &&
        fields->mfg_data[0] == 0x4C && fields->mfg_data[1] == 0x00 &&
        fields->mfg_data[2] == 0x12) {
        flags |= 0x01;
    }
    // Tile: company ID 0x0067 (LE = 67 00)
    if (fields->mfg_data && fields->mfg_data_len >= 2 &&
        fields->mfg_data[0] == 0x67 && fields->mfg_data[1] == 0x00) {
        flags |= 0x04;
    }
    // Chipolo: company ID 0x07E6 (LE = E6 07)
    if (fields->mfg_data && fields->mfg_data_len >= 2 &&
        fields->mfg_data[0] == 0xE6 && fields->mfg_data[1] == 0x07) {
        flags |= 0x08;
    }
    // Samsung SmartTag: svc_data com UUID 0xFD5A (Samsung Find).
    // svc_data_uuid16 começa com os 2 bytes da UUID em LE: 5A FD.
    if (fields->svc_data_uuid16 && fields->svc_data_uuid16_len >= 2 &&
        fields->svc_data_uuid16[0] == 0x5A && fields->svc_data_uuid16[1] == 0xFD) {
        flags |= 0x02;
    }
    return flags;
}

static void emit_dev(const uint8_t *mac, uint8_t addr_type, int8_t rssi,
                     const struct ble_hs_adv_fields *fields)
{
    uint8_t payload[10 + MAX_NAME_LEN + 1 + MAX_MFG_LEN + 1];
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

    uint8_t tracker = classify_tracker(fields);
    payload[off++] = tracker;

    uint8_t frame[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(frame, sizeof(frame),
                           TLV_MSG_BLE_SCAN_DEV, s_seq++,
                           payload, off);
    if (total > 0 && s_emit) s_emit(frame, (size_t)total);
}

// Classifica adv pela assinatura de spam que NÓS conhecemos:
//   - Apple Continuity Proximity Pairing: mfg_data 4C 00 07 19 ...
//   - Samsung EasySetup: mfg_data 75 00 01 00 02 00 ...
//   - Google Fast Pair: svc_data UUID 0xFE2C
// Retorna -1 se não for spam suspeito.
static int classify_spam_signature(const struct ble_hs_adv_fields *f)
{
    if (f->mfg_data && f->mfg_data_len >= 4 &&
        f->mfg_data[0] == 0x4C && f->mfg_data[1] == 0x00 &&
        f->mfg_data[2] == 0x07 && f->mfg_data[3] == 0x19) {
        return 0; // Apple Continuity proximity pairing
    }
    if (f->mfg_data && f->mfg_data_len >= 6 &&
        f->mfg_data[0] == 0x75 && f->mfg_data[1] == 0x00 &&
        f->mfg_data[2] == 0x01 && f->mfg_data[3] == 0x00 &&
        f->mfg_data[4] == 0x02 && f->mfg_data[5] == 0x00) {
        return 1; // Samsung EasySetup
    }
    if (f->svc_data_uuid16 && f->svc_data_uuid16_len >= 2 &&
        f->svc_data_uuid16[0] == 0x2C && f->svc_data_uuid16[1] == 0xFE) {
        return 2; // Google Fast Pair
    }
    return -1;
}

static bool spam_macs_add(int vendor, const uint8_t mac[6])
{
    for (size_t i = 0; i < s_spam_count[vendor]; i++) {
        if (memcmp(s_spam_macs[vendor][i], mac, 6) == 0) return false;
    }
    if (s_spam_count[vendor] >= BLE_SPAM_MAC_SET_CAP) return false;
    memcpy(s_spam_macs[vendor][s_spam_count[vendor]++], mac, 6);
    return true;
}

static void emit_defense_ble_spam(uint8_t vendor, uint8_t unique_macs,
                                    uint16_t window_ms)
{
    uint8_t payload[4];
    payload[0] = vendor;
    payload[1] = unique_macs;
    payload[2] = (uint8_t)(window_ms >> 8);
    payload[3] = (uint8_t)(window_ms & 0xFF);

    uint8_t frame[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(frame, sizeof(frame),
                           TLV_MSG_DEFENSE_BLE_SPAM, s_seq++,
                           payload, sizeof(payload));
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

        struct ble_hs_adv_fields fields = {0};
        ble_hs_adv_parse_fields(&fields, disc->data, disc->length_data);

        // Modo defense: classifica por assinatura, contadores
        // independentes (não usa s_seen). Não emite BLE_SCAN_DEV;
        // só DEFENSE_BLE_SPAM quando threshold cruza.
        if (s_defense_mode) {
            int sig = classify_spam_signature(&fields);
            if (sig >= 0 && sig < BLE_SPAM_VENDOR_COUNT) {
                spam_macs_add(sig, mac_be);
            }
            return 0;
        }

        if (seen(mac_be)) return 0;
        if (!add_seen(mac_be)) {
            // limite excedido — para o scan e marca como truncado
            ble_gap_disc_cancel();
            emit_done(1);
            s_busy = false;
            return 0;
        }
        s_dev_count++;
        emit_dev(mac_be, disc->addr.type, disc->rssi, &fields);
        return 0;
    }

    case BLE_GAP_EVENT_DISC_COMPLETE:
        emit_done(s_defense_mode ? 0 : 0);
        s_busy = false;
        s_defense_mode = false;
        return 0;

    default:
        return 0;
    }
}

esp_err_t scan_ble_start_ex(scan_ble_mode_t mode, uint16_t duration_sec)
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
    params.passive = (mode == SCAN_BLE_MODE_PASSIVE) ? 1 : 0;
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
    ESP_LOGI(TAG, "scan started (mode=%s, duration=%us)",
             (mode == SCAN_BLE_MODE_PASSIVE) ? "passive" : "active",
             (unsigned)duration_sec);
    return ESP_OK;
}

esp_err_t scan_ble_start(uint16_t duration_sec)
{
    return scan_ble_start_ex(SCAN_BLE_MODE_PASSIVE, duration_sec);
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

// ----------------------------------------------------------------------
// BLE spam detector (defense mode)
// ----------------------------------------------------------------------

static void defense_check_task(void *arg)
{
    uint16_t duration_sec = (uint16_t)(uintptr_t)arg;
    int64_t deadline_us = duration_sec
        ? esp_timer_get_time() + (int64_t)duration_sec * 1000000LL
        : esp_timer_get_time() + (int64_t)3600 * 1000000LL;

    s_spam_window_start_us = esp_timer_get_time();
    for (int v = 0; v < BLE_SPAM_VENDOR_COUNT; v++) {
        s_spam_count[v] = 0;
        s_spam_last_alert_us[v] = 0;
    }

    while (!s_defense_stop_requested && esp_timer_get_time() < deadline_us) {
        vTaskDelay(pdMS_TO_TICKS(200));
        int64_t now = esp_timer_get_time();

        if (now - s_spam_window_start_us < (int64_t)BLE_SPAM_WINDOW_MS * 1000) {
            continue;
        }

        for (int v = 0; v < BLE_SPAM_VENDOR_COUNT; v++) {
            uint8_t cnt = (uint8_t)s_spam_count[v];
            if (cnt >= BLE_SPAM_THRESHOLD) {
                if (now - s_spam_last_alert_us[v] >= (int64_t)BLE_SPAM_COOLDOWN_MS * 1000) {
                    emit_defense_ble_spam((uint8_t)v, cnt, BLE_SPAM_WINDOW_MS);
                    s_spam_last_alert_us[v] = now;
                    ESP_LOGW(TAG, "BLE spam detected: vendor=%d unique_macs=%u",
                             v, (unsigned)cnt);
                    // Watchdog hook: contra-ação opcional
                    watchdog_hook_ble_spam((uint8_t)v);
                }
            }
            s_spam_count[v] = 0;
        }
        s_spam_window_start_us = now;
    }

    // Encerra scan
    ble_gap_disc_cancel();
    s_defense_check_task = NULL;
    s_defense_stop_requested = false;
    vTaskDelete(NULL);
}

esp_err_t scan_ble_defense_start(uint16_t duration_sec)
{
    if (s_busy) return ESP_ERR_INVALID_STATE;
    if (duration_sec > 3600) duration_sec = 3600;

    s_busy = true;
    s_defense_mode = true;
    s_defense_stop_requested = false;
    s_started_us = esp_timer_get_time();
    s_dev_count = 0;
    s_seen_count = 0;

    struct ble_gap_disc_params params = {0};
    params.passive = 1;
    params.filter_duplicates = 0;

    int rc = ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &params,
                           gap_disc_event_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "defense: ble_gap_disc rc=%d", rc);
        s_busy = false;
        s_defense_mode = false;
        emit_done(2);
        return ESP_FAIL;
    }

    if (xTaskCreate(defense_check_task, "ble_def_chk", 3072,
                    (void *)(uintptr_t)duration_sec, 5,
                    &s_defense_check_task) != pdPASS) {
        ble_gap_disc_cancel();
        s_busy = false;
        s_defense_mode = false;
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "ble defense started for %us", (unsigned)duration_sec);
    return ESP_OK;
}

esp_err_t scan_ble_defense_stop(void)
{
    if (!s_busy || !s_defense_mode) return ESP_ERR_INVALID_STATE;
    s_defense_stop_requested = true;
    return ESP_OK;
}

bool scan_ble_busy(void)
{
    return s_busy;
}

bool scan_ble_in_defense_mode(void)
{
    return s_defense_mode;
}
