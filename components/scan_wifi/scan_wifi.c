#include "scan_wifi.h"
#include "tlv.h"

#include <string.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "scan-wifi";

static scan_wifi_emit_t s_emit = NULL;
static bool s_busy = false;
static int64_t s_started_us = 0;
static uint8_t s_seq = 0;

// Layout do payload TLV_MSG_WIFI_SCAN_AP (sem fragmentação,
// max ssid 32 → 43 bytes total payload, cabe em 1 frame BLE):
//   [0..5]  bssid (6 bytes)
//   [6]     rssi (int8)
//   [7]     primary channel (uint8)
//   [8]     auth_mode (uint8 = wifi_auth_mode_t)
//   [9]     ssid_len (uint8, max 32) — 0 implica hidden, mas use o flag
//   [10..]  ssid bytes (UTF-8, sem terminador)
//   [10+ssid_len] flags (uint8) — NOVO no 0xc0c7b49+:
//                  bit 0 = hidden (SSID em beacon vazio)
//                  bit 1 = WPS habilitado
//                  bit 2 = 802.11 phy_11b
//                  bit 3 = 802.11 phy_11n
//                  bits 4..7 = reservado
//
// App antigo que parou de ler em 10+ssid_len continua funcionando (não vê
// flags). App novo lê 1 byte adicional após o ssid.
//
// Layout do payload TLV_MSG_WIFI_SCAN_DONE (7 bytes):
//   [0..1]  ap_count (uint16 BE)
//   [2..5]  scan_time_ms (uint32 BE)
//   [6]     status (0=ok, 1=err)

static void emit_ap(const wifi_ap_record_t *rec)
{
    uint8_t payload[10 + 33 + 1];
    memcpy(&payload[0], rec->bssid, 6);
    payload[6] = (uint8_t)rec->rssi;
    payload[7] = rec->primary;
    payload[8] = (uint8_t)rec->authmode;

    size_t ssid_len = strnlen((const char *)rec->ssid, 32);
    payload[9] = (uint8_t)ssid_len;
    memcpy(&payload[10], rec->ssid, ssid_len);

    uint8_t flags = 0;
    if (ssid_len == 0)        flags |= 0x01; // hidden
    if (rec->wps)             flags |= 0x02; // WPS habilitado (IDF parseou IE)
    if (rec->phy_11b)         flags |= 0x04;
    if (rec->phy_11n)         flags |= 0x08;
    payload[10 + ssid_len] = flags;

    uint8_t frame[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(frame, sizeof(frame),
                           TLV_MSG_WIFI_SCAN_AP, s_seq++,
                           payload, 11 + ssid_len);
    if (total > 0 && s_emit) {
        s_emit(frame, (size_t)total);
    }
}

static void emit_done(uint16_t ap_count, uint32_t scan_ms, uint8_t status)
{
    uint8_t payload[7];
    payload[0] = (uint8_t)((ap_count >> 8) & 0xFF);
    payload[1] = (uint8_t)(ap_count & 0xFF);
    payload[2] = (uint8_t)((scan_ms >> 24) & 0xFF);
    payload[3] = (uint8_t)((scan_ms >> 16) & 0xFF);
    payload[4] = (uint8_t)((scan_ms >> 8) & 0xFF);
    payload[5] = (uint8_t)(scan_ms & 0xFF);
    payload[6] = status;

    uint8_t frame[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(frame, sizeof(frame),
                           TLV_MSG_WIFI_SCAN_DONE, s_seq++,
                           payload, sizeof(payload));
    if (total > 0 && s_emit) {
        s_emit(frame, (size_t)total);
    }
}

static void scan_done_handler(void *arg, esp_event_base_t base,
                              int32_t event_id, void *event_data)
{
    (void)arg; (void)base; (void)event_id; (void)event_data;

    uint16_t count = 0;
    esp_wifi_scan_get_ap_num(&count);

    wifi_ap_record_t *records = NULL;
    if (count > 0) {
        records = calloc(count, sizeof(wifi_ap_record_t));
        if (records) {
            esp_wifi_scan_get_ap_records(&count, records);
            for (uint16_t i = 0; i < count; i++) {
                emit_ap(&records[i]);
                // Pequeno yield pra não saturar fila do GATT
                vTaskDelay(pdMS_TO_TICKS(5));
            }
            free(records);
        } else {
            count = 0;
        }
    }

    uint32_t scan_ms = (uint32_t)((esp_timer_get_time() - s_started_us) / 1000);
    emit_done(count, scan_ms, 0);
    ESP_LOGI(TAG, "scan done: %u APs in %u ms",
             (unsigned)count, (unsigned)scan_ms);

    s_busy = false;
}

esp_err_t scan_wifi_start(scan_wifi_mode_t mode, uint8_t channel)
{
    if (s_busy) return ESP_ERR_INVALID_STATE;
    if (channel > 13) return ESP_ERR_INVALID_ARG;
    s_busy = true;
    s_started_us = esp_timer_get_time();

    wifi_scan_config_t cfg = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = channel, // 0 = todos os canais
        .show_hidden = true,
        .scan_type = (mode == SCAN_WIFI_MODE_PASSIVE)
                       ? WIFI_SCAN_TYPE_PASSIVE
                       : WIFI_SCAN_TYPE_ACTIVE,
    };
    if (mode == SCAN_WIFI_MODE_PASSIVE) {
        cfg.scan_time.passive = 360; // ms por canal — beacons ~100ms cada
    } else {
        cfg.scan_time.active.min = 80;
        cfg.scan_time.active.max = 120;
    }

    esp_err_t err = esp_wifi_scan_start(&cfg, false);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "scan_start failed: %s", esp_err_to_name(err));
        s_busy = false;
        emit_done(0, 0, 1);
    }
    return err;
}

esp_err_t scan_wifi_start_active(void)
{
    return scan_wifi_start(SCAN_WIFI_MODE_ACTIVE, 0);
}

esp_err_t scan_wifi_init(scan_wifi_emit_t emit)
{
    s_emit = emit;

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, WIFI_EVENT_SCAN_DONE,
        &scan_done_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "ready (STA mode, scan-only)");
    return ESP_OK;
}
