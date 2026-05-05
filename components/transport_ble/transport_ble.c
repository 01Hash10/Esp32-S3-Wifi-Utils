#include "transport_ble.h"
#include "ble_uuids.h"
#include "tlv.h"

#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "nvs_flash.h"

#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_uuid.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

static const char *TAG = "transport-ble";

// UUIDs em formato little-endian (NimBLE convenção).
// Strings em INTEGRATION.md / ble_uuids.h:
//   svc:    e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c01
//   cmd:    e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c02
//   stream: e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c03
static const ble_uuid128_t svc_uuid = BLE_UUID128_INIT(
    0x01, 0x0c, 0x5e, 0x4b, 0x8d, 0x1a, 0x6c, 0x9d,
    0x1a, 0x4b, 0x1f, 0x4f, 0xa0, 0xc5, 0xc0, 0xe7);
static const ble_uuid128_t chr_cmd_uuid = BLE_UUID128_INIT(
    0x02, 0x0c, 0x5e, 0x4b, 0x8d, 0x1a, 0x6c, 0x9d,
    0x1a, 0x4b, 0x1f, 0x4f, 0xa0, 0xc5, 0xc0, 0xe7);
static const ble_uuid128_t chr_stream_uuid = BLE_UUID128_INIT(
    0x03, 0x0c, 0x5e, 0x4b, 0x8d, 0x1a, 0x6c, 0x9d,
    0x1a, 0x4b, 0x1f, 0x4f, 0xa0, 0xc5, 0xc0, 0xe7);

static uint16_t s_cmd_attr_handle;
static uint16_t s_stream_attr_handle;

static uint16_t s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
static bool s_cmd_subscribed = false;
static bool s_stream_subscribed = false;

static transport_ble_cmd_handler_t s_cmd_handler = NULL;

static uint8_t s_addr_type;

static int gap_event_cb(struct ble_gap_event *event, void *arg);
static void advertise(void);

static int chr_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                         struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }
    // Só cmd_ctrl é gravável.
    if (attr_handle != s_cmd_attr_handle) {
        return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
    }

    const uint16_t len = OS_MBUF_PKTLEN(ctxt->om);
    if (len == 0 || len > 512) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }

    uint8_t buf[513];
    uint16_t out_len = 0;
    int rc = ble_hs_mbuf_to_flat(ctxt->om, buf, sizeof(buf) - 1, &out_len);
    if (rc != 0) {
        return BLE_ATT_ERR_UNLIKELY;
    }
    buf[out_len] = 0;

    if (s_cmd_handler) {
        s_cmd_handler(buf, out_len);
    }
    return 0;
}

static const struct ble_gatt_svc_def s_gatt_svcs[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &svc_uuid.u,
        .characteristics = (struct ble_gatt_chr_def[]) {
            {
                .uuid = &chr_cmd_uuid.u,
                .access_cb = chr_access_cb,
                .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_NOTIFY,
                .val_handle = &s_cmd_attr_handle,
            },
            {
                .uuid = &chr_stream_uuid.u,
                .access_cb = chr_access_cb,
                .flags = BLE_GATT_CHR_F_NOTIFY,
                .val_handle = &s_stream_attr_handle,
            },
            { 0 }
        },
    },
    { 0 }
};

static int gap_event_cb(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            ESP_LOGI(TAG, "client connected, conn_handle=%d", event->connect.conn_handle);
            s_conn_handle = event->connect.conn_handle;
        } else {
            ESP_LOGW(TAG, "connect failed, status=%d", event->connect.status);
            advertise();
        }
        break;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "client disconnected, reason=%d", event->disconnect.reason);
        s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
        s_cmd_subscribed = false;
        s_stream_subscribed = false;
        advertise();
        break;

    case BLE_GAP_EVENT_SUBSCRIBE:
        if (event->subscribe.attr_handle == s_cmd_attr_handle) {
            s_cmd_subscribed = event->subscribe.cur_notify;
        } else if (event->subscribe.attr_handle == s_stream_attr_handle) {
            s_stream_subscribed = event->subscribe.cur_notify;
        }
        ESP_LOGI(TAG, "subscribe attr=%d notify=%d",
                 event->subscribe.attr_handle, event->subscribe.cur_notify);
        break;

    case BLE_GAP_EVENT_MTU:
        ESP_LOGI(TAG, "mtu update conn=%d mtu=%d",
                 event->mtu.conn_handle, event->mtu.value);
        break;

    case BLE_GAP_EVENT_ADV_COMPLETE:
        advertise();
        break;

    default:
        break;
    }
    return 0;
}

static void advertise(void)
{
    // Adv packet (limite 31 bytes): flags + nome completo.
    struct ble_hs_adv_fields adv_fields = {0};
    adv_fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;

    const char *name = ble_svc_gap_device_name();
    adv_fields.name = (uint8_t *)name;
    adv_fields.name_len = strlen(name);
    adv_fields.name_is_complete = 1;

    int rc = ble_gap_adv_set_fields(&adv_fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_set_fields rc=%d", rc);
        return;
    }

    // Scan response (limite 31 bytes): service UUID 128-bit (18 bytes).
    // Service UUID 128-bit não cabe junto com o nome no adv packet.
    struct ble_hs_adv_fields rsp_fields = {0};
    rsp_fields.uuids128 = (ble_uuid128_t *)&svc_uuid;
    rsp_fields.num_uuids128 = 1;
    rsp_fields.uuids128_is_complete = 1;

    rc = ble_gap_adv_rsp_set_fields(&rsp_fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_rsp_set_fields rc=%d", rc);
        return;
    }

    struct ble_gap_adv_params adv_params = {0};
    adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;

    rc = ble_gap_adv_start(s_addr_type, NULL, BLE_HS_FOREVER,
                           &adv_params, gap_event_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_start rc=%d", rc);
    } else {
        ESP_LOGI(TAG, "advertising as '%s'", name);
    }
}

static void on_sync(void)
{
    int rc = ble_hs_id_infer_auto(0, &s_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "infer addr rc=%d", rc);
        return;
    }

    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_BT);
    char name[32];
    snprintf(name, sizeof(name), WIFIUTILS_DEVICE_NAME_PREFIX "%02X%02X",
             mac[4], mac[5]);
    ble_svc_gap_device_name_set(name);

    advertise();
}

static void on_reset(int reason)
{
    ESP_LOGW(TAG, "host reset, reason=%d", reason);
}

static void host_task(void *param)
{
    (void)param;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

static void send_notify(uint16_t attr_handle, bool subscribed,
                        const uint8_t *data, size_t len)
{
    if (!subscribed || s_conn_handle == BLE_HS_CONN_HANDLE_NONE) {
        return;
    }
    struct os_mbuf *om = ble_hs_mbuf_from_flat(data, len);
    if (!om) {
        ESP_LOGW(TAG, "mbuf alloc failed");
        return;
    }
    int rc = ble_gattc_notify_custom(s_conn_handle, attr_handle, om);
    if (rc != 0) {
        ESP_LOGW(TAG, "notify rc=%d (attr=%d)", rc, attr_handle);
    }
}

void transport_ble_send_cmd(const uint8_t *data, size_t len)
{
    send_notify(s_cmd_attr_handle, s_cmd_subscribed, data, len);
}

void transport_ble_advertising_resume(void)
{
    if (s_conn_handle != BLE_HS_CONN_HANDLE_NONE) return; // adv suprimida durante conexão
    if (ble_gap_adv_active()) return;
    advertise();
}

// Hook weak pro playbook engine inspecionar TLVs antes do BLE send.
// No-op por default; playbook component override forte se linkado.
__attribute__((weak)) void playbook_hook_tlv(uint8_t msg_type,
                                              const uint8_t *payload, size_t len)
{
    (void)msg_type; (void)payload; (void)len;
}

void transport_ble_send_stream(const uint8_t *data, size_t len)
{
    if (len >= 4) {
        playbook_hook_tlv(data[2], data + 4, len - 4);
    }
    send_notify(s_stream_attr_handle, s_stream_subscribed, data, len);
}

// Heartbeat periódico: emite TLV_MSG_HEARTBEAT no stream a cada 5s enquanto
// houver cliente subscribed. Permite o app detectar conexão "morta" sem
// precisar fazer polling via ping.
//
// Payload (10 bytes):
//   [0..3] uptime_ms (uint32 BE)
//   [4..7] free_sram (uint32 BE)
//   [8..9] free_psram_kb (uint16 BE) — em KB pra caber em 16 bits
static esp_timer_handle_t s_heartbeat_timer = NULL;
static uint8_t s_heartbeat_seq = 0;

static void heartbeat_cb(void *arg)
{
    (void)arg;
    if (s_conn_handle == BLE_HS_CONN_HANDLE_NONE) return;
    if (!s_stream_subscribed) return;

    uint64_t uptime_ms = esp_timer_get_time() / 1000;
    uint32_t free_sram = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    uint32_t free_psram = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    uint16_t free_psram_kb = (uint16_t)(free_psram / 1024);

    uint8_t payload[10];
    payload[0] = (uint8_t)(uptime_ms >> 24);
    payload[1] = (uint8_t)(uptime_ms >> 16);
    payload[2] = (uint8_t)(uptime_ms >> 8);
    payload[3] = (uint8_t)(uptime_ms & 0xFF);
    payload[4] = (uint8_t)(free_sram >> 24);
    payload[5] = (uint8_t)(free_sram >> 16);
    payload[6] = (uint8_t)(free_sram >> 8);
    payload[7] = (uint8_t)(free_sram & 0xFF);
    payload[8] = (uint8_t)(free_psram_kb >> 8);
    payload[9] = (uint8_t)(free_psram_kb & 0xFF);

    uint8_t frame[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(frame, sizeof(frame),
                           TLV_MSG_HEARTBEAT, s_heartbeat_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(frame, (size_t)total);
}

esp_err_t transport_ble_init(transport_ble_cmd_handler_t cmd_handler)
{
    s_cmd_handler = cmd_handler;

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    err = nimble_port_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init failed: %s", esp_err_to_name(err));
        return err;
    }

    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.reset_cb = on_reset;

    ble_svc_gap_init();
    ble_svc_gatt_init();

    int rc = ble_gatts_count_cfg(s_gatt_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "gatts_count_cfg rc=%d", rc);
        return ESP_FAIL;
    }
    rc = ble_gatts_add_svcs(s_gatt_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "gatts_add_svcs rc=%d", rc);
        return ESP_FAIL;
    }

    nimble_port_freertos_init(host_task);

    // Inicia heartbeat periódico (5s)
    const esp_timer_create_args_t hb_args = {
        .callback = &heartbeat_cb,
        .name = "ble_heartbeat",
    };
    if (esp_timer_create(&hb_args, &s_heartbeat_timer) == ESP_OK) {
        esp_timer_start_periodic(s_heartbeat_timer, 5000000); // 5s
    } else {
        ESP_LOGW(TAG, "heartbeat timer create failed");
    }

    return ESP_OK;
}
