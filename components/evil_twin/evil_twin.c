#include "evil_twin.h"
#include "tlv.h"
#include "transport_ble.h"

#include <string.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"

static const char *TAG = "evil-twin";

static volatile bool s_active = false;
static esp_netif_t *s_ap_netif = NULL;
static uint8_t s_seq = 0;

bool evil_twin_busy(void)
{
    return s_active;
}

static void emit_client_join(const uint8_t mac[6], uint16_t aid)
{
    uint8_t payload[8];
    memcpy(&payload[0], mac, 6);
    payload[6] = (uint8_t)(aid >> 8);
    payload[7] = (uint8_t)(aid & 0xFF);

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_EVIL_CLIENT_JOIN, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

static void emit_client_leave(const uint8_t mac[6], uint8_t reason)
{
    uint8_t payload[7];
    memcpy(&payload[0], mac, 6);
    payload[6] = reason;

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_EVIL_CLIENT_LEAVE, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

static void wifi_event_handler(void *arg, esp_event_base_t base,
                                int32_t id, void *data)
{
    (void)arg;
    if (base != WIFI_EVENT) return;

    if (id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *evt = data;
        ESP_LOGI(TAG, "client join: %02x:%02x:%02x:%02x:%02x:%02x aid=%u",
                 evt->mac[0], evt->mac[1], evt->mac[2],
                 evt->mac[3], evt->mac[4], evt->mac[5], evt->aid);
        emit_client_join(evt->mac, evt->aid);
    } else if (id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t *evt = data;
        ESP_LOGI(TAG, "client leave: %02x:%02x:%02x:%02x:%02x:%02x reason=%u",
                 evt->mac[0], evt->mac[1], evt->mac[2],
                 evt->mac[3], evt->mac[4], evt->mac[5], evt->reason);
        emit_client_leave(evt->mac, (uint8_t)evt->reason);
    }
}

esp_err_t evil_twin_init(void)
{
    esp_err_t err = esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL);
    if (err != ESP_OK) return err;
    ESP_LOGI(TAG, "ready");
    return ESP_OK;
}

esp_err_t evil_twin_start(const char *ssid, const char *psk,
                          uint8_t channel, uint8_t max_conn)
{
    if (s_active) return ESP_ERR_INVALID_STATE;
    if (!ssid || !*ssid) return ESP_ERR_INVALID_ARG;
    if (channel == 0 || channel > 13) return ESP_ERR_INVALID_ARG;
    if (max_conn == 0)  max_conn = 4;
    if (max_conn > 10)  max_conn = 10;

    size_t ssid_len = strnlen(ssid, 33);
    if (ssid_len == 0 || ssid_len > 32) return ESP_ERR_INVALID_ARG;

    bool open = (psk == NULL) || (psk[0] == 0);
    if (!open) {
        size_t psk_len = strnlen(psk, 64);
        if (psk_len < 8 || psk_len > 63) return ESP_ERR_INVALID_ARG;
    }

    // Cria netif AP se ainda não criado
    if (!s_ap_netif) {
        s_ap_netif = esp_netif_create_default_wifi_ap();
        if (!s_ap_netif) {
            ESP_LOGE(TAG, "failed to create AP netif");
            return ESP_FAIL;
        }
    }

    // Mode APSTA pra coexistir com promiscuous/scan se já existirem.
    // (scan_wifi inicializa em STA — APSTA é superset.)
    esp_err_t err = esp_wifi_set_mode(WIFI_MODE_APSTA);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_mode rc=%s", esp_err_to_name(err));
        return err;
    }

    wifi_config_t cfg = {0};
    memcpy(cfg.ap.ssid, ssid, ssid_len);
    cfg.ap.ssid_len = (uint8_t)ssid_len;
    cfg.ap.channel = channel;
    cfg.ap.max_connection = max_conn;
    cfg.ap.beacon_interval = 100;
    if (open) {
        cfg.ap.authmode = WIFI_AUTH_OPEN;
    } else {
        cfg.ap.authmode = WIFI_AUTH_WPA2_PSK;
        strncpy((char *)cfg.ap.password, psk, sizeof(cfg.ap.password) - 1);
    }
    cfg.ap.pmf_cfg.capable = true;
    cfg.ap.pmf_cfg.required = false;

    err = esp_wifi_set_config(WIFI_IF_AP, &cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_config rc=%s", esp_err_to_name(err));
        return err;
    }

    s_active = true;
    ESP_LOGI(TAG, "started: ssid='%s' ch=%u %s max_conn=%u",
             ssid, channel, open ? "OPEN" : "WPA2", max_conn);
    return ESP_OK;
}

esp_err_t evil_twin_stop(void)
{
    if (!s_active) return ESP_ERR_INVALID_STATE;

    // Volta a STA-only — desliga o AP.
    esp_err_t err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "set_mode(STA) rc=%s", esp_err_to_name(err));
    }
    s_active = false;
    ESP_LOGI(TAG, "stopped");
    return ESP_OK;
}
