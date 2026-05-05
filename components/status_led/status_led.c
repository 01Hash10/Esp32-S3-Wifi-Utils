#include "status_led.h"

#include "esp_log.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "led_strip.h"

#include "transport_ble.h"
#include "scan_wifi.h"
#include "scan_ble.h"
#include "hacking_wifi.h"
#include "hacking_ble.h"
#include "attack_lan.h"
#include "sniff_wifi.h"
#include "evil_twin.h"
#include "captive_portal.h"
#include "watchdog.h"

static const char *TAG = "status-led";

// ESP32-S3-DevKitC-1 tem WS2812 no GPIO 48
#define LED_GPIO            48
#define LED_POLL_INTERVAL_MS 500

typedef enum {
    LED_STATE_IDLE      = 0,  // azul    — boot OK, sem BLE
    LED_STATE_CONNECTED = 1,  // roxo    — BLE pareado/subscribed
    LED_STATE_SCAN      = 2,  // branco  — wifi/ble scan ou sniff (não-defense)
    LED_STATE_DEFENSE   = 3,  // amarelo — defense detectors ou watchdog
    LED_STATE_ATTACK    = 4,  // vermelho — qualquer feature ofensiva
} led_state_t;

// Cores RGB (intensidade reduzida pra LED não ofuscar)
static const uint8_t COLORS[][3] = {
    [LED_STATE_IDLE]      = {0,   0,   60}, // azul
    [LED_STATE_CONNECTED] = {50,  0,   60}, // roxo
    [LED_STATE_SCAN]      = {60,  60,  60}, // branco
    [LED_STATE_DEFENSE]   = {80,  70,  0},  // amarelo
    [LED_STATE_ATTACK]    = {100, 0,   0},  // vermelho
};

static const char *STATE_NAMES[] = {
    "idle/blue", "connected/purple", "scan/white", "defense/yellow", "attack/red"
};

static led_strip_handle_t s_strip = NULL;
static led_state_t s_last_state = (led_state_t)-1;

static void apply_state(led_state_t state)
{
    if (!s_strip) return;
    if (state == s_last_state) return;
    led_strip_set_pixel(s_strip, 0,
                         COLORS[state][0], COLORS[state][1], COLORS[state][2]);
    led_strip_refresh(s_strip);
    ESP_LOGI(TAG, "state → %s", STATE_NAMES[state]);
    s_last_state = state;
}

static led_state_t compute_state(void)
{
    // ATTACK (vermelho) — prioridade máxima
    if (hacking_wifi_busy())              return LED_STATE_ATTACK;
    if (hacking_ble_busy())               return LED_STATE_ATTACK;
    if (evil_twin_busy())                 return LED_STATE_ATTACK;
    if (captive_portal_busy())            return LED_STATE_ATTACK;
    if (attack_lan_arp_cut_busy())        return LED_STATE_ATTACK;
    if (attack_lan_arp_throttle_busy())   return LED_STATE_ATTACK;

    // sniff_wifi modos ofensivos (karma sobe probe response forjado)
    sniff_mode_t sm = sniff_wifi_mode();
    if (sm == SNIFF_MODE_KARMA)           return LED_STATE_ATTACK;

    // DEFENSE (amarelo)
    if (watchdog_busy())                  return LED_STATE_DEFENSE;
    if (sm == SNIFF_MODE_DEFENSE)         return LED_STATE_DEFENSE;
    if (scan_ble_in_defense_mode())       return LED_STATE_DEFENSE;

    // SCAN (branco) — modos passivos de coleta
    if (sm == SNIFF_MODE_PROBE ||
        sm == SNIFF_MODE_EAPOL ||
        sm == SNIFF_MODE_PMKID ||
        sm == SNIFF_MODE_PCAP)            return LED_STATE_SCAN;
    if (scan_wifi_busy())                 return LED_STATE_SCAN;
    if (scan_ble_busy())                  return LED_STATE_SCAN;
    if (attack_lan_lan_scan_busy())       return LED_STATE_SCAN;

    // CONNECTED (roxo) — BLE pareado e subscribed
    if (transport_ble_is_connected())     return LED_STATE_CONNECTED;

    // Default: IDLE (azul)
    return LED_STATE_IDLE;
}

static void status_led_task(void *arg)
{
    (void)arg;
    while (1) {
        apply_state(compute_state());
        vTaskDelay(pdMS_TO_TICKS(LED_POLL_INTERVAL_MS));
    }
}

esp_err_t status_led_init(void)
{
    led_strip_config_t strip_cfg = {
        .strip_gpio_num = LED_GPIO,
        .max_leds = 1,
        .led_pixel_format = LED_PIXEL_FORMAT_GRB,
        .led_model = LED_MODEL_WS2812,
    };
    led_strip_rmt_config_t rmt_cfg = {
        .resolution_hz = 10 * 1000 * 1000, // 10 MHz
    };
    esp_err_t err = led_strip_new_rmt_device(&strip_cfg, &rmt_cfg, &s_strip);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "led_strip init rc=%s", esp_err_to_name(err));
        return err;
    }

    // Acende imediatamente em azul (idle) pra ter feedback visual de boot
    led_strip_set_pixel(s_strip, 0,
                         COLORS[LED_STATE_IDLE][0],
                         COLORS[LED_STATE_IDLE][1],
                         COLORS[LED_STATE_IDLE][2]);
    led_strip_refresh(s_strip);
    s_last_state = LED_STATE_IDLE;

    if (xTaskCreate(status_led_task, "status_led", 2560, NULL, 1, NULL) != pdPASS) {
        ESP_LOGE(TAG, "task create failed");
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "ready (GPIO %d, WS2812)", LED_GPIO);
    return ESP_OK;
}
