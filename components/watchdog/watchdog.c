#include "watchdog.h"
#include "tlv.h"
#include "transport_ble.h"
#include "hacking_wifi.h"
#include "hacking_ble.h"

#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"

static const char *TAG = "watchdog";

#define WHITELIST_MAX     16
#define ACTION_TYPES      2  // anti_evil_twin + ble_spam_jam (índices 0, 1)

static volatile bool s_active = false;
static uint8_t s_actions_mask = 0;
static uint8_t s_whitelist[WHITELIST_MAX][6];
static size_t s_whitelist_count = 0;
static uint32_t s_cooldown_ms = 10000;
static uint16_t s_max_actions = 5;

static int64_t s_last_action_us[ACTION_TYPES] = {0};
static volatile uint16_t s_actions_fired = 0;
static volatile uint16_t s_actions_blocked_whitelist = 0;
static volatile uint16_t s_actions_blocked_cooldown = 0;
static volatile uint16_t s_actions_blocked_cap = 0;
static int64_t s_started_us = 0;
static uint8_t s_seq = 0;

bool watchdog_busy(void) { return s_active; }

esp_err_t watchdog_init(void)
{
    ESP_LOGI(TAG, "ready");
    return ESP_OK;
}

static bool in_whitelist(const uint8_t bssid[6])
{
    for (size_t i = 0; i < s_whitelist_count; i++) {
        if (memcmp(s_whitelist[i], bssid, 6) == 0) return true;
    }
    return false;
}

static void emit_watchdog_action(uint8_t action, const uint8_t target[6],
                                  uint8_t status)
{
    uint8_t payload[8];
    payload[0] = action;
    memcpy(&payload[1], target, 6);
    payload[7] = status;

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_WATCHDOG_ACTION, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

static void emit_watchdog_done(uint32_t elapsed_ms, uint8_t status)
{
    uint8_t payload[12];
    payload[0]  = (uint8_t)(s_actions_fired >> 8);
    payload[1]  = (uint8_t)(s_actions_fired & 0xFF);
    payload[2]  = (uint8_t)(s_actions_blocked_whitelist >> 8);
    payload[3]  = (uint8_t)(s_actions_blocked_whitelist & 0xFF);
    payload[4]  = (uint8_t)(s_actions_blocked_cooldown >> 8);
    payload[5]  = (uint8_t)(s_actions_blocked_cooldown & 0xFF);
    payload[6]  = (uint8_t)(s_actions_blocked_cap >> 8);
    payload[7]  = (uint8_t)(s_actions_blocked_cap & 0xFF);
    payload[8]  = (uint8_t)(elapsed_ms >> 24);
    payload[9]  = (uint8_t)(elapsed_ms >> 16);
    payload[10] = (uint8_t)(elapsed_ms >> 8);
    payload[11] = (uint8_t)(elapsed_ms & 0xFF);
    (void)status;

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_WATCHDOG_DONE, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

// Verifica se contra-ação action_idx está autorizada (cooldown + cap +
// whitelist no caller). Atualiza timestamp se autorizado.
static bool action_authorized(int action_idx)
{
    if (s_actions_fired >= s_max_actions) {
        s_actions_blocked_cap++;
        return false;
    }
    int64_t now = esp_timer_get_time();
    if (now - s_last_action_us[action_idx] < (int64_t)s_cooldown_ms * 1000) {
        s_actions_blocked_cooldown++;
        return false;
    }
    s_last_action_us[action_idx] = now;
    return true;
}

// ----------------------------------------------------------------------
// Hook: evil_twin alert
// ----------------------------------------------------------------------
void watchdog_hook_evil_twin(const uint8_t bssid_a[6], int8_t rssi_a,
                              const uint8_t bssid_b[6], int8_t rssi_b,
                              uint8_t channel)
{
    if (!s_active) return;
    if (!(s_actions_mask & WATCHDOG_ACTION_ANTI_EVIL_TWIN)) return;

    // Heurística: o BSSID "twin" é o de bit locally-admin (0x02) OU,
    // sem isso, o mais fraco (provável fake mais distante).
    const uint8_t *target;
    bool a_la = (bssid_a[0] & 0x02) != 0;
    bool b_la = (bssid_b[0] & 0x02) != 0;
    if (a_la && !b_la) target = bssid_a;
    else if (b_la && !a_la) target = bssid_b;
    else target = (rssi_a < rssi_b) ? bssid_a : bssid_b;

    if (in_whitelist(target)) {
        s_actions_blocked_whitelist++;
        return;
    }
    if (!action_authorized(0)) return;

    // Fire deauth(broadcast) at the twin BSSID. hacking_wifi gerencia
    // sua própria task assíncrona — não bloqueia.
    uint8_t broadcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    esp_err_t err = hacking_wifi_deauth(broadcast, target, channel, 30, 7);
    uint8_t status = (err == ESP_OK) ? 0 : 1;
    if (err == ESP_OK) {
        s_actions_fired++;
        ESP_LOGW(TAG, "anti_evil_twin: deauth at %02x:%02x:%02x:%02x:%02x:%02x ch=%u",
                 target[0],target[1],target[2],target[3],target[4],target[5],channel);
    } else {
        ESP_LOGW(TAG, "anti_evil_twin failed: %s", esp_err_to_name(err));
    }
    emit_watchdog_action(WATCHDOG_ACTION_ANTI_EVIL_TWIN, target, status);
}

// ----------------------------------------------------------------------
// Hook: BLE spam alert
// ----------------------------------------------------------------------
void watchdog_hook_ble_spam(uint8_t vendor)
{
    if (!s_active) return;
    if (!(s_actions_mask & WATCHDOG_ACTION_BLE_SPAM_JAM)) return;
    if (!action_authorized(1)) return;

    // Fire BLE adv flood por 5s — congestiona o canal pra dificultar
    // atacante continuar emitindo. hacking_ble gerencia sua própria task.
    esp_err_t err = hacking_ble_adv_flood(5);
    uint8_t status = (err == ESP_OK) ? 0 : 1;
    uint8_t target[6] = {vendor, 0, 0, 0, 0, 0}; // sem MAC do atacante (BLE rotaciona)
    if (err == ESP_OK) {
        s_actions_fired++;
        ESP_LOGW(TAG, "ble_spam_jam fired vs vendor=%u", vendor);
    } else {
        ESP_LOGW(TAG, "ble_spam_jam failed: %s", esp_err_to_name(err));
    }
    emit_watchdog_action(WATCHDOG_ACTION_BLE_SPAM_JAM, target, status);
}

// ----------------------------------------------------------------------
// API
// ----------------------------------------------------------------------
esp_err_t watchdog_start(uint8_t actions,
                         const uint8_t *whitelist, size_t n_whitelist,
                         uint32_t cooldown_ms,
                         uint16_t max_actions)
{
    if (s_active) return ESP_ERR_INVALID_STATE;
    if ((actions & WATCHDOG_ACTION_ALL) == 0) return ESP_ERR_INVALID_ARG;
    if (n_whitelist > WHITELIST_MAX) return ESP_ERR_INVALID_ARG;

    s_actions_mask = actions & WATCHDOG_ACTION_ALL;
    s_cooldown_ms = (cooldown_ms == 0) ? 10000 : cooldown_ms;
    s_max_actions = (max_actions == 0) ? 5 : max_actions;

    if (whitelist && n_whitelist) {
        memcpy(s_whitelist, whitelist, n_whitelist * 6);
    }
    s_whitelist_count = n_whitelist;

    s_actions_fired = 0;
    s_actions_blocked_whitelist = 0;
    s_actions_blocked_cooldown = 0;
    s_actions_blocked_cap = 0;
    memset(s_last_action_us, 0, sizeof(s_last_action_us));
    s_started_us = esp_timer_get_time();
    s_active = true;

    ESP_LOGI(TAG, "started: actions=0x%02x whitelist=%u cooldown=%lums max=%u",
             actions, (unsigned)n_whitelist,
             (unsigned long)s_cooldown_ms, (unsigned)s_max_actions);
    return ESP_OK;
}

esp_err_t watchdog_stop(void)
{
    if (!s_active) return ESP_ERR_INVALID_STATE;
    s_active = false;
    uint32_t elapsed = (uint32_t)((esp_timer_get_time() - s_started_us) / 1000);
    emit_watchdog_done(elapsed, 0);
    ESP_LOGI(TAG, "stopped: fired=%u blocked_wl=%u blocked_cd=%u blocked_cap=%u",
             (unsigned)s_actions_fired,
             (unsigned)s_actions_blocked_whitelist,
             (unsigned)s_actions_blocked_cooldown,
             (unsigned)s_actions_blocked_cap);
    return ESP_OK;
}
