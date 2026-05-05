#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

esp_err_t watchdog_init(void);

// Bitmask de contra-ações
#define WATCHDOG_ACTION_ANTI_EVIL_TWIN  0x01
#define WATCHDOG_ACTION_BLE_SPAM_JAM    0x02
// (anti_deauth não implementado — MAC spoofing torna direcionar contra-deauth
//  pro atacante real inviável; ver METHODS.md pra discussão.)
#define WATCHDOG_ACTION_ALL             0x03

// Habilita o watchdog. Deve ser chamado em conjunto com `defense_start`
// (WiFi) e/ou `ble_defense_start` (BLE) — esses comandos rodam os
// detectores; o watchdog gating decide quando disparar contra-ações.
//
// @param actions     bitmask WATCHDOG_ACTION_*
// @param whitelist   array de BSSIDs (n_whitelist entries × 6 bytes BE) que
//                    devem ser ignorados (não são alvo de contra-ação)
// @param n_whitelist tamanho do whitelist (max 16)
// @param cooldown_ms tempo mínimo entre 2 contra-ações do mesmo tipo
// @param max_actions cap total de contra-ações na sessão (default 5)
//
// @return ESP_ERR_INVALID_STATE se watchdog já ativo.
esp_err_t watchdog_start(uint8_t actions,
                         const uint8_t *whitelist, size_t n_whitelist,
                         uint32_t cooldown_ms,
                         uint16_t max_actions);

esp_err_t watchdog_stop(void);

bool watchdog_busy(void);

// ----------------------------------------------------------------------
// Hook API: chamado pelos detectores quando alertas cruzam threshold.
// Watchdog decide se dispara contra-ação (whitelist + cooldown + max).
// ----------------------------------------------------------------------

// Hook do evil_twin detector (sniff_wifi). `bssid_a` e `bssid_b` são os
// 2 BSSIDs do mesmo SSID; watchdog escolhe qual é o twin (heurística:
// locally-admin bit, ou o mais fraco de RSSI).
//
// `channel` = canal corrente do scan (pra deauth atingir o alvo).
void watchdog_hook_evil_twin(const uint8_t bssid_a[6], int8_t rssi_a,
                              const uint8_t bssid_b[6], int8_t rssi_b,
                              uint8_t channel);

// Hook do BLE spam detector (scan_ble).
void watchdog_hook_ble_spam(uint8_t vendor);
