#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

typedef void (*scan_ble_emit_t)(const uint8_t *frame, size_t len);

esp_err_t scan_ble_init(scan_ble_emit_t emit);

typedef enum {
    SCAN_BLE_MODE_PASSIVE = 0,  // só escuta adv
    SCAN_BLE_MODE_ACTIVE  = 1,  // envia scan request, captura scan response
} scan_ble_mode_t;

// Inicia discovery BLE. Resultados via emit. Dedup por MAC, max 64
// dispositivos únicos por scan.
//
// @param mode         PASSIVE = silencioso, só recebe adv;
//                     ACTIVE = envia scan request → recebe scan response
//                     (popula campos extras como nome completo).
// @param duration_sec 0 = roda até `scan_ble_stop`; >0 = duração fixa.
// @return ESP_OK iniciado, ESP_ERR_INVALID_STATE se outro scan rodando.
esp_err_t scan_ble_start_ex(scan_ble_mode_t mode, uint16_t duration_sec);

// Atalho legacy: scan passivo.
esp_err_t scan_ble_start(uint16_t duration_sec);

esp_err_t scan_ble_stop(void);

// BLE spam detector: roda scan passivo contínuo, classifica advs por
// assinatura vendor (Apple Continuity / Samsung EasySetup / Google Fast Pair)
// e detecta **rate-based**: muitos MACs únicos broadcasting mesma assinatura
// em janela curta = spam (atacante rotacionando MAC por payload).
//
// Threshold default: 6 MACs únicos/s por vendor (ambient real: 0–2).
// Cooldown de 3s por vendor pra não inundar app.
//
// @param duration_sec 0=até stop, 1..3600
//
// Emite TLV_MSG_DEFENSE_BLE_SPAM (0x35) por alerta. BLE_SCAN_DONE
// (0x13) ainda é emitido ao final.
esp_err_t scan_ble_defense_start(uint16_t duration_sec);

esp_err_t scan_ble_defense_stop(void);
