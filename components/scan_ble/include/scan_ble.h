#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

typedef void (*scan_ble_emit_t)(const uint8_t *frame, size_t len);

esp_err_t scan_ble_init(scan_ble_emit_t emit);

// Inicia discovery passivo. Resultados via emit. Dedup por MAC, max
// 64 dispositivos únicos por scan.
//
// @param duration_sec 0 = passivo até `scan_ble_stop`; >0 = duração fixa
// @return ESP_OK iniciado, ESP_ERR_INVALID_STATE se outro scan rodando.
esp_err_t scan_ble_start(uint16_t duration_sec);

esp_err_t scan_ble_stop(void);
