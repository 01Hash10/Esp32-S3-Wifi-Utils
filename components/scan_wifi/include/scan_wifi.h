#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

// Callback usado para empurrar frames TLV pra fora do componente
// (tipicamente transport_ble_send_stream).
typedef void (*scan_wifi_emit_t)(const uint8_t *frame, size_t len);

esp_err_t scan_wifi_init(scan_wifi_emit_t emit);

// Dispara um scan ativo. É async: retorna imediatamente; resultados
// chegam via emit_t conforme o evento WIFI_EVENT_SCAN_DONE dispara.
//
// @return ESP_OK se o scan foi enfileirado, ESP_ERR_INVALID_STATE se já
// houver um scan em andamento.
esp_err_t scan_wifi_start_active(void);
