#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

// Callback usado para empurrar frames TLV pra fora do componente
// (tipicamente transport_ble_send_stream).
typedef void (*scan_wifi_emit_t)(const uint8_t *frame, size_t len);

esp_err_t scan_wifi_init(scan_wifi_emit_t emit);

typedef enum {
    SCAN_WIFI_MODE_ACTIVE  = 0,
    SCAN_WIFI_MODE_PASSIVE = 1,
} scan_wifi_mode_t;

// Dispara um scan WiFi. É async: retorna imediatamente; resultados chegam
// via emit_t conforme WIFI_EVENT_SCAN_DONE dispara.
//
// @param mode    ACTIVE = envia probe requests (rápido, mas anuncia presença);
//                PASSIVE = só escuta beacons (silencioso, demora mais).
// @param channel 0 = todos os canais; 1..13 = só esse canal.
// @return ESP_OK ok, ESP_ERR_INVALID_STATE se já houver scan em andamento.
esp_err_t scan_wifi_start(scan_wifi_mode_t mode, uint8_t channel);

// Atalho legacy: scan ativo, todos os canais.
esp_err_t scan_wifi_start_active(void);

// Indica se há scan WiFi rodando.
bool scan_wifi_busy(void);
