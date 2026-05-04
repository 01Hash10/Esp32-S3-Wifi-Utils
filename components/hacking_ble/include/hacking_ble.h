#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

esp_err_t hacking_ble_init(void);

// Apple Continuity Proximity Pairing spam:
// Cada cycle = MAC random + payload aleatório dentre uma lista de devices
// (AirPods, AirPods Pro, AirPods Max, Beats Solo3). Pausa o advertising
// do GATT durante a operação e retoma ao final.
//
// @param cycles 1..500, cada cycle dura ~100ms.
// @return ESP_ERR_INVALID_STATE se outro spam estiver rodando.
esp_err_t hacking_ble_apple_spam(uint16_t cycles, uint16_t *out_sent);
