#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

esp_err_t hacking_ble_init(void);

// Apple Continuity Proximity Pairing spam (async).
// Cada cycle = payload aleatório dentre uma lista de devices (AirPods,
// AirPods Pro, AirPods Max, Beats Solo3, AirPods Pro 2). Pausa o
// advertising do GATT durante a operação e retoma ao final.
//
// Retorna assim que a task é criada. O resultado final é emitido como
// TLV_MSG_HACK_BLE_SPAM_DONE no `stream` quando termina.
//
// @param cycles 1..500, cada cycle dura ~100ms.
// @return ESP_ERR_INVALID_STATE se outro spam estiver rodando,
//         ESP_ERR_NO_MEM se não conseguir criar task.
esp_err_t hacking_ble_apple_spam(uint16_t cycles);

bool hacking_ble_busy(void);
