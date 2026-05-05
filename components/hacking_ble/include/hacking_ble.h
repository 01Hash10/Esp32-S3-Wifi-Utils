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

// Vendor identificadores no payload do TLV HACK_BLE_SPAM_DONE (offset 4):
//   0 = Apple, 1 = Samsung, 2 = Google, 0xFF = multi-vendor random
typedef enum {
    BLE_SPAM_VENDOR_APPLE   = 0,
    BLE_SPAM_VENDOR_SAMSUNG = 1,
    BLE_SPAM_VENDOR_GOOGLE  = 2,
    BLE_SPAM_VENDOR_MULTI   = 0xFF,
} ble_spam_vendor_t;

// Samsung EasySetup spam (Manufacturer Data 0x0075).
// Gera popup de "Galaxy Buds próximos" em Samsung phones.
esp_err_t hacking_ble_samsung_spam(uint16_t cycles);

// Google Fast Pair spam (Service Data UUID 0xFE2C).
// Gera popup "Pixel Buds detected" em Android phones com Fast Pair.
esp_err_t hacking_ble_google_spam(uint16_t cycles);

// Multi-vendor spam: cada cycle escolhe Apple/Samsung/Google aleatoriamente.
// Cobre o máximo de vítimas em volta com 1 só comando.
esp_err_t hacking_ble_multi_spam(uint16_t cycles);

// BLE adv flood — DoS via channel congestion. Loop tight de adv com
// payload aleatório + interval mínimo (20ms). Diferente dos spam_*
// (que tentam triggerar popups específicos), este é puro flood — mata
// detectabilidade no canal pra outros devices BLE.
//
// Async, pausa GATT adv durante a sessão, retoma ao final.
//
// @param duration_sec 1..60 (cap pra não esquentar a placa)
// @return ESP_ERR_INVALID_STATE se outro spam/flood ainda rodando.
esp_err_t hacking_ble_adv_flood(uint16_t duration_sec);

bool hacking_ble_busy(void);
