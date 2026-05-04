#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

esp_err_t hacking_wifi_init(void);

// Envia `count` frames deauth (subtype 0x0C). Frame source = ap_bssid,
// addr3 = ap_bssid, addr1 = target_mac (broadcast = ff:ff:...).
//
// Operação síncrona: bloqueia ~3ms × count na task chamadora. Pode ser
// chamada da task BLE (limitar count <= 200 pra não estourar timeout).
esp_err_t hacking_wifi_deauth(const uint8_t target_mac[6],
                              const uint8_t ap_bssid[6],
                              uint8_t channel,
                              uint16_t count,
                              uint16_t reason_code,
                              uint16_t *out_sent);

// Envia frames de beacon (subtype 0x08) com SSIDs falsos.
// Para cada cycle, percorre `ssids` em ordem; total de TX = cycles * ssid_count.
// BSSID é derivado de hash(ssid + index) com prefixo 02: (locally administered).
//
// Limites: ssid_count <= 32, cada SSID <= 32 bytes, cycles <= 200.
esp_err_t hacking_wifi_beacon_flood(uint8_t channel,
                                    uint16_t cycles,
                                    const char *const *ssids,
                                    size_t ssid_count,
                                    uint16_t *out_sent);
