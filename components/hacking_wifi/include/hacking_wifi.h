#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

esp_err_t hacking_wifi_init(void);

// Dispara `count` frames deauth (subtype 0x0C) em FreeRTOS task assíncrona.
// Frame source = ap_bssid, addr3 = ap_bssid, addr1 = target_mac (broadcast = ff:ff:...).
//
// Async: a função retorna assim que a task é criada. O resultado final
// (sent count, etc) é emitido como TLV_MSG_HACK_DEAUTH_DONE no `stream`
// quando a task termina.
//
// @return ESP_ERR_INVALID_STATE se outro deauth/beacon_flood ainda rodando,
//         ESP_ERR_NO_MEM se não conseguir criar task.
esp_err_t hacking_wifi_deauth(const uint8_t target_mac[6],
                              const uint8_t ap_bssid[6],
                              uint8_t channel,
                              uint16_t count,
                              uint16_t reason_code);

// Dispara frames de beacon (subtype 0x08) com SSIDs falsos em task assíncrona.
// Para cada cycle, percorre `ssids` em ordem; total de TX = cycles * ssid_count.
// BSSID é derivado de hash(ssid + index) com prefixo 02: (locally administered).
//
// `ssids` é copiado internamente — caller pode liberar após a chamada.
//
// Async: idem ao deauth, emite TLV_MSG_HACK_BEACON_DONE ao final.
//
// Limites: ssid_count <= 32, cada SSID <= 32 bytes, cycles <= 200.
esp_err_t hacking_wifi_beacon_flood(uint8_t channel,
                                    uint16_t cycles,
                                    const char *const *ssids,
                                    size_t ssid_count);

// Indica se há um job (deauth ou beacon_flood ou channel_jam) rodando agora.
bool hacking_wifi_busy(void);

// Channel jam: spam de RTS frames broadcast (FC=0xB4) com duration field
// alto, fazendo todas as STAs no canal respeitarem o NAV (Network
// Allocation Vector) e ficarem em silêncio. Resultado: airtime do canal
// fica monopolizado pelo ESP, vítimas não conseguem TX/RX.
//
// Async via FreeRTOS task. Emite TLV_MSG_HACK_JAM_DONE ao final.
//
// @param channel canal alvo (1–14)
// @param duration_sec 1..120 (limitado pra não esgotar bateria/aquecimento)
// @return ESP_ERR_INVALID_STATE se outro job de hacking_wifi rodando.
esp_err_t hacking_wifi_channel_jam(uint8_t channel, uint16_t duration_sec);

// Para um channel_jam em andamento (sinaliza stop pra task).
esp_err_t hacking_wifi_channel_jam_stop(void);
