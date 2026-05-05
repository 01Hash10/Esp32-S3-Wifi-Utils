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

// Deauth storm: combina deauth (rajada inicial) + RTS jam (alternados
// com mais deauths) num único job. Compartilha s_busy com deauth/jam/
// beacon_flood — usa a mesma task pra evitar race no set_channel.
//
// Pipeline:
//   1. set_channel(channel)
//   2. burst inicial de `deauth_count` deauth frames (~3ms cada)
//   3. loop até deadline: 30 RTS frames (jam, ~25ms cada) + 5 deauths
//
// @param deauth_count rajada inicial (10..500, default 50)
// @param jam_seconds  duração total do jam pós-burst (5..60, default 15)
esp_err_t hacking_wifi_deauth_storm(const uint8_t target_mac[6],
                                     const uint8_t ap_bssid[6],
                                     uint8_t channel,
                                     uint16_t deauth_count,
                                     uint16_t jam_seconds);

// Testa 1 PIN WPS contra um BSSID. Usa o supplicant WPS do IDF em modo
// enrollee; se PIN é válido + AP suporta, recupera PSK e SSID.
//
// Limitações: API do IDF não expõe o M2 cru, então **Pixie Dust offline
// não é viável** com este firmware (precisa sniffar troca WPS de outro
// device com `pcap_start` e processar offline com `pixiewps`). Esta
// primitiva é a base pra brute-force lado-app ou validação de PIN
// descoberto externamente.
//
// Pré-requisito: ESP NÃO conectado como STA.
//
// Async: emite TLV_MSG_WPS_TEST_DONE ao final com status + (se sucesso)
// SSID + PSK.
//
// @param bssid     BSSID alvo
// @param pin       string de 8 dígitos (formato "12345670")
// @param timeout_sec timeout total da tentativa (15..120, default 60)
esp_err_t hacking_wifi_wps_pin_test(const uint8_t bssid[6],
                                    const char *pin,
                                    uint16_t timeout_sec);
