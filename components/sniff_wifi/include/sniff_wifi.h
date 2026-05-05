#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

esp_err_t sniff_wifi_init(void);

// Inicia sniffer de probe requests em modo promiscuous, com channel hopping
// no range [ch_min..ch_max] (1..13 cada) e dwell_ms por canal.
// Roda por duration_sec e encerra automaticamente — ou pode ser parado
// antes via sniff_wifi_probe_stop.
//
// Pré-requisito: ESP NÃO pode estar associado como STA (channel hopping
// vs AP fixo). O command_router checa isso e retorna erro `wifi_busy`.
//
// Async: emite TLV_MSG_PROBE_REQ por (mac, ssid) único (dedup interno
// até 256 entradas), depois TLV_MSG_PROBE_DONE ao final.
esp_err_t sniff_wifi_probe_start(uint8_t ch_min, uint8_t ch_max,
                                 uint16_t dwell_ms, uint16_t duration_sec);

esp_err_t sniff_wifi_probe_stop(void);

bool sniff_wifi_busy(void);
