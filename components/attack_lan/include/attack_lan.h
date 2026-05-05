#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

esp_err_t attack_lan_init(void);

// Conecta como WiFi STA. Espera DHCP até timeout_ms; retorna ip/gw/mac do
// ESP em caso de sucesso.
esp_err_t attack_lan_wifi_connect(const char *ssid, const char *psk,
                                  uint16_t timeout_ms,
                                  uint8_t out_ip[4],
                                  uint8_t out_gw[4],
                                  uint8_t out_mac[6]);

esp_err_t attack_lan_wifi_disconnect(void);

bool attack_lan_is_connected(void);

// ARP cut: dispara task assíncrona que envia 2 ARP replies fake a cada
// interval_ms (poison vítima + poison gateway). Roda por duration_sec.
//
// O atacante (ESP) não encaminha o tráfego: lwIP recebe os pacotes
// destinados ao "gateway falsificado" e dropa por não ter o IP esperado
// → vítima fica sem internet (modo "drop").
//
// @return ESP_ERR_INVALID_STATE se outro cut em andamento ou sem WiFi.
esp_err_t attack_lan_arp_cut_start(const uint8_t target_ip[4],
                                   const uint8_t target_mac[6],
                                   const uint8_t gateway_ip[4],
                                   const uint8_t gateway_mac[6],
                                   uint16_t interval_ms,
                                   uint16_t duration_sec);

esp_err_t attack_lan_arp_cut_stop(void);

// LAN host discovery (ARP scan no /24 do IP atual). Dispara um ARP request
// pra cada IP de 1..254 (excluindo o ESP), aguarda `timeout_ms` pra replies
// populares o cache do lwIP, e emite TLV_MSG_LAN_HOST por host encontrado +
// TLV_MSG_LAN_SCAN_DONE ao final.
//
// Async (FreeRTOS task).
//
// @param timeout_ms 500–30000, default 3000.
// @return ESP_ERR_INVALID_STATE se já há lan_scan rodando, ou WiFi offline.
esp_err_t attack_lan_lan_scan_start(uint16_t timeout_ms);

bool attack_lan_lan_scan_busy(void);
