#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

esp_err_t evil_twin_init(void);

// Sobe SoftAP fake (modo WIFI_MODE_APSTA) com SSID/canal/password
// configurável. DHCP server da IDF distribui IPs (default 192.168.4.x).
// Cada client que associa emite TLV_MSG_EVIL_CLIENT_JOIN; quando sai,
// EVIL_CLIENT_LEAVE.
//
// Pré-requisito: ESP NÃO conectado como STA (channel + AP em modos
// concorrentes). Caller deve chamar wifi_disconnect antes se necessário.
//
// @param ssid     SSID do AP fake (1..32 chars)
// @param psk      senha WPA2-PSK (8..63 chars), ou NULL/vazio = open
// @param channel  canal 1..13
// @param max_conn limite de clients (1..10)
//
// @return ESP_ERR_INVALID_STATE se já há AP rodando ou STA conectada.
esp_err_t evil_twin_start(const char *ssid, const char *psk,
                          uint8_t channel, uint8_t max_conn);

esp_err_t evil_twin_stop(void);

bool evil_twin_busy(void);
