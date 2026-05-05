#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

esp_err_t sniff_wifi_init(void);

// Modos de sniff suportados (apenas um pode rodar de cada vez).
typedef enum {
    SNIFF_MODE_IDLE  = 0,
    SNIFF_MODE_PROBE = 1,
    SNIFF_MODE_EAPOL = 2,
    SNIFF_MODE_PMKID = 3,
    SNIFF_MODE_PCAP  = 4,
} sniff_mode_t;

// Bitmask para filtro do pcap_start.
#define SNIFF_PCAP_FILTER_MGMT  0x01
#define SNIFF_PCAP_FILTER_DATA  0x02
#define SNIFF_PCAP_FILTER_CTRL  0x04
#define SNIFF_PCAP_FILTER_ALL   0x07

// Inicia sniffer de probe requests com channel hopping (1..13).
// Pré-requisito: ESP NÃO conectado como STA.
// Async: emite TLV_MSG_PROBE_REQ por (mac, ssid) único + PROBE_DONE.
esp_err_t sniff_wifi_probe_start(uint8_t ch_min, uint8_t ch_max,
                                 uint16_t dwell_ms, uint16_t duration_sec);

esp_err_t sniff_wifi_probe_stop(void);

// Inicia captura de EAPOL 4-way handshake num BSSID/canal específicos.
// Pré-requisito: ESP NÃO conectado como STA. Channel fixo (sem hop).
// Encerra automaticamente quando todos os 4 frames forem capturados ou
// duration_sec expirar. Async: emite TLV_MSG_WPA_EAPOL por frame
// EAPOL capturado + WPA_CAPTURE_DONE no final.
//
// Para forçar a re-handshake, o app pode disparar `deauth` (broadcast
// no mesmo BSSID) num cmd separado antes ou durante.
esp_err_t sniff_wifi_eapol_start(const uint8_t bssid[6], uint8_t channel,
                                  uint16_t duration_sec);

esp_err_t sniff_wifi_eapol_stop(void);

// Inicia captura de PMKID a partir de EAPOL-Key M1 (frame com ACK=1, MIC=0).
// Diferente do wpa_capture, só procura PMKID KDE (OUI 00:0F:AC, type 0x04)
// no Key Data do M1 — emite TLV_MSG_PMKID_FOUND compacto (28B) por captura
// + TLV_MSG_PMKID_DONE ao final. Pré-requisito: ESP NÃO conectado.
//
// PMKID hash format do hashcat: WPA*02*pmkid*ap*sta*essid (essid é
// fornecido pelo app — firmware não precisa).
esp_err_t sniff_wifi_pmkid_start(const uint8_t bssid[6], uint8_t channel,
                                  uint16_t duration_sec);

esp_err_t sniff_wifi_pmkid_stop(void);

// Inicia pcap streaming: captura frames 802.11 num canal fixo, filtra
// por tipo (mgmt/data/ctrl) e opcionalmente por BSSID, e emite TLVs
// PCAP_FRAME no `stream`. Sem storage local — frames vão direto pro app.
//
// Rate-limit interno (~5ms entre emits) evita saturar o BLE notify;
// frames acima do rate são contados como `frames_dropped` no DONE.
//
// @param channel canal fixo (1–13)
// @param filter  bitmask SNIFF_PCAP_FILTER_*; pelo menos 1 bit setado
// @param bssid   se != NULL, filtra frames cujo addr1/addr2/addr3 contenham
//                esse BSSID (útil pra escopo a uma rede só)
// @param duration_sec 1..300, default 60
esp_err_t sniff_wifi_pcap_start(uint8_t channel, uint8_t filter,
                                 const uint8_t *bssid,
                                 uint16_t duration_sec);

esp_err_t sniff_wifi_pcap_stop(void);

bool sniff_wifi_busy(void);
sniff_mode_t sniff_wifi_mode(void);
