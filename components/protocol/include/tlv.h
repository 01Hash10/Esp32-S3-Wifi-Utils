#pragma once

#include <stddef.h>
#include <stdint.h>

// Frame TLV usado na characteristic `stream` (alta frequência, binário):
//   [u16 length BE] [u8 type] [u8 seq] [payload...]
//
// length = 2 (type + seq) + payload_len, em bytes.
// Total da frame = 2 + length.

#define TLV_HEADER_SIZE        4u    // 2 length + 1 type + 1 seq
#define TLV_MAX_FRAME_SIZE     247u  // limite alinhado ao MTU BLE preferido
#define TLV_MAX_PAYLOAD_SIZE   (TLV_MAX_FRAME_SIZE - TLV_HEADER_SIZE)

// Faixas reservadas (ver INTEGRATION.md)
//   0x00–0x0F  control / sistema
//   0x10–0x1F  scan results
//   0x20–0x2F  hacking events
//   0x30–0x3F  defense events
//   0x40–0x4F  captura / dados
//   0x50–0xFF  reservado
typedef enum {
    // Control / sistema (0x00–0x0F)
    TLV_MSG_HEARTBEAT       = 0x00,

    // Scan results (0x10–0x1F)
    TLV_MSG_WIFI_SCAN_AP    = 0x10,
    TLV_MSG_WIFI_SCAN_DONE  = 0x11,
    TLV_MSG_BLE_SCAN_DEV    = 0x12,
    TLV_MSG_BLE_SCAN_DONE   = 0x13,
    TLV_MSG_LAN_HOST        = 0x14,
    TLV_MSG_LAN_SCAN_DONE   = 0x15,
    TLV_MSG_PROBE_REQ       = 0x16,
    TLV_MSG_PROBE_DONE      = 0x17,
    TLV_MSG_WPA_EAPOL       = 0x18,
    TLV_MSG_WPA_CAPTURE_DONE = 0x19,
    TLV_MSG_PMKID_FOUND     = 0x1A,
    TLV_MSG_PMKID_DONE      = 0x1B,

    // Hacking events (0x20–0x2F): emitidos ao final de um job assíncrono
    // disparado por deauth / beacon_flood / ble_spam_apple.
    TLV_MSG_HACK_DEAUTH_DONE   = 0x20,
    TLV_MSG_HACK_BEACON_DONE   = 0x21,
    TLV_MSG_HACK_BLE_SPAM_DONE = 0x22,
    TLV_MSG_HACK_JAM_DONE      = 0x23,
    TLV_MSG_KARMA_HIT          = 0x24,
    TLV_MSG_KARMA_DONE         = 0x25,
    TLV_MSG_EVIL_CLIENT_JOIN   = 0x26,
    TLV_MSG_EVIL_CLIENT_LEAVE  = 0x27,

    // Captura/dados (0x40–0x4F): streaming de pcap chunks.
    TLV_MSG_PCAP_FRAME         = 0x40,
    TLV_MSG_PCAP_DONE          = 0x41,
    // demais tipos serão adicionados conforme features são entregues.
} tlv_msg_type_t;

/**
 * Encode a TLV frame em out_buf.
 *
 * @return >0 = total frame size em bytes (gravado no início de out_buf);
 *         -1 = out_buf_cap insuficiente;
 *         -2 = payload muito grande (> TLV_MAX_PAYLOAD_SIZE).
 */
int tlv_encode(uint8_t *out_buf, size_t out_buf_cap,
               uint8_t type, uint8_t seq,
               const void *payload, size_t payload_len);

/**
 * Decode uma frame TLV de in_buf. Zero-copy: out_payload aponta pra
 * dentro de in_buf.
 *
 * @return 0 ok, -1 frame muito pequena, -2 inconsistência de length.
 */
int tlv_decode(const uint8_t *in_buf, size_t in_buf_len,
               uint8_t *out_type, uint8_t *out_seq,
               const uint8_t **out_payload, size_t *out_payload_len);
