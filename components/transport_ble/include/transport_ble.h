#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

// Callback chamado quando o app envia um Write na characteristic cmd_ctrl.
// Os bytes apontados são válidos apenas durante a chamada (copiar se precisar).
typedef void (*transport_ble_cmd_handler_t)(const uint8_t *data, size_t len);

esp_err_t transport_ble_init(transport_ble_cmd_handler_t cmd_handler);

// Envia bytes via Notify na characteristic cmd_ctrl (usado pra responder
// comandos JSON). Falha silenciosamente se não houver cliente conectado
// ou ele não tiver assinado a notify (CCCD).
void transport_ble_send_cmd(const uint8_t *data, size_t len);

// Envia uma frame TLV completa via Notify na characteristic stream.
void transport_ble_send_stream(const uint8_t *data, size_t len);

// Reinicia o advertising do GATT (chamado por hacking_ble após spam).
// No-op se já estiver advertising ou se houver cliente conectado.
void transport_ble_advertising_resume(void);
