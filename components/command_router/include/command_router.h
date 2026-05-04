#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

esp_err_t command_router_init(void);

// Handler para receber bytes JSON do app (vai pra transport_ble como
// callback de Write em cmd_ctrl).
void command_router_handle_json(const uint8_t *data, size_t len);
