#pragma once

// Source of truth dos UUIDs do serviço GATT WifiUtils.
// Componentes que precisarem em formato stack-specific (bytes LE pro NimBLE,
// Guid no flutter_blue_plus, etc) constroem a partir destas strings.
//
// Ver INTEGRATION.md (seção "Identificação BLE") para o catálogo completo
// das characteristics.

#define WIFIUTILS_SVC_UUID_STR         "e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c01"
#define WIFIUTILS_CHR_CMD_UUID_STR     "e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c02"
#define WIFIUTILS_CHR_STREAM_UUID_STR  "e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c03"

#define WIFIUTILS_DEVICE_NAME_PREFIX   "WifiUtils-"
