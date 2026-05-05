#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

esp_err_t playbook_init(void);

// Roda um playbook (array JSON de steps). Retorna assim que a task é
// criada. Cada step emite TLV_MSG_PLAYBOOK_STEP_DONE conforme termina;
// fim do playbook emite TLV_MSG_PLAYBOOK_DONE.
//
// Step types suportados (v1):
//   - {"type":"cmd","cmd":"X","args":{...}}
//     Despacha "X" pelo command_router localmente. args é mergeado no JSON.
//   - {"type":"wait_ms","ms":N}
//   - {"type":"wait_event","tlv":N,"timeout_ms":M}
//     Aguarda TLV de msg_type N chegar (via hook em transport_ble) ou
//     timeout. Default timeout 30000.
//   - {"type":"set","name":"$var","value":"X"}
//     Armazena variável pra substituição em steps subsequentes.
//
// Variável: strings começando com "$" em qualquer arg são substituídas
// pela última value setada via "set" antes do step.
//
// Limites:
//   - 32 steps por playbook
//   - 8 variáveis simultâneas
//   - cada arg "value" até 64 chars (string ou número)
//
// @param steps_json string JSON com array de steps (ou objeto com `steps:[]`)
// @return ESP_ERR_INVALID_STATE se outro playbook rodando
esp_err_t playbook_run(const char *steps_json);

esp_err_t playbook_stop(void);

bool playbook_busy(void);
