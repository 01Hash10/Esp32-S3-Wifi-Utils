#pragma once

#include "esp_err.h"

// LED RGB integrado (WS2812 no GPIO 48 do ESP32-S3-DevKitC-1).
// Indica visualmente o estado do firmware via cores:
//   azul    = boot OK, idle (sem cliente BLE)
//   roxo    = cliente BLE conectado e subscribed
//   branco  = método de scan ativo
//   amarelo = método de defesa ativo
//   vermelho = método de ataque ativo
//
// Prioridade (highest wins):
//   ATTACK > DEFENSE > SCAN > CONNECTED > IDLE
//
// Inicialização cria task de poll (~500ms) que verifica busy flags dos
// outros componentes e atualiza o LED. Sem latência humanamente perceptível.

esp_err_t status_led_init(void);
