# Esp32-S3-Wifi-Utils — guia para Claude Code

Projeto ESP-IDF puro (sem Arduino) para ESP32-S3-WROOM-1 N16R8. Pesquisa
de segurança WiFi/BT em laboratório controlado.

## Hardware/build essentials

- **Plataforma**: `platform = espressif32 @ 6.5.0` (pinada — **não atualizar**).
  Downgrade obrigatório a partir do commit `028e2e2`: IDF 5.2+ adicionou um
  filter `unsupport frame type 0c0` ANTES da função
  `ieee80211_raw_frame_sanity_check` que bypassamos via `--weaken-symbol`
  (`components/hacking_wifi/wsl_bypasser.c`). Sem esse downgrade, `deauth`
  / `beacon_flood` / `channel_jam` / `deauth_storm` **silenciosamente não
  injetam mgmt frames** (TX retorna ESP_OK, frame não vai pro ar).
- **Framework**: `espidf` (ESP-IDF 5.1.2). NUNCA misturar Arduino.
- **Linguagem**: C
- **Toolchain `pio`**: `~/.platformio/penv/bin/pio` (também no PATH via `~/.zshrc`)
- **esptool**: 5.2.0 (instalada no venv via `pip install --upgrade esptool`).
  A versão default 4.5.1 do PlatformIO **não funciona** com este chip — usar
  sempre o caminho via `scripts/flash.sh`.
- **Patch binário pendente** (não automatizado, refazer ao trocar de máquina):
  `~/.platformio/packages/framework-espidf@3.50102.240122/components/esp_wifi/lib/esp32s3/libnet80211.a`
  — função `ieee80211_raw_frame_sanity_check` modificada pra `return 0`
  (4 bytes em offset 0x2a0f de `ieee80211_output.o`: `movi.n a2,0; retw.n`).
  Backup em `libnet80211.a.bak`. Ver comentário em `platformio.ini`.

## Fonte de verdade do Kconfig

- **`sdkconfig.defaults`** = fonte de verdade. Editar aqui.
- **`sdkconfig.esp32-s3-devkitc-1`** = gerado pelo build, **não editar**, está no `.gitignore`.
- Após mudar `sdkconfig.defaults`: `rm sdkconfig.esp32-s3-devkitc-1 && pio run` para forçar regen limpa.
- Configs críticas que NÃO podem regredir:
  - `CONFIG_SPIRAM_MODE_OCT=y` + `CONFIG_SPIRAM_SPEED_80M=y` (PSRAM N16R8)
  - `CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y` + `CONFIG_ESPTOOLPY_FLASHMODE_QIO=y`
  - `CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=240`
  - `CONFIG_PARTITION_TABLE_CUSTOM=y` (usa `partitions.csv`)
  - `# CONFIG_ESP_CONSOLE_UART_DEFAULT is not set` + `CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y`

## Quirk crítico: flash NÃO funciona via PlatformIO `pio run -t upload`

Este DevKit chinês tem um chip USB-Serial **CH343 defeituoso** (idVendor 0x1A86)
que corrompe transferências sustentadas (`Failed to write to target RAM (Checksum error)`).
A porta UART (`/dev/cu.usbmodem59590728871` quando aparece) **não deve ser usada**.

**Sempre usar a porta USB-Serial-JTAG nativa do S3** (`/dev/cu.usbmodem11201`,
`USB JTAG_serial debug unit`):

1. Build: `pio run`
2. Coloca em DL mode: segura BOOT, toca RESET, solta BOOT
3. Flash: `./scripts/flash.sh` (não `pio run -t upload`)
4. Após flash terminar, **toca RESET** (sem BOOT) pra sair do DL mode e bootar
5. Monitor: `./scripts/monitor.sh` (também `DURATION=10 ./scripts/monitor.sh`)

Não usar `pio device monitor` em shell não-interativo (precisa TTY).
Usar `monitor.sh` (pyserial direto).

## Estrutura

```
.
├── platformio.ini          # overrides: 16MB, QIO, 240MHz, partitions.csv
├── partitions.csv          # 16MB: nvs + phy + 4MB factory + ~12MB storage
├── sdkconfig.defaults      # fonte de verdade do Kconfig
├── CMakeLists.txt
├── scripts/
│   ├── flash.sh            # esptool 5.2 via USB-Serial-JTAG (PORT/BAUD overridable via env)
│   └── monitor.sh          # pyserial (DURATION=N opcional)
├── src/
│   ├── CMakeLists.txt      # GLOB src/*.* — adicionar arquivos novos é automático
│   └── main.c              # boot diag (SRAM/PSRAM heap_caps)
├── include/  lib/  test/   # placeholders padrão IDF/PlatformIO
```

## Decisões de arquitetura (fechadas)

- **App**: Flutter + `flutter_blue_plus`
- **Transporte**: BLE GATT (custom service, NUS-style)
- **Protocolo híbrido**:
  - `cmd_ctrl` characteristic (Write+Notify) → **JSON minificado**
    (comandos, ack/err, status — baixa frequência)
  - `stream` characteristic (Notify) → **TLV binário** (scan results,
    eventos defense, pcap chunks — alta frequência)
- **Frame TLV**: `[u16 length BE][u8 msg_type][u8 seq][payload]`
- **Roadmap**: `ROADMAP.md` é a fonte de verdade do que está feito vs
  pendente. Checklist por fase. Atualizar ao concluir cada item.
- **Manual de integração mobile**: `INTEGRATION.md` é a documentação viva
  de **como o app Flutter deve conversar com o firmware**. Contém:
  UUIDs, schemas de comandos JSON, msg_types TLV, fluxos de pareamento,
  exemplos de código Dart, diagramas de sequência quando relevante.

  **Regra obrigatória**: toda feature nova que altera ou adiciona algo ao
  protocolo BLE (novo comando, novo msg_type, novo characteristic, mudança
  de schema) **DEVE** ser documentada em `INTEGRATION.md` no mesmo commit
  que adiciona o código no firmware. Sem documentação ↔ feature incompleta.
  Aplicar isso desde a Phase 1 e por todo o resto do desenvolvimento.

- **Manual técnico / estudo**: `METHODS.md` é a documentação viva de
  **o que cada método faz, como faz e o fluxo dos dados**. Foco em
  teoria (RFC / 802.11 / BLE), implementação interna e diagrama textual
  do fluxo App ↔ ESP ↔ ar.

  **Regra obrigatória**: toda feature nova **DEVE** ter sua entrada em
  `METHODS.md` no mesmo commit que a implementa, no formato:
  O que faz / Como funciona / Implementação / Fluxo / Limitações.
  Sem entrada lá ↔ feature incompleta.

- **Composição & orquestração**: `COMPOSITION.md` documenta combinações
  entre features, matriz de compatibilidade (o que roda em paralelo) e
  o catálogo de macros / playbook da Phase 3.5.

  **Regra obrigatória**: toda macro nova ou mudança em exclusão
  mútua entre componentes (`s_busy`, `s_mode`, etc) **DEVE** atualizar
  `COMPOSITION.md` no mesmo commit.

## Convenções

- Sem comentários narrativos no código (manter `main.c` enxuto).
- Sem libs externas nessa fase — só ESP-IDF puro.
- Logs via `ESP_LOGI(TAG, ...)` em C, nunca `printf`.
- Para novos componentes: criar diretório em `components/<nome>/` com seu
  próprio `CMakeLists.txt`, IDF detecta automaticamente.

## Restrições do usuário

- NÃO rodar comandos destrutivos (rm, format, git reset --hard, force-push)
  sem confirmação explícita.
- NÃO sugerir Arduino framework.
- NÃO criar arquivos novos sem perguntar antes (exceto quando o usuário
  pedir explicitamente).
- Mostrar comandos longos antes de executar.
- Para mudanças de config críticas (sdkconfig, platformio.ini, partitions),
  sempre mostrar o diff antes.

## Validação esperada após flash

`./scripts/monitor.sh` deve mostrar a cada 5s:
- `Free SRAM: ~120 KB` (range observado em 5.1.2 com todos componentes ativos)
- `Free PSRAM: ~7.92 MB` (≈ 8302984 bytes)
- `Total PSRAM: 8370428 bytes`
- `ESP-IDF: 5.1.2`

Se PSRAM = 0 → conferir `CONFIG_SPIRAM_MODE_OCT` no `sdkconfig.<env>` gerado;
se não bater, regenerar (`rm sdkconfig.<env> && pio run`).

## Mgmt frame injection (deauth/beacon/jam/storm)

Stack inteira depende de 3 peças que **devem ficar sincronizadas**:

1. **IDF pinada em 5.1.2** (acima) — sem isso o filter de 5.2+ dropa
   mgmt frames antes da função wrappada.
2. **`wsl_bypasser.c`** + flag `-Wl,--weaken-symbol=ieee80211_raw_frame_sanity_check`
   em `platformio.ini > build_flags` — substitui a função do `libnet80211.a`
   pela nossa que retorna 0.
3. **`inject_begin()` / `inject_end()`** em `hacking_wifi.c` — liga
   promiscuous antes do TX (o driver só aceita raw mgmt em modo raw) e
   troca canal. `inject_end()` **desliga promiscuous** ao terminar —
   isso é incompatível com `sniff_wifi`/`defense_start` rodando em
   paralelo no mesmo timeframe; ver `COMPOSITION.md` seção 5.
