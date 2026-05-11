# Esp32-S3-Wifi-Utils

[![ci](https://github.com/01Hash10/Esp32-S3-Wifi-Utils/actions/workflows/ci.yml/badge.svg)](https://github.com/01Hash10/Esp32-S3-Wifi-Utils/actions/workflows/ci.yml)

Ferramenta de pesquisa em segurança WiFi/Bluetooth para uso pessoal em
ambiente de laboratório controlado (apenas em redes próprias).

## ⚠️ Política de uso responsável

Este firmware contém features **ofensivas** que só são legais em:
1. **Hardware/redes de propriedade do operador**, OU
2. **Ambientes com autorização explícita por escrito** do dono da
   rede/device (pentest contratado, CTF, lab acadêmico).

**Uso fora desses cenários é ilegal** na maioria das jurisdições:
- Brasil: Lei 9.296/96 (interceptação de comunicações), Lei 12.737/12
  (Carolina Dieckmann)
- EU: GDPR + ePrivacy Directive
- US: Computer Fraud and Abuse Act (CFAA), Wiretap Act

### Checklist antes de testar

- [ ] Estou em rede/hardware que **eu controlo** OU tenho autorização
      escrita do dono?
- [ ] O ambiente RF está isolado (Hotspot pessoal, rede de lab) — sem
      vizinhos sendo afetados colateralmente?
- [ ] Vou parar os serviços ofensivos (`evil_twin_stop`,
      `captive_portal_stop`, `arp_cut_stop`) ao terminar?
- [ ] Documentei o teste (data, escopo, alvos)?

Em caso de dúvida sobre legalidade: **pergunte a um advogado**, não a
um chatbot. Ver `THREAT_MODEL.md` pra threat model completo +
discussão de mitigações.

## Hardware

- **Módulo**: ESP32-S3-WROOM-1 N16R8
- **Flash**: 16 MB QIO @ 80 MHz
- **PSRAM**: 8 MB Octal SPI @ 80 MHz (AP Memory gen3)
- **CPU**: 240 MHz dual-core Xtensa LX7
- **Antena**: PCB integrada
- **DevKit**: genérico USB-C (com chip CH343 defeituoso — flash via USB nativa)

## Stack

- PlatformIO + framework `espidf`
- ESP-IDF 5.1.2 (via `platform = espressif32 @ 6.5.0`). **Não atualizar
  sem ler `CLAUDE.md`**: o bypass de `ieee80211_raw_frame_sanity_check`
  necessário pra `deauth`/`beacon_flood`/`channel_jam` injetarem mgmt
  frames depende dessa versão (5.2+ adicionou filter mais cedo no TX path).
- esptool 5.2.0 (atualizada via pip — versão default 4.5.1 não funciona com este chip)
- Linguagem: C

## Estrutura

```
.
├── platformio.ini              # build config (overrides explícitos)
├── partitions.csv              # tabela 16MB: nvs + phy + 4MB app + ~12MB storage
├── sdkconfig.defaults          # fonte de verdade do Kconfig (PSRAM/CPU/flash/console)
├── CMakeLists.txt              # entry point IDF
├── scripts/
│   ├── flash.sh                # flash via USB-Serial-JTAG nativa (bypassa CH343)
│   └── monitor.sh              # leitura serial via pyserial
├── src/
│   ├── CMakeLists.txt
│   └── main.c                  # boot diag (SRAM/PSRAM)
├── include/
├── lib/
└── test/
```

> `sdkconfig.<env>` é gerado pelo build — **não editar à mão**. Sempre
> alterar `sdkconfig.defaults` e rebuildar.

## Workflow

### Conexão da placa

O DevKit tem **duas portas USB-C**. Devido a um chip CH343 defeituoso/com
firmware ruim, **use sempre a porta USB-Serial-JTAG nativa do S3**:

| Porta na placa | Aparece como | Uso |
|---|---|---|
| Lado oposto ao botão BOOT | `/dev/cu.usbmodem11201` (`USB JTAG_serial debug unit`) | **Use esta** |
| Lado do botão BOOT (CH343) | `/dev/cu.usbmodem59590728871` (`USB Single Serial`) | Não usar — corrupção em transferências sustentadas |

A porta nativa funciona com o driver Apple CDC e gerencia flash + console
sem CH343 envolvido.

### Build

```bash
pio run                # compila bootloader, partition table e firmware
```

### Flash

A USB-Serial-JTAG nativa não tem auto-reset confiável, então sempre faça a
sequência manual antes de flashar:

1. **Segure** o botão `BOOT` (`IO0`)
2. **Toque** rápido no botão `RESET` (`EN`/`RST`)
3. **Solte** `BOOT`

A placa entrou em download mode. Em seguida:

```bash
./scripts/flash.sh
```

Após o flash terminar, **toque uma vez no `RESET`** (sem segurar BOOT) pra
sair do download mode e bootar o firmware.

### Monitor

Console roteada por `CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y` — usa a mesma
porta USB nativa.

```bash
./scripts/monitor.sh                # streaming até Ctrl+C
DURATION=10 ./scripts/monitor.sh    # captura por 10 segundos
```

### Menuconfig

Pra alterar configs do IDF interativamente (mudanças vão pro `sdkconfig.<env>`,
não pro `defaults` — copie manualmente as linhas que quiser persistir):

```bash
pio run -t menuconfig
```

## Validação esperada do boot diag

Logs no monitor a cada 5s:

```
Free SRAM     : ~120 KB
Free PSRAM    : ~7.92 MB (≈ 8302984 bytes)
Total PSRAM   : 8370428 bytes
ESP-IDF       : 5.1.2
```

## Troubleshooting

### `Failed to write to target RAM (Checksum error)` no flash

Você está conectado na porta CH343 (`usbmodem59590728871`). Mude pra USB
nativa (`usbmodem11201`).

### `Hash of data verified` mas firmware não roda

esptool fez `hard_reset` mas chip ficou em download mode. Toque uma vez
no `RESET` (sem segurar BOOT).

### Porta `usbmodem11201` não aparece

A USB nativa do S3 só aparece quando o chip está alimentado E o firmware
ativou USB-Serial-JTAG (ou está em download mode pelo ROM). Se não
aparecer:

1. Verifique que está conectado na porta USB-C correta da placa
2. Coloque a placa em DL mode (BOOT+RESET) — força a porta a aparecer
   via ROM bootloader

### Build falha com `KeyError: 'version'` no codemodel

Cache do CMake corrompido. Solução: `rm -rf .pio/build && pio run`.

## Status

Firmware **maduro** — Phases 0–7 entregues. Restam apenas evoluções
incrementais (forwarding real pra MITM, agregação multi-scan tracker,
playbook step types `if`/`loop`).

Resumo:
- Phase 0–2: Foundation, BLE transport, scan WiFi/BLE — ✅
- Phase 3 + 3.5: ataques WiFi + macros + **playbook engine** — ✅ (Pixie Dust nativo blocked, MITM forwarding deferred)
- Phase 4: ataques BLE (Apple/Samsung/Google spam, adv flood) — ✅
- Phase 5: defense detectors (deauth/beacon flood/evil twin/karma/BLE spam) — ✅
- Phase 6: counter-measures (watchdog gating com whitelist + cooldown) — ✅
- Phase 7: persistence NVS + profiles — ✅ (OTA deferred)
- Phase 8: app Flutter — out of scope deste repo
- Phase 9: CI/CD + tests + threat model — ✅

## Documentação

| Arquivo | Para quê |
|---|---|
| [`ROADMAP.md`](ROADMAP.md) | Checklist de features + status por phase |
| [`INTEGRATION.md`](INTEGRATION.md) | Manual do app: protocolo BLE, comandos JSON, TLVs |
| [`METHODS.md`](METHODS.md) | Referência técnica: como cada método funciona internamente |
| [`COMPOSITION.md`](COMPOSITION.md) | Auditoria de exclusão entre componentes + matriz de paralelismo + macros |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Modelagem de ameaças do firmware + política de uso responsável |
| [`CLAUDE.md`](CLAUDE.md) | Guia pra contribuição + decisões de arquitetura

## Arquitetura (decisões fechadas)

- **Firmware**: ESP-IDF 5.1.2 puro, C (versão pinada por causa do bypass de mgmt frame injection — ver `CLAUDE.md`)
- **App**: Flutter (`flutter_blue_plus`)
- **Transporte**: BLE GATT
- **Protocolo híbrido**:
  - JSON minificado em `cmd_ctrl` (comandos pontuais)
  - TLV binário em `stream` (scan results, eventos, pcap)
