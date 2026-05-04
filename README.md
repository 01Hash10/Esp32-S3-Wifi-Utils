# Esp32-S3-Wifi-Utils

Ferramenta de pesquisa em segurança WiFi/Bluetooth para uso pessoal em
ambiente de laboratório controlado (apenas em redes próprias).

> **Aviso legal**: este projeto destina-se exclusivamente a pesquisa de
> segurança autorizada e fins educacionais em hardware/redes próprias.
> O uso em redes ou dispositivos sem autorização explícita do proprietário
> é ilegal na maioria das jurisdições.

## Hardware

- **Módulo**: ESP32-S3-WROOM-1 N16R8
- **Flash**: 16 MB QIO @ 80 MHz
- **PSRAM**: 8 MB Octal SPI @ 80 MHz (AP Memory gen3)
- **CPU**: 240 MHz dual-core Xtensa LX7
- **Antena**: PCB integrada
- **DevKit**: genérico USB-C (com chip CH343 defeituoso — flash via USB nativa)

## Stack

- PlatformIO + framework `espidf`
- ESP-IDF 5.4.0 (via `platform = espressif32 @ 6.10.0`)
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
Free SRAM     : ~332 KB (320-340 KB)
Free PSRAM    : ~8.00 MB
Total PSRAM   : 8388608 bytes
ESP-IDF       : 5.4.0
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

- [x] Setup inicial do projeto
- [x] Configuração de PSRAM Octal + 16MB flash
- [x] Diagnóstico de boot (SRAM/PSRAM)
- [x] Workflow de flash via USB-Serial-JTAG
- [ ] WiFi scan (próximo)
- [ ] Bluetooth scan
- [ ] (demais features a definir)

## Roadmap

A definir conforme progresso.
