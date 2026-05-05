#!/usr/bin/env bash
# Flash ESP32-S3 via ROM bootloader (sem stub, sem compressão).
# Workaround pra placa rev v0.2 onde stub upload falha em "Failed to write to target RAM".
#
# Uso:
#   1. Coloque a placa em download mode: segure BOOT, toque RESET, solte BOOT.
#   2. Rode: ./scripts/flash.sh
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/.pio/build/esp32-s3-devkitc-1"
PORT="${PORT:-/dev/cu.usbmodem11201}"
BAUD="${BAUD:-115200}"
ESPTOOL="$HOME/.platformio/penv/bin/esptool.py"

echo "→ Port: $PORT"
echo "→ Baud: $BAUD"
echo "→ Build dir: $BUILD_DIR"
echo

# Nota: --flash_mode dio é INTENCIONAL aqui, mesmo com sdkconfig configurado
# em QIO. O esptool reescreve apenas o header do bootloader.bin (pra que o
# ROM bootloader inicialize a flash em DIO no primeiro boot); o firmware em
# si continua compilado pra QIO via Kconfig e o IDF faz o switch durante o
# init. Esse workaround é necessário pra esta DevKit chinesa rev v0.2 onde
# o init em QIO direto pelo ROM falha. NÃO trocar pra qio aqui.
"$ESPTOOL" \
    --chip esp32s3 \
    --port "$PORT" \
    --baud "$BAUD" \
    --before no_reset \
    --after hard_reset \
    --no-stub \
    write_flash \
    --flash_mode dio \
    --flash_freq 80m \
    --flash_size 16MB \
    --no-compress \
    0x0     "$BUILD_DIR/bootloader.bin" \
    0x8000  "$BUILD_DIR/partitions.bin" \
    0x10000 "$BUILD_DIR/firmware.bin"
