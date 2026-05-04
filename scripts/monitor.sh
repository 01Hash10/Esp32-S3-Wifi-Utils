#!/usr/bin/env bash
# Lê o console do ESP32-S3 via USB-Serial-JTAG.
# Console roteada por CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y no sdkconfig.defaults.
#
# Uso:
#   ./scripts/monitor.sh             # streaming até Ctrl+C
#   DURATION=10 ./scripts/monitor.sh # captura por 10 segundos
set -euo pipefail

PORT="${PORT:-/dev/cu.usbmodem11201}"
BAUD="${BAUD:-115200}"
DURATION="${DURATION:-0}"  # 0 = infinito
PYTHON="$HOME/.platformio/penv/bin/python"

echo "→ Port: $PORT  Baud: $BAUD  Duration: ${DURATION}s (0=infinito)"
echo "→ Ctrl+C para sair"
echo

"$PYTHON" - <<PY
import serial, sys, time
s = serial.Serial("$PORT", $BAUD, timeout=1)
time.sleep(0.2)
s.setDTR(False); s.setRTS(False)
duration = $DURATION
deadline = (time.time() + duration) if duration > 0 else None
try:
    while deadline is None or time.time() < deadline:
        line = s.readline()
        if line:
            sys.stdout.write(line.decode("utf-8", errors="replace"))
            sys.stdout.flush()
except KeyboardInterrupt:
    pass
PY
