#!/usr/bin/env python3
"""
Spam de Apple Continuity (Proximity Pairing) — gera popup de pareamento
de AirPods/Beats em iPhones próximos.

Uso:
    ~/.platformio/penv/bin/python scripts/ble_spam_test.py [--cycles 50]
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
        await client.start_notify(
            CMD_UUID,
            lambda h, d: print(f"← {d.decode('utf-8', errors='replace')}"),
        )
        cmd = {"cmd": "ble_spam_apple", "seq": 1, "cycles": args.cycles}
        payload = json.dumps(cmd)
        print(f"→ {payload}")
        print(f"→ duração estimada: {args.cycles * 0.1:.1f}s")
        print(f"→ aproxime um iPhone/iPad próximo da placa pra ver os popups")
        await client.write_gatt_char(CMD_UUID, payload.encode("utf-8"), response=True)

        # Aguarda spam terminar (cycles * 100ms + slack)
        await asyncio.sleep(args.cycles * 0.1 + 5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Apple Continuity spam via firmware WifiUtils. Para uso em ambiente controlado.",
    )
    parser.add_argument("--cycles", type=int, default=50,
                        help="Número de cycles (default 50, max 500). Cada cycle = 1 popup ~100ms.")
    args = parser.parse_args()

    asyncio.run(run(args))
