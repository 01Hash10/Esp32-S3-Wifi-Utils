#!/usr/bin/env python3
"""
Dispara beacon flood com lista de SSIDs falsos. Detectável em qualquer
WiFi scanner (apps de scanning no celular, Mac airport, etc).

Uso:
    ~/.platformio/penv/bin/python scripts/beacon_test.py \\
        --channel 1 \\
        --cycles 50 \\
        --ssids "FreeWifi,Starbucks,Cafe Free,IT Support,Public-WiFi"
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

    ssids = [s.strip() for s in args.ssids.split(",") if s.strip()]
    if not ssids:
        print("✗ no ssids provided"); sys.exit(2)
    print(f"→ ssids ({len(ssids)}): {ssids}")
    print(f"→ channel={args.channel}, cycles={args.cycles}, total_tx={args.cycles*len(ssids)}")

    async with BleakClient(dev) as client:
        await client.start_notify(
            CMD_UUID,
            lambda h, d: print(f"← {d.decode('utf-8', errors='replace')}"),
        )
        cmd = {
            "cmd": "beacon_flood", "seq": 1,
            "channel": args.channel,
            "cycles": args.cycles,
            "ssids": ssids,
        }
        payload = json.dumps(cmd)
        print(f"→ {payload}")
        await client.write_gatt_char(CMD_UUID, payload.encode("utf-8"), response=True)

        # Tempo estimado: cycles * len(ssids) * 2ms + slack
        est = args.cycles * len(ssids) * 0.003 + 2
        await asyncio.sleep(min(15, est))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Beacon flood via firmware WifiUtils. Para uso em ambiente controlado.",
    )
    parser.add_argument("--channel", required=True, type=int, help="Canal 2.4GHz (1–14)")
    parser.add_argument("--cycles", type=int, default=50, help="Repetições (default 50, max 200)")
    parser.add_argument("--ssids", required=True,
                        help="Lista de SSIDs separados por vírgula (max 32)")
    args = parser.parse_args()

    asyncio.run(run(args))
