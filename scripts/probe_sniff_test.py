#!/usr/bin/env python3
"""
Probe request sniffer via firmware WifiUtils.

Captura probe requests (devices procurando APs) com channel hopping no
range configurado. Útil pra fingerprinting (devices revelam SSIDs salvos).

ATENÇÃO: ESP precisa estar **NÃO conectado** (channel hop conflita com STA).
Se estiver conectado, chame wifi_disconnect antes.

Uso:
    ~/.platformio/penv/bin/python scripts/probe_sniff_test.py \\
        [--ch-min 1] [--ch-max 13] [--dwell-ms 500] [--duration 30]
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


def decode_probe(payload: bytes) -> dict:
    if len(payload) < 9:
        return {"_truncated": payload.hex()}
    mac = ":".join(f"{b:02x}" for b in payload[0:6])
    rssi = int.from_bytes(payload[6:7], "big", signed=True)
    channel = payload[7]
    ssid_len = payload[8]
    ssid = payload[9:9 + ssid_len].decode("utf-8", errors="replace")
    return {"mac": mac, "rssi": rssi, "ch": channel,
            "ssid": ssid or "<broadcast>"}


def decode_done(payload: bytes) -> dict:
    if len(payload) < 9:
        return {"_truncated": payload.hex()}
    return {
        "unique":       int.from_bytes(payload[0:2], "big"),
        "frames_total": int.from_bytes(payload[2:4], "big"),
        "scan_time_ms": int.from_bytes(payload[4:8], "big"),
        "status":       payload[8],
    }


async def run(args):
    dev = await find_target()
    if not dev:
        print("✗ WifiUtils device not found"); sys.exit(2)
    print(f"→ connecting to {dev.address} ({dev.name})")

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
            if mtype == 0x16:
                p = decode_probe(payload)
                print(f"  PROBE  mac={p['mac']}  rssi={p['rssi']:>4}  "
                      f"ch={p['ch']:>2}  ssid={p['ssid']!r}")
            elif mtype == 0x17:
                summary.update(decode_done(payload))
                done_evt.set()
            else:
                print(f"  ?  type=0x{mtype:02x} ({len(payload)}B)")

        await client.start_notify(CMD_UUID, cmd_cb)
        await client.start_notify(STREAM_UUID, stream_cb)

        cmd = {
            "cmd": "probe_sniff", "seq": 1,
            "ch_min": args.ch_min,
            "ch_max": args.ch_max,
            "dwell_ms": args.dwell_ms,
            "duration_sec": args.duration,
        }
        payload = json.dumps(cmd)
        print(f"→ {payload}")
        await client.write_gatt_char(CMD_UUID, payload.encode("utf-8"), response=True)

        try:
            await asyncio.wait_for(done_evt.wait(), timeout=args.duration + 15)
        except asyncio.TimeoutError:
            print("✗ timeout waiting PROBE_DONE")
            return

        print(f"\nPROBE_DONE: {summary['unique']} únicos / "
              f"{summary['frames_total']} frames totais em "
              f"{summary['scan_time_ms']}ms (status={summary['status']})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Probe request sniffer via firmware WifiUtils.",
    )
    parser.add_argument("--ch-min", type=int, default=1,  help="canal min (1–13)")
    parser.add_argument("--ch-max", type=int, default=13, help="canal max (1–13)")
    parser.add_argument("--dwell-ms", type=int, default=500,
                        help="ms por canal (100–5000, default 500)")
    parser.add_argument("--duration", type=int, default=30,
                        help="duração total em segundos (1–300, default 30)")
    args = parser.parse_args()

    asyncio.run(run(args))
