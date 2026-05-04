#!/usr/bin/env python3
"""
Teste local de Phase 1: scan + connect + ping/hello/status.

Uso:
    ~/.platformio/penv/bin/python scripts/ble_test.py [--scan-only]
"""
import asyncio
import json
import sys

from bleak import BleakClient, BleakScanner

SVC_UUID    = "e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c01"
CMD_UUID    = "e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c02"
STREAM_UUID = "e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c03"


async def find_device(scan_only: bool = False, timeout: float = 8.0):
    print(f"→ scanning {timeout}s for any BLE adv...")
    found = await BleakScanner.discover(timeout=timeout, return_adv=True)
    target = None
    for addr, (dev, adv) in found.items():
        name = dev.name or adv.local_name or "<no-name>"
        uuids = adv.service_uuids or []
        marker = ""
        if name.startswith("WifiUtils-") or SVC_UUID in [u.lower() for u in uuids]:
            marker = "  ← TARGET"
            target = dev
        print(f"  {addr}  rssi={adv.rssi}  name={name}  uuids={uuids}{marker}")
    return target


def decode_wifi_ap(payload: bytes) -> dict:
    bssid = ":".join(f"{b:02x}" for b in payload[0:6])
    rssi = int.from_bytes(payload[6:7], "big", signed=True)
    channel = payload[7]
    auth = payload[8]
    ssid_len = payload[9]
    ssid = payload[10:10 + ssid_len].decode("utf-8", errors="replace")
    return {
        "bssid": bssid, "rssi": rssi, "channel": channel,
        "auth": auth, "ssid": ssid or "<hidden>",
    }


def decode_wifi_done(payload: bytes) -> dict:
    return {
        "ap_count": int.from_bytes(payload[0:2], "big"),
        "scan_ms":  int.from_bytes(payload[2:6], "big"),
        "status":   payload[6],
    }


async def run_ping(client: BleakClient):
    inbox: asyncio.Queue = asyncio.Queue()
    stream_inbox: asyncio.Queue = asyncio.Queue()

    def cmd_handler(_handle, data: bytearray):
        try:
            msg = json.loads(data.decode("utf-8"))
        except Exception as exc:
            msg = {"_raw": bytes(data), "_err": str(exc)}
        inbox.put_nowait(msg)

    def stream_handler(_handle, data: bytearray):
        if len(data) >= 4:
            mtype = data[2]
            seq = data[3]
            payload = bytes(data[4:])
            stream_inbox.put_nowait((mtype, seq, payload))

    await client.start_notify(CMD_UUID, cmd_handler)
    await client.start_notify(STREAM_UUID, stream_handler)
    print("→ subscribed to cmd_ctrl + stream notifies")

    for cmd in ("ping", "hello", "status"):
        payload = json.dumps({"cmd": cmd, "seq": 100 + len(cmd)})
        print(f"\n→ send: {payload}")
        await client.write_gatt_char(CMD_UUID, payload.encode("utf-8"), response=True)
        try:
            resp = await asyncio.wait_for(inbox.get(), timeout=2.0)
            print(f"← recv: {resp}")
        except asyncio.TimeoutError:
            print(f"  ✗ timeout waiting reply for '{cmd}'")

    print("\n→ send: wifi_scan")
    await client.write_gatt_char(
        CMD_UUID, json.dumps({"cmd": "wifi_scan", "seq": 200}).encode("utf-8"),
        response=True,
    )
    try:
        ack = await asyncio.wait_for(inbox.get(), timeout=2.0)
        print(f"← ack: {ack}")
    except asyncio.TimeoutError:
        print("  ✗ no ack for wifi_scan"); return

    print("\n→ awaiting WIFI_SCAN_AP frames (timeout 12s)...")
    aps = []
    while True:
        try:
            mtype, seq, payload = await asyncio.wait_for(stream_inbox.get(), timeout=12.0)
        except asyncio.TimeoutError:
            print("  ✗ stream timeout (no SCAN_DONE received)")
            return
        if mtype == 0x10:
            ap = decode_wifi_ap(payload)
            aps.append(ap)
            print(f"  AP  ssid={ap['ssid']!r:<32} bssid={ap['bssid']} rssi={ap['rssi']} ch={ap['channel']} auth={ap['auth']}")
        elif mtype == 0x11:
            done = decode_wifi_done(payload)
            print(f"\nSCAN_DONE: {done['ap_count']} APs in {done['scan_ms']}ms (received {len(aps)}, status={done['status']})")
            return
        else:
            print(f"  ?  type=0x{mtype:02x} payload={len(payload)}B (ignored)")


async def main(scan_only: bool):
    dev = await find_device(scan_only=scan_only)
    if scan_only:
        print("\nscan-only mode, exiting.")
        return
    if not dev:
        print("\n✗ WifiUtils device not found in scan")
        sys.exit(2)

    print(f"\n→ connecting to {dev.address} ({dev.name})")
    async with BleakClient(dev) as client:
        if not client.is_connected:
            print("✗ connect failed")
            sys.exit(3)
        print("→ connected")
        try:
            mtu = client.mtu_size
            print(f"  mtu={mtu}")
        except Exception:
            pass
        await run_ping(client)


if __name__ == "__main__":
    scan_only = "--scan-only" in sys.argv
    asyncio.run(main(scan_only))
