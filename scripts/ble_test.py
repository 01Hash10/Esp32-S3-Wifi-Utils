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


async def run_ping(client: BleakClient):
    inbox: asyncio.Queue = asyncio.Queue()

    def cmd_handler(_handle, data: bytearray):
        try:
            msg = json.loads(data.decode("utf-8"))
        except Exception as exc:
            msg = {"_raw": bytes(data), "_err": str(exc)}
        inbox.put_nowait(msg)

    def stream_handler(_handle, data: bytearray):
        if len(data) >= 4:
            length = (data[0] << 8) | data[1]
            mtype = data[2]
            seq = data[3]
            print(f"  stream  type=0x{mtype:02x} seq={seq} payload={len(data)-4}B")

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
