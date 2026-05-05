#!/usr/bin/env python3
"""
LAN host discovery via firmware WifiUtils (ARP scan no /24).

Fluxo:
    1. Conecta ESP em rede WiFi (--ssid + --psk)
    2. Dispara lan_scan
    3. Imprime hosts (LAN_HOST 0x14) conforme chegam, encerra ao receber
       LAN_SCAN_DONE (0x15).

Uso:
    ~/.platformio/penv/bin/python scripts/lan_scan_test.py \\
        --ssid "MinhaRedeLab" --psk "senha123" [--timeout-ms 3000]
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


def decode_lan_host(payload: bytes) -> dict:
    if len(payload) < 10:
        return {"_truncated": payload.hex()}
    ip = ".".join(str(b) for b in payload[0:4])
    mac = ":".join(f"{b:02x}" for b in payload[4:10])
    return {"ip": ip, "mac": mac}


def decode_lan_done(payload: bytes) -> dict:
    if len(payload) < 7:
        return {"_truncated": payload.hex()}
    return {
        "host_count":   int.from_bytes(payload[0:2], "big"),
        "scan_time_ms": int.from_bytes(payload[2:6], "big"),
        "status":       payload[6],
    }


async def send_and_wait(client, queue, payload, timeout=20.0):
    print(f"→ {payload}")
    await client.write_gatt_char(CMD_UUID, payload.encode("utf-8"), response=True)
    try:
        resp = await asyncio.wait_for(queue.get(), timeout=timeout)
        print(f"← {resp}")
        return resp
    except asyncio.TimeoutError:
        print("  ✗ timeout")
        return None


async def run(args):
    dev = await find_target()
    if not dev:
        print("✗ WifiUtils device not found"); sys.exit(2)
    print(f"→ connecting to {dev.address} ({dev.name})")

    async with BleakClient(dev) as client:
        cmd_q: asyncio.Queue = asyncio.Queue()
        done_evt = asyncio.Event()
        hosts = []
        summary = {}

        def cmd_cb(_h, data):
            try:
                cmd_q.put_nowait(json.loads(data.decode("utf-8")))
            except Exception:
                cmd_q.put_nowait({"_raw": bytes(data)})

        def stream_cb(_h, data):
            if len(data) < 4:
                return
            mtype = data[2]
            payload = bytes(data[4:])
            if mtype == 0x14:
                h = decode_lan_host(payload)
                hosts.append(h)
                print(f"  HOST  ip={h.get('ip')!s:<15}  mac={h.get('mac')}")
            elif mtype == 0x15:
                summary.update(decode_lan_done(payload))
                done_evt.set()
            else:
                print(f"  ?  type=0x{mtype:02x} ({len(payload)}B)")

        await client.start_notify(CMD_UUID, cmd_cb)
        await client.start_notify(STREAM_UUID, stream_cb)

        # 1) wifi_connect
        wc = {"cmd": "wifi_connect", "seq": 1, "ssid": args.ssid}
        if args.psk:
            wc["password"] = args.psk
        wc["timeout_ms"] = args.connect_timeout_ms
        resp = await send_and_wait(
            client, cmd_q, json.dumps(wc),
            timeout=args.connect_timeout_ms / 1000 + 5,
        )
        if not resp or resp.get("status") != "connected":
            print("✗ wifi_connect failed"); return

        # 2) lan_scan
        ls = {"cmd": "lan_scan", "seq": 2, "timeout_ms": args.timeout_ms}
        await send_and_wait(client, cmd_q, json.dumps(ls), timeout=5)

        print(f"\n→ aguardando LAN_SCAN_DONE...")
        try:
            await asyncio.wait_for(done_evt.wait(),
                                    timeout=args.timeout_ms / 1000 + 30)
        except asyncio.TimeoutError:
            print("✗ timeout"); return

        print(f"\nLAN_SCAN_DONE: {summary['host_count']} hosts em "
              f"{summary['scan_time_ms']}ms (status={summary['status']})")

        if args.disconnect_after:
            await send_and_wait(
                client, cmd_q, json.dumps({"cmd": "wifi_disconnect", "seq": 3}),
                timeout=5,
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="LAN host discovery (ARP scan no /24) via firmware WifiUtils.",
    )
    parser.add_argument("--ssid", required=True, help="SSID da rede 2.4GHz alvo")
    parser.add_argument("--psk", default="", help="Senha WPA/WPA2 (vazio = aberta)")
    parser.add_argument("--timeout-ms", type=int, default=3000,
                        help="Tempo de espera por replies (default 3000, range 500–30000)")
    parser.add_argument("--connect-timeout-ms", type=int, default=15000)
    parser.add_argument("--disconnect-after", action="store_true")
    args = parser.parse_args()

    asyncio.run(run(args))
