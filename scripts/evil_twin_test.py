#!/usr/bin/env python3
"""
Evil Twin AP via firmware WifiUtils.

Sobe um SoftAP com SSID/canal/password configurável e monitora cada
client que associa/disassocia (TLVs EVIL_CLIENT_JOIN/LEAVE).

ATENÇÃO: ESP precisa estar **NÃO conectado** como STA. Use somente
em ambiente controlado / autorizado.

Uso:
    ~/.platformio/penv/bin/python scripts/evil_twin_test.py \\
        --ssid "FreeWifi" --channel 6 [--password senha123] [--duration 120]

Ctrl+C pra encerrar antes do duration.
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


def decode_join(payload: bytes) -> dict:
    if len(payload) < 8: return {}
    mac = ":".join(f"{b:02x}" for b in payload[0:6])
    aid = int.from_bytes(payload[6:8], "big")
    return {"mac": mac, "aid": aid}


def decode_leave(payload: bytes) -> dict:
    if len(payload) < 7: return {}
    mac = ":".join(f"{b:02x}" for b in payload[0:6])
    reason = payload[6]
    return {"mac": mac, "reason": reason}


async def run(args):
    dev = await find_target()
    if not dev:
        print("✗ WifiUtils device not found"); sys.exit(2)
    print(f"→ connecting to {dev.address} ({dev.name})")

    async with BleakClient(dev) as client:
        clients = {}  # mac -> aid

        def cmd_cb(_h, data):
            print(f"← cmd: {data.decode('utf-8', errors='replace')}")

        def stream_cb(_h, data):
            if len(data) < 4: return
            mtype = data[2]
            payload = bytes(data[4:])
            if mtype == 0x26:
                e = decode_join(payload)
                clients[e['mac']] = e['aid']
                print(f"  ↳ JOIN  mac={e['mac']}  aid={e['aid']}  "
                      f"(total={len(clients)})")
            elif mtype == 0x27:
                e = decode_leave(payload)
                clients.pop(e['mac'], None)
                print(f"  ↳ LEAVE mac={e['mac']}  reason={e['reason']}  "
                      f"(total={len(clients)})")
            elif mtype == 0x00:
                pass  # heartbeat — ignora
            else:
                print(f"  ?  type=0x{mtype:02x} ({len(payload)}B)")

        await client.start_notify(CMD_UUID, cmd_cb)
        await client.start_notify(STREAM_UUID, stream_cb)

        cmd = {
            "cmd": "evil_twin_start", "seq": 1,
            "ssid": args.ssid,
            "channel": args.channel,
            "max_conn": args.max_conn,
        }
        if args.password:
            cmd["password"] = args.password

        payload = json.dumps(cmd)
        print(f"→ {payload}")
        await client.write_gatt_char(CMD_UUID, payload.encode("utf-8"), response=True)

        print(f"\n→ AP ativo por {args.duration}s. Ctrl+C pra parar.")
        try:
            await asyncio.sleep(args.duration)
        except (KeyboardInterrupt, asyncio.CancelledError):
            print("\n→ interrompido pelo usuário")

        # Stop
        stop_cmd = json.dumps({"cmd": "evil_twin_stop", "seq": 99})
        print(f"→ {stop_cmd}")
        await client.write_gatt_char(CMD_UUID, stop_cmd.encode("utf-8"), response=True)
        await asyncio.sleep(1)

        print(f"\n=== Resumo ===")
        print(f"Clients associados na sessão: {len(clients)}")
        for mac, aid in clients.items():
            print(f"  {mac}  aid={aid}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Evil Twin AP via firmware WifiUtils.",
    )
    parser.add_argument("--ssid", required=True, help="SSID do AP fake (1–32 chars)")
    parser.add_argument("--channel", type=int, required=True, help="Canal (1–13)")
    parser.add_argument("--password", default="", help="Senha WPA2 (8–63 chars; vazio = OPEN)")
    parser.add_argument("--max-conn", type=int, default=4, help="Max clients (1–10, default 4)")
    parser.add_argument("--duration", type=int, default=120,
                        help="Duração da sessão em segundos (default 120)")
    args = parser.parse_args()

    asyncio.run(run(args))
