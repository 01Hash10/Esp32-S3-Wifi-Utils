#!/usr/bin/env python3
"""
Pcap streaming via firmware WifiUtils.

Recebe TLVs PCAP_FRAME (0x40) do ESP em tempo real e monta um arquivo
.pcap (LINKTYPE_IEEE802_11 = 105) que abre direto no Wireshark.

ATENÇÃO: ESP precisa estar **NÃO conectado**. Use somente em redes
próprias / autorizadas.

Uso:
    ~/.platformio/penv/bin/python scripts/pcap_test.py \\
        --channel 6 [--filter mgmt|data|ctrl|all|mgmt+data] \\
        [--bssid aa:bb:cc:dd:ee:ff] [--duration 60] [--out capture.pcap]

Exemplos:
    # Captura de tudo no canal 6 por 30s
    python scripts/pcap_test.py --channel 6 --filter all --duration 30

    # Só mgmt frames de uma rede específica
    python scripts/pcap_test.py --channel 11 --filter mgmt \\
        --bssid AA:BB:CC:DD:EE:FF --duration 60
"""
import argparse
import asyncio
import json
import struct
import sys
import time

from bleak import BleakClient, BleakScanner

SVC_UUID    = "e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c01"
CMD_UUID    = "e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c02"
STREAM_UUID = "e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c03"

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_IEEE802_11 = 105


def pcap_write_header(f):
    f.write(struct.pack("<IHHiIII",
                         PCAP_MAGIC, 2, 4, 0, 0, 65535,
                         LINKTYPE_IEEE802_11))


def pcap_write_record(f, frame: bytes, ts: float, orig_len: int):
    sec = int(ts)
    usec = int((ts - sec) * 1e6)
    f.write(struct.pack("<IIII", sec, usec, len(frame), orig_len))
    f.write(frame)


async def find_target():
    print("→ scanning for WifiUtils-* device...")
    async with BleakScanner(service_uuids=[SVC_UUID]) as sc:
        await asyncio.sleep(5)
        for d in sc.discovered_devices:
            if (d.name or "").startswith("WifiUtils-"):
                return d
    return None


def decode_pcap_frame(payload: bytes) -> dict:
    if len(payload) < 7:
        return {"_truncated": payload.hex()}
    ts_us = int.from_bytes(payload[0:4], "big")
    orig_len = int.from_bytes(payload[4:6], "big")
    flags = payload[6]
    frame = bytes(payload[7:])
    return {"ts_us": ts_us, "orig_len": orig_len, "flags": flags,
            "frame": frame, "truncated": bool(flags & 0x01)}


def decode_pcap_done(payload: bytes) -> dict:
    if len(payload) < 9:
        return {"_truncated": payload.hex()}
    return {
        "emitted":   int.from_bytes(payload[0:2], "big"),
        "dropped":   int.from_bytes(payload[2:4], "big"),
        "elapsed_ms": int.from_bytes(payload[4:8], "big"),
        "status":    payload[8],
    }


async def run(args):
    dev = await find_target()
    if not dev:
        print("✗ WifiUtils device not found"); sys.exit(2)
    print(f"→ connecting to {dev.address} ({dev.name})")

    pcap_file = open(args.out, "wb")
    pcap_write_header(pcap_file)
    capture_start = time.time()

    async with BleakClient(dev) as client:
        done_evt = asyncio.Event()
        summary = {}
        captured = 0
        truncated_count = 0

        def cmd_cb(_h, data):
            print(f"← cmd: {data.decode('utf-8', errors='replace')}")

        def stream_cb(_h, data):
            nonlocal captured, truncated_count
            if len(data) < 4:
                return
            mtype = data[2]
            payload = bytes(data[4:])
            if mtype == 0x40:
                f = decode_pcap_frame(payload)
                ts = capture_start + f["ts_us"] / 1e6
                pcap_write_record(pcap_file, f["frame"], ts, f["orig_len"])
                captured += 1
                if f["truncated"]:
                    truncated_count += 1
                if captured % 50 == 0:
                    print(f"  [{captured} frames captured, "
                          f"{truncated_count} truncated so far]")
            elif mtype == 0x41:
                summary.update(decode_pcap_done(payload))
                done_evt.set()
            else:
                print(f"  ?  type=0x{mtype:02x} ({len(payload)}B)")

        await client.start_notify(CMD_UUID, cmd_cb)
        await client.start_notify(STREAM_UUID, stream_cb)

        cmd = {
            "cmd": "pcap_start", "seq": 1,
            "channel": args.channel,
            "filter": args.filter,
            "duration_sec": args.duration,
        }
        if args.bssid:
            cmd["bssid"] = args.bssid

        payload = json.dumps(cmd)
        print(f"→ {payload}")
        await client.write_gatt_char(CMD_UUID, payload.encode("utf-8"), response=True)

        try:
            await asyncio.wait_for(done_evt.wait(), timeout=args.duration + 15)
        except asyncio.TimeoutError:
            print("✗ timeout waiting PCAP_DONE")

        pcap_file.close()

        if summary:
            ratio = (summary['dropped'] / max(1, summary['emitted'] + summary['dropped'])) * 100
            print(f"\nPCAP_DONE: emitted={summary['emitted']} dropped={summary['dropped']} "
                  f"({ratio:.1f}% drop) in {summary['elapsed_ms']}ms (status={summary['status']})")

        print(f"\n✓ pcap salvo em: {args.out} ({captured} frames, {truncated_count} truncados)")
        print(f"→ abrir no Wireshark: wireshark {args.out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Pcap streaming via firmware WifiUtils.",
    )
    parser.add_argument("--channel", type=int, required=True, help="Canal (1–13)")
    parser.add_argument("--filter", default="mgmt",
                        help="mgmt|data|ctrl|all|combinações (default mgmt)")
    parser.add_argument("--bssid", default=None,
                        help="Opcional: filtra frames por BSSID alvo")
    parser.add_argument("--duration", type=int, default=60,
                        help="Duração em segundos (1–300, default 60)")
    parser.add_argument("--out", default="capture.pcap",
                        help="Arquivo pcap de saída (default capture.pcap)")
    args = parser.parse_args()

    asyncio.run(run(args))
