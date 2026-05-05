#!/usr/bin/env python3
"""
Defense WiFi monitor via firmware WifiUtils.

Roda 4 detectores em paralelo: deauth storm, beacon flood, evil twin,
karma. Cada alerta vira TLV no stream — script imprime em tempo real.

Pra testar end-to-end: rode esse script no ESP-A e simultaneamente um
ataque (deauth/beacon_flood/karma_start/evil_twin_start) num ESP-B.

ATENÇÃO: ESP precisa estar **NÃO conectado** (canal fixo ou hop conflita
com STA).

Uso:
    ~/.platformio/penv/bin/python scripts/defense_test.py \\
        [--mask 15] [--channel 0] [--duration 300]

mask bits: 1=deauth, 2=beacon_flood, 4=evil_twin, 8=karma. Default 15=all.
channel 0 = hop em ch_min..ch_max; 1-13 = canal fixo.
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


def fmt_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def decode_deauth(p: bytes) -> str:
    return (f"DEAUTH STORM bssid={fmt_mac(p[0:6])} "
            f"count={int.from_bytes(p[6:8], 'big')} "
            f"window={int.from_bytes(p[8:10], 'big')}ms")


def decode_flood(p: bytes) -> str:
    return (f"BEACON FLOOD unique={int.from_bytes(p[0:2], 'big')} "
            f"window={int.from_bytes(p[2:4], 'big')}ms "
            f"total={int.from_bytes(p[4:6], 'big')}")


def decode_evil(p: bytes) -> str:
    sl = p[0]
    ssid = p[1:1+sl].decode("utf-8", errors="replace")
    a = fmt_mac(p[1+sl:7+sl])
    ra = int.from_bytes(p[7+sl:8+sl], "big", signed=True)
    b = fmt_mac(p[8+sl:14+sl])
    rb = int.from_bytes(p[14+sl:15+sl], "big", signed=True)
    return f"EVIL TWIN ssid={ssid!r} bssid_a={a} ({ra}dBm) bssid_b={b} ({rb}dBm)"


def decode_karma(p: bytes) -> str:
    bssid = fmt_mac(p[0:6])
    rssi = int.from_bytes(p[6:7], "big", signed=True)
    sl = p[7]
    ssid = p[8:8+sl].decode("utf-8", errors="replace")
    return f"KARMA bssid={bssid} ({rssi}dBm) ssid={ssid!r}"


def decode_done(p: bytes) -> dict:
    return {
        "alerts":        int.from_bytes(p[0:2], "big"),
        "total_deauth":  int.from_bytes(p[2:6], "big"),
        "total_beacons": int.from_bytes(p[6:10], "big"),
        "elapsed_ms":    int.from_bytes(p[10:14], "big"),
        "status":        p[14],
    }


async def run(args):
    dev = await find_target()
    if not dev:
        print("✗ WifiUtils device not found"); sys.exit(2)
    print(f"→ connecting to {dev.address} ({dev.name})")

    async with BleakClient(dev) as client:
        done_evt = asyncio.Event()
        summary = {}
        alerts = {"deauth": 0, "flood": 0, "evil": 0, "karma": 0}

        def cmd_cb(_h, data):
            print(f"← cmd: {data.decode('utf-8', errors='replace')}")

        def stream_cb(_h, data):
            if len(data) < 4: return
            mtype = data[2]
            payload = bytes(data[4:])
            if mtype == 0x30:
                alerts["deauth"] += 1
                print(f"⚠  {decode_deauth(payload)}")
            elif mtype == 0x31:
                alerts["flood"] += 1
                print(f"⚠  {decode_flood(payload)}")
            elif mtype == 0x32:
                alerts["evil"] += 1
                print(f"⚠  {decode_evil(payload)}")
            elif mtype == 0x33:
                alerts["karma"] += 1
                print(f"⚠  {decode_karma(payload)}")
            elif mtype == 0x34:
                summary.update(decode_done(payload))
                done_evt.set()
            elif mtype == 0x00:
                pass  # heartbeat

        await client.start_notify(CMD_UUID, cmd_cb)
        await client.start_notify(STREAM_UUID, stream_cb)

        cmd = {
            "cmd": "defense_start", "seq": 1,
            "mask": args.mask,
            "channel": args.channel,
            "ch_min": args.ch_min,
            "ch_max": args.ch_max,
            "dwell_ms": args.dwell_ms,
            "duration_sec": args.duration,
        }
        payload = json.dumps(cmd)
        print(f"→ {payload}")
        await client.write_gatt_char(CMD_UUID, payload.encode("utf-8"), response=True)

        print(f"\n→ Defense ativo. Ctrl+C pra encerrar antes do timeout.\n")
        try:
            await asyncio.wait_for(done_evt.wait(),
                                    timeout=args.duration + 30 if args.duration else None)
        except asyncio.TimeoutError:
            print("✗ timeout aguardando DEFENSE_DONE")
        except (KeyboardInterrupt, asyncio.CancelledError):
            print("\n→ interrompido — enviando defense_stop")
            await client.write_gatt_char(CMD_UUID,
                json.dumps({"cmd": "defense_stop", "seq": 99}).encode("utf-8"),
                response=True)
            try:
                await asyncio.wait_for(done_evt.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass

        if summary:
            print(f"\nDEFENSE_DONE: alerts={summary['alerts']} "
                  f"deauth={summary['total_deauth']} "
                  f"beacons={summary['total_beacons']} "
                  f"in {summary['elapsed_ms']}ms")
        print(f"\nAlerts por tipo: deauth={alerts['deauth']} "
              f"flood={alerts['flood']} evil={alerts['evil']} "
              f"karma={alerts['karma']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Defense WiFi monitor via firmware WifiUtils.",
    )
    parser.add_argument("--mask", type=int, default=15,
                        help="Bitmask de detectores (1=deauth, 2=flood, 4=evil, 8=karma; default 15=all)")
    parser.add_argument("--channel", type=int, default=0,
                        help="0=hop, 1-13=fixo")
    parser.add_argument("--ch-min", type=int, default=1)
    parser.add_argument("--ch-max", type=int, default=13)
    parser.add_argument("--dwell-ms", type=int, default=500)
    parser.add_argument("--duration", type=int, default=300,
                        help="Duração em segundos (0=até stop, max 3600)")
    args = parser.parse_args()

    asyncio.run(run(args))
