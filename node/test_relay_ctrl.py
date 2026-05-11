#!/usr/bin/env python3
"""
test_relay_ctrl.py — bench test for the relay control plane.

Builds a signed RELAY_CTRL packet using the dev/default key, then injects it
via the daemon's SEND_RAW socket command. Watch the T-Beam OLED for the
'[MODE]' indicator to change.

Run from the same dir as relay_admin.py, or with PYTHONPATH set appropriately.

Usage:
    python3 test_relay_ctrl.py ROUTED
    python3 test_relay_ctrl.py FLOOD
    python3 test_relay_ctrl.py STORE_FWD --target 0x62
    python3 test_relay_ctrl.py SELECTIVE --rssi-floor -100
"""
import argparse
import socket
import sys
from pathlib import Path

# Make node/ importable if running from project root
sys.path.insert(0, str(Path(__file__).resolve().parent))

from relay_admin import RelayAdmin, RelayMode, BROADCAST_ID


SOCKET_PATH = "/tmp/darknet.sock"

# MUST match ADMIN_KEY in the .ino firmware.
# This is the default; replace with your real key for production.
DEFAULT_KEY = b"change-me-shared-darknet-secret-key"


def send_raw(packet_bytes: bytes) -> str:
    s = socket.socket(socket.AF_UNIX)
    s.connect(SOCKET_PATH)
    cmd = b"SEND_RAW:" + packet_bytes.hex().encode()
    s.sendall(cmd)
    reply = s.recv(256).decode()
    s.close()
    return reply


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=[m.name for m in RelayMode],
                    help="Mode to set on the relay")
    ap.add_argument("--target", default="broadcast",
                    help="0xNN for one relay, or 'broadcast' for all relays")
    ap.add_argument("--rssi-floor", type=int, default=-128)
    ap.add_argument("--duty-cap", type=int, default=0)
    ap.add_argument("--sf-queue-max", type=int, default=8)
    ap.add_argument("--sf-ttl", type=int, default=1800)
    ap.add_argument("--my-id", type=lambda x: int(x, 0), default=0x00,
                    help="Our node ID (must match the daemon's --node-id)")
    ap.add_argument("--key", default=DEFAULT_KEY,
                    help="Admin key (raw bytes or string)")
    args = ap.parse_args()

    if args.target == "broadcast":
        dst = BROADCAST_ID
    else:
        dst = int(args.target, 0)

    key = args.key if isinstance(args.key, bytes) else args.key.encode()

    admin = RelayAdmin(
        my_id=args.my_id,
        admin_key=key,
        nonce_state_path="/tmp/darknet_relay_nonce",
    )

    pkt = admin.build_ctrl(
        dst=dst,
        mode=RelayMode[args.mode],
        rssi_floor=args.rssi_floor,
        duty_cap_pct=args.duty_cap,
        sf_queue_max=args.sf_queue_max,
        sf_ttl_seconds=args.sf_ttl,
    )

    print(f"Built RELAY_CTRL packet, {len(pkt)} bytes")
    print(f"  src=0x{args.my_id:02X} dst=0x{dst:02X} mode={args.mode}")
    print(f"  hex: {pkt.hex()}")

    reply = send_raw(pkt)
    print(f"Daemon reply: {reply}")
    print()
    print("Now watch the T-Beam OLED — the mode tag should change within ~1s.")
    print("The daemon log should also show a STATUS heartbeat back from 0x62")
    print("(currently parsed as 'Unknown pkt type 0x0D' — we'll fix that next).")


if __name__ == "__main__":
    main()
