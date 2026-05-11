#!/usr/bin/env python3
"""
Heltec diagnostic — bypasses the daemon to test the radio directly.
Run with: sudo systemctl stop darknet-node && python3 heltec_test.py

Listens for 5s (catches READY frame if Heltec resets), then sends a test
HELLO every 2s. Run this on BOTH Pis. Each should see the other's HELLO.
"""

import serial
import sys
import time
from pathlib import Path

# Make protocol/ importable
sys.path.insert(0, str(Path(__file__).parent.parent))
from protocol import protocol as P


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB0"
    my_id = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0

    ser = serial.Serial(port, 115200, timeout=0.1)
    parser = P.FrameParser()
    print(f"Opened {port}, my_id=0x{my_id:02X}")

    # Listen for 3s — catches READY if you reset the Heltec
    print("Listening 3s (press RST on Heltec to see READY)...")
    end = time.time() + 3
    while time.time() < end:
        chunk = ser.read(256)
        for ftype, payload in parser.feed(chunk):
            handle_frame(ftype, payload)

    # Send a test HELLO
    print(f"\nSending test HELLO from 0x{my_id:02X}...")
    hello_payload = P.pack_hello(is_root=False, is_relay=False)
    pkt, mid = P.build_packet(my_id, P.BROADCAST_ID, P.PKT_HELLO, hello_payload)
    frame = P.encode_send_frame(pkt)
    print(f"  packet:   {len(pkt)} bytes  mid={mid}  hex={pkt.hex()}")
    print(f"  frame:    {len(frame)} bytes  hex={frame.hex()}")
    ser.write(frame)

    # Listen for 30s — should see RECV frames if other side transmits
    print("\nListening 30s for incoming traffic...")
    end = time.time() + 30
    last_send = time.time()
    while time.time() < end:
        chunk = ser.read(256)
        for ftype, payload in parser.feed(chunk):
            handle_frame(ftype, payload)

        # Send a HELLO every 5s
        if time.time() - last_send > 5:
            ser.write(frame)
            print(f"  [tx] HELLO mid={mid}")
            last_send = time.time()

    print("\nDone.")


def handle_frame(ftype, payload):
    if ftype == P.FRAME_TYPE_INFO:
        text = payload.decode("utf-8", errors="replace")
        print(f"  [INFO] {text}")
    elif ftype == P.FRAME_TYPE_RECV:
        parsed = P.parse_recv_payload(payload)
        if parsed is None:
            print(f"  [RECV] bad frame: {payload.hex()}")
            return
        rssi, snr, pkt_bytes = parsed
        hdr = P.unpack_header(pkt_bytes)
        if hdr is None:
            print(f"  [RECV] rssi={rssi} snr={snr} (invalid header) hex={pkt_bytes.hex()}")
            return
        ptype_name = P.PKT_NAMES.get(hdr["type"], f"0x{hdr['type']:02X}")
        print(f"  [RECV] rssi={rssi} snr={snr} src=0x{hdr['src']:02X} "
              f"type={ptype_name} hops={hdr['hops']} mid={hdr['mid']}")
    else:
        print(f"  [FRAME 0x{ftype:02X}] {payload.hex()}")


if __name__ == "__main__":
    main()
