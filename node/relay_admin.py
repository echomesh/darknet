"""
relay_admin.py — DarkNet relay control plane (Pi side).

Build, sign, and parse RELAY_CTRL / RELAY_STATUS packets. This module is purely
serialization + crypto; you plug the resulting bytes into your existing daemon's
TX path (the same path that emits HELLOs over the Heltec bridge).

Layout MUST match protocol.h byte-for-byte.

Quick start
-----------
    from relay_admin import RelayAdmin, RelayMode

    admin = RelayAdmin(
        my_id=0x00,
        admin_key=b"shared-secret-32-bytes-or-so",
        nonce_state_path="/var/lib/darknet/relay_nonce",
    )

    # Tell all relays to switch to ROUTED mode
    pkt = admin.build_ctrl(
        dst=0xFF,                       # broadcast
        mode=RelayMode.ROUTED,
        rssi_floor=-110,
        duty_cap_pct=10,
    )
    daemon.send_raw(pkt)

    # Target a specific relay
    pkt = admin.build_ctrl(
        dst=0x62,
        mode=RelayMode.STORE_FWD,
        sf_queue_max=8,
        sf_ttl_seconds=1800,
    )
    daemon.send_raw(pkt)

    # When you receive a packet of type PKT_RELAY_STATUS:
    status = admin.parse_status(payload_bytes)
    print(status)
"""

from __future__ import annotations
import hmac
import hashlib
import os
import struct
import time
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Optional


# ─── Must match protocol.h ────────────────────────────────────────────────────
DARKNET_MAGIC = 0xDA
DARKNET_VERSION = 1
BROADCAST_ID = 0xFF
MAX_HOPS = 5
MAX_PKT_SIZE = 240

# Packet types
PKT_RELAY_CTRL = 0x0C
PKT_RELAY_STATUS = 0x0D


class RelayMode(IntEnum):
    OFF = 0
    FLOOD = 1
    ROUTED = 2
    STORE_FWD = 3
    SELECTIVE = 4


def type_bit(t: int) -> int:
    """Build a single bit for use in RelayCtrl.type_mask."""
    return 1 << (t & 0x1F)


TYPE_MASK_ALL = 0xFFFFFFFF


# ─── Struct formats ───────────────────────────────────────────────────────────
# Header: magic, version, src, dst, type, hops, ttl, flags, mid, len  -> 12 bytes
_HDR_FMT = "<BBBBBBBBHH"
_HDR_SIZE = struct.calcsize(_HDR_FMT)
assert _HDR_SIZE == 12

# RelayCtrl: nonce(I), mode(B), flags(B), rssi_floor(b), duty_cap(B),
#            type_mask(I), sf_queue_max(H), sf_ttl(I),
#            max_hops_added(B), reserved(7s), hmac(8s)
_CTRL_FMT = "<IBBbBIHIB7s8s"
_CTRL_SIZE = struct.calcsize(_CTRL_FMT)
# 4+1+1+1+1+4+2+4+1+7+8 = 34 bytes
assert _CTRL_SIZE == 34, f"CTRL size mismatch: {_CTRL_SIZE}"

# RelayStatus: mode(B), flags(B), rssi_floor(b), duty_cap(B),
#              type_mask(I), sf_depth(H), sf_max(H),
#              relayed(I), dropped(I), uptime(I), last_nonce(I),
#              max_hops_added(B), reserved(3s)
_STATUS_FMT = "<BBbBIHHIIIIB3s"
_STATUS_SIZE = struct.calcsize(_STATUS_FMT)


# ─── Dataclasses ──────────────────────────────────────────────────────────────
@dataclass
class RelayStatus:
    src: int
    mode: RelayMode
    rssi_floor: int
    duty_cap_pct: int
    type_mask: int
    sf_queue_depth: int
    sf_queue_max: int
    relayed_count: int
    dropped_count: int
    uptime_seconds: int
    last_nonce: int
    max_hops_added: int

    def __str__(self) -> str:
        return (
            f"RelayStatus src=0x{self.src:02X} mode={self.mode.name} "
            f"rssi_floor={self.rssi_floor}dBm duty={self.duty_cap_pct}% "
            f"sf={self.sf_queue_depth}/{self.sf_queue_max} "
            f"relayed={self.relayed_count} dropped={self.dropped_count} "
            f"up={self.uptime_seconds}s nonce={self.last_nonce}"
        )


# ─── Admin client ─────────────────────────────────────────────────────────────
class RelayAdmin:
    """
    Builds signed RELAY_CTRL packets and parses RELAY_STATUS.

    Nonce state is persisted to disk so the counter never resets even if the
    daemon restarts — otherwise the relay would reject CTRL packets after any
    Pi reboot (because nonce <= last_seen).
    """

    def __init__(
        self,
        my_id: int,
        admin_key: bytes,
        nonce_state_path: Optional[str | os.PathLike] = None,
    ):
        if not 0 <= my_id <= 0xFE:
            raise ValueError("my_id must be 0..0xFE")
        if not admin_key:
            raise ValueError("admin_key must be non-empty")
        self.my_id = my_id
        self.admin_key = admin_key
        self._nonce_path: Optional[Path] = (
            Path(nonce_state_path) if nonce_state_path else None
        )
        self._nonce = self._load_nonce()

    # ─── Nonce management ─────────────────────────────────────────────────
    def _load_nonce(self) -> int:
        if not self._nonce_path:
            # Seed from wall-clock so a freshly-started daemon doesn't collide
            # with whatever the relay last accepted. Caller can pass an explicit
            # state path to persist properly.
            return int(time.time())
        try:
            return int(self._nonce_path.read_text().strip())
        except (FileNotFoundError, ValueError):
            return int(time.time())

    def _save_nonce(self) -> None:
        if not self._nonce_path:
            return
        self._nonce_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._nonce_path.with_suffix(self._nonce_path.suffix + ".tmp")
        tmp.write_text(str(self._nonce))
        os.replace(tmp, self._nonce_path)

    def _next_nonce(self) -> int:
        self._nonce += 1
        self._save_nonce()
        return self._nonce

    # ─── Build CTRL packet ────────────────────────────────────────────────
    def build_ctrl(
        self,
        dst: int,
        mode: RelayMode,
        *,
        rssi_floor: int = -128,
        duty_cap_pct: int = 0,
        type_mask: int = TYPE_MASK_ALL,
        sf_queue_max: int = 8,
        sf_ttl_seconds: int = 1800,
        max_hops_added: int = 1,
        mid: Optional[int] = None,
    ) -> bytes:
        """
        Build a signed RELAY_CTRL packet ready to inject into the daemon TX path.

        dst = 0xFF for broadcast (sets default for all relays), or a specific
        relay's node ID to target just that one.
        """
        if mid is None:
            mid = int.from_bytes(os.urandom(2), "little")

        nonce = self._next_nonce() & 0xFFFFFFFF

        # Build CTRL payload with hmac=zeros, then HMAC the whole thing
        payload_unsigned = struct.pack(
            _CTRL_FMT,
            nonce,
            int(mode),
            0,                              # flags reserved
            rssi_floor,
            duty_cap_pct,
            type_mask & 0xFFFFFFFF,
            sf_queue_max,
            sf_ttl_seconds,
            max_hops_added,
            b"\x00" * 7,                    # reserved
            b"\x00" * 8,                    # hmac placeholder
        )

        header = struct.pack(
            _HDR_FMT,
            DARKNET_MAGIC,
            DARKNET_VERSION,
            self.my_id,
            dst,
            PKT_RELAY_CTRL,
            0,                              # hops
            MAX_HOPS,                       # ttl
            0,                              # flags
            mid,
            _CTRL_SIZE,
        )

        msg = header + payload_unsigned
        tag = hmac.new(self.admin_key, msg, hashlib.sha256).digest()[:8]

        # Replace the placeholder with the real tag
        signed_payload = payload_unsigned[:-8] + tag
        return header + signed_payload

    # ─── Parse incoming STATUS ────────────────────────────────────────────
    @staticmethod
    def parse_status(pkt: bytes) -> Optional[RelayStatus]:
        """
        Parse a RELAY_STATUS packet. Accepts either:
          - the full packet (header + payload), or
          - just the payload bytes.

        Returns None if it doesn't look like a STATUS.
        """
        if len(pkt) >= _HDR_SIZE + _STATUS_SIZE:
            (magic, version, src, dst, type_, hops, ttl, flags, mid, length) = \
                struct.unpack(_HDR_FMT, pkt[:_HDR_SIZE])
            if magic != DARKNET_MAGIC or version != DARKNET_VERSION:
                return None
            if type_ != PKT_RELAY_STATUS:
                return None
            payload = pkt[_HDR_SIZE:_HDR_SIZE + _STATUS_SIZE]
        elif len(pkt) == _STATUS_SIZE:
            payload = pkt
            src = 0  # unknown if caller only handed us the payload
        else:
            return None

        (mode, flags, rssi_floor, duty_cap, type_mask,
         sf_depth, sf_max, relayed, dropped, uptime,
         last_nonce, max_hops_added, _reserved) = struct.unpack(_STATUS_FMT, payload)

        try:
            mode_e = RelayMode(mode)
        except ValueError:
            mode_e = RelayMode.OFF

        return RelayStatus(
            src=src,
            mode=mode_e,
            rssi_floor=rssi_floor,
            duty_cap_pct=duty_cap,
            type_mask=type_mask,
            sf_queue_depth=sf_depth,
            sf_queue_max=sf_max,
            relayed_count=relayed,
            dropped_count=dropped,
            uptime_seconds=uptime,
            last_nonce=last_nonce,
            max_hops_added=max_hops_added,
        )


# ─── Self-test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Round-trip sanity check
    key = b"test-key-32-bytes-long-fine-1234"
    admin = RelayAdmin(my_id=0x00, admin_key=key, nonce_state_path=None)
    pkt = admin.build_ctrl(
        dst=BROADCAST_ID,
        mode=RelayMode.ROUTED,
        rssi_floor=-110,
        duty_cap_pct=15,
    )
    print(f"Built RELAY_CTRL packet, {len(pkt)} bytes:")
    print("  hex:", pkt.hex())
    print(f"  header({_HDR_SIZE}B) + payload({_CTRL_SIZE}B) = {_HDR_SIZE + _CTRL_SIZE}B")
    assert len(pkt) == _HDR_SIZE + _CTRL_SIZE

    # Verify HMAC ourselves (same way the firmware will)
    hdr_and_payload = pkt[:_HDR_SIZE + _CTRL_SIZE]
    supplied_tag = hdr_and_payload[-8:]
    msg_zeroed = hdr_and_payload[:-8] + b"\x00" * 8
    expected = hmac.new(key, msg_zeroed, hashlib.sha256).digest()[:8]
    assert supplied_tag == expected, "HMAC mismatch!"
    print("HMAC self-check: OK")
