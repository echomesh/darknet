"""
DarkNet binary protocol — Python side.
Mirrors protocol.h. Both must stay in sync byte-for-byte.

Packet format on the radio:
  [12-byte PktHeader][payload bytes]

Packet format on the Heltec serial link (both directions):
  [0xAA][0x55][type_byte][len_lo][len_hi][...payload...][crc8]
  type_byte: 'R' = radio→Pi (with RxMeta prefix), 'S' = Pi→radio,
             'I' = info/log line (radio→Pi, ASCII payload)

RxMeta (4 bytes prepended to 'R' frames):
  [int16 rssi][int16 snr_x10]
"""

import struct
import secrets

# ── Constants (must match protocol.h) ─────────────────────────────────────────
MAGIC          = 0xDA
VERSION        = 1
BROADCAST_ID   = 0xFF
MAX_PKT_SIZE   = 240
MAX_HOPS       = 5

# ── Packet types ──────────────────────────────────────────────────────────────
PKT_HELLO      = 0x01
PKT_PING       = 0x02
PKT_PONG       = 0x03
PKT_BEACON     = 0x04
PKT_STATE      = 0x05
PKT_ACK        = 0x06
PKT_LINK       = 0x07
PKT_RT         = 0x08
PKT_ROUTE_REQ  = 0x09
PKT_MSG        = 0x0A
PKT_MSG_ACK    = 0x0B
PKT_RELAY_CTRL = 0x0D
PKT_NETSTATE   = 0x0E

PKT_NAMES = {
    PKT_HELLO: "HELLO", PKT_PING: "PING", PKT_PONG: "PONG",
    PKT_BEACON: "BEACON", PKT_STATE: "STATE", PKT_ACK: "ACK",
    PKT_LINK: "LINK", PKT_RT: "RT", PKT_ROUTE_REQ: "ROUTE_REQ",
    PKT_MSG: "MSG", PKT_MSG_ACK: "MSG_ACK",
}

# ── Status codes (in STATE payload) ───────────────────────────────────────────
STATUS_ONLINE    = 0
STATUS_BUSY      = 1
STATUS_AWAY      = 2
STATUS_OFFLINE   = 3

STATUS_NAMES = {
    STATUS_ONLINE: "online", STATUS_BUSY: "busy",
    STATUS_AWAY: "away", STATUS_OFFLINE: "offline",
}
STATUS_FROM_NAME = {v: k for k, v in STATUS_NAMES.items()}

# ── Flag bits ─────────────────────────────────────────────────────────────────
FLAG_SIGNED    = 0x01
FLAG_ENCRYPTED = 0x02
FLAG_HAS_PUBKEY = 0x04   # used in HELLO

# ── Header ────────────────────────────────────────────────────────────────────
HEADER_FMT  = "<BBBBBBBBHH"
HEADER_SIZE = struct.calcsize(HEADER_FMT)   # 12 bytes


def random_mid():
    return secrets.randbits(16)


def pack_header(src, dst, ptype, mid=None, hops=0, ttl=MAX_HOPS, flags=0, payload_len=0):
    """Returns (header_bytes, mid)."""
    if mid is None:
        mid = random_mid()
    return (
        struct.pack(HEADER_FMT, MAGIC, VERSION, src, dst, ptype,
                    hops, ttl, flags, mid, payload_len),
        mid,
    )


def unpack_header(buf):
    """Returns dict or None on invalid header."""
    if len(buf) < HEADER_SIZE:
        return None
    magic, ver, src, dst, ptype, hops, ttl, flags, mid, plen = \
        struct.unpack(HEADER_FMT, buf[:HEADER_SIZE])
    if magic != MAGIC or ver != VERSION:
        return None
    if HEADER_SIZE + plen > len(buf):
        return None
    return {
        "src": src, "dst": dst, "type": ptype, "hops": hops,
        "ttl": ttl, "flags": flags, "mid": mid, "len": plen,
        "payload": bytes(buf[HEADER_SIZE:HEADER_SIZE + plen]),
    }


def build_packet(src, dst, ptype, payload=b"", mid=None, hops=0, ttl=MAX_HOPS, flags=0):
    """Build a complete packet (header + payload). Returns (bytes, mid)."""
    header, mid = pack_header(src, dst, ptype, mid, hops, ttl, flags, len(payload))
    return header + payload, mid


# ── Per-packet payload pack/unpack ────────────────────────────────────────────

# HELLO: optional 32-byte pubkey + flags byte (is_root, is_relay)
# Layout: [is_root:1][is_relay:1] (+ pubkey:32 if FLAG_HAS_PUBKEY in header.flags)
HELLO_FMT = "<BB"
HELLO_SIZE = struct.calcsize(HELLO_FMT)  # 2

def pack_hello(is_root, is_relay, pubkey=None):
    base = struct.pack(HELLO_FMT, 1 if is_root else 0, 1 if is_relay else 0)
    if pubkey:
        if len(pubkey) != 32:
            raise ValueError("pubkey must be 32 bytes")
        return base + pubkey
    return base

def unpack_hello(payload):
    if len(payload) < HELLO_SIZE:
        return None
    is_root, is_relay = struct.unpack(HELLO_FMT, payload[:HELLO_SIZE])
    pubkey = payload[HELLO_SIZE:HELLO_SIZE + 32] if len(payload) >= HELLO_SIZE + 32 else None
    return {
        "is_root": bool(is_root),
        "is_relay": bool(is_relay),
        "pubkey": pubkey,
    }


# PING / PONG: empty payload (just header)
def pack_ping(): return b""
def pack_pong(): return b""


# BEACON: lat/lon/sats/is_relay
BEACON_FMT = "<ffBB"
BEACON_SIZE = struct.calcsize(BEACON_FMT)  # 10

def pack_beacon(lat=0.0, lon=0.0, sats=0, is_relay=True):
    return struct.pack(BEACON_FMT, lat, lon, sats, 1 if is_relay else 0)

def unpack_beacon(payload):
    if len(payload) < BEACON_SIZE:
        return None
    lat, lon, sats, is_relay = struct.unpack(BEACON_FMT, payload[:BEACON_SIZE])
    return {"lat": lat, "lon": lon, "sats": sats, "is_relay": bool(is_relay)}


# STATE: 1 byte status code
STATE_FMT = "<B"
STATE_SIZE = struct.calcsize(STATE_FMT)  # 1

def pack_state(status):
    if isinstance(status, str):
        status = STATUS_FROM_NAME.get(status.lower(), STATUS_ONLINE)
    return struct.pack(STATE_FMT, status)

def unpack_state(payload):
    if len(payload) < STATE_SIZE:
        return None
    status = struct.unpack(STATE_FMT, payload[:STATE_SIZE])[0]
    return {"status": status, "status_name": STATUS_NAMES.get(status, "unknown")}


# ACK: u16 acked_mid
ACK_FMT = "<H"
ACK_SIZE = struct.calcsize(ACK_FMT)  # 2

def pack_ack(acked_mid):
    return struct.pack(ACK_FMT, acked_mid)

def unpack_ack(payload):
    if len(payload) < ACK_SIZE:
        return None
    return {"acked_mid": struct.unpack(ACK_FMT, payload[:ACK_SIZE])[0]}


# LINK: count + entries [u8 id, i8 rssi, i8 snr]
def pack_link(neighbours):
    """neighbours: list of (id, rssi_dbm, snr_db). Truncated to fit MAX_PKT_SIZE."""
    max_n = (MAX_PKT_SIZE - HEADER_SIZE - 1) // 3
    neighbours = neighbours[:max_n]
    out = struct.pack("<B", len(neighbours))
    for nid, rssi, snr in neighbours:
        rssi_b = max(-128, min(127, int(rssi)))
        snr_b = max(-128, min(127, int(snr)))
        out += struct.pack("<BbB", nid, rssi_b, snr_b & 0xFF)  # snr as unsigned wrap
    return out

def unpack_link(payload):
    if len(payload) < 1:
        return None
    n = payload[0]
    out = []
    off = 1
    for _ in range(n):
        if off + 3 > len(payload):
            break
        nid, rssi = struct.unpack("<Bb", payload[off:off+2])
        snr = struct.unpack("<b", payload[off+2:off+3])[0]
        out.append({"id": nid, "rssi": rssi, "snr": snr})
        off += 3
    return {"neighbours": out}


# RT: gateway + count + entries [u8 dest, u8 next_hop, u8 hops]
def pack_rt(gateway, routes):
    """routes: dict of dest_id -> {"next_hop": id, "hops": h}."""
    max_n = (MAX_PKT_SIZE - HEADER_SIZE - 2) // 3
    items = list(routes.items())[:max_n]
    out = struct.pack("<BB", gateway, len(items))
    for dest, r in items:
        out += struct.pack("<BBB", dest, r["next_hop"], r["hops"])
    return out

def unpack_rt(payload):
    if len(payload) < 2:
        return None
    gateway, n = struct.unpack("<BB", payload[:2])
    routes = {}
    off = 2
    for _ in range(n):
        if off + 3 > len(payload):
            break
        dest, next_hop, hops = struct.unpack("<BBB", payload[off:off+3])
        routes[dest] = {"next_hop": next_hop, "hops": hops}
        off += 3
    return {"gateway": gateway, "routes": routes}


# ROUTE_REQ: empty
def pack_route_req(): return b""


# MSG: next_hop + payload_len + payload
MSG_HEADER_FMT = "<BB"
MSG_HEADER_SIZE = struct.calcsize(MSG_HEADER_FMT)  # 2

def pack_msg(next_hop, msg_payload):
    if isinstance(msg_payload, str):
        msg_payload = msg_payload.encode("utf-8")
    max_payload = MAX_PKT_SIZE - HEADER_SIZE - MSG_HEADER_SIZE
    msg_payload = msg_payload[:max_payload]
    return struct.pack(MSG_HEADER_FMT, next_hop, len(msg_payload)) + msg_payload

def unpack_msg(payload):
    if len(payload) < MSG_HEADER_SIZE:
        return None
    next_hop, plen = struct.unpack(MSG_HEADER_FMT, payload[:MSG_HEADER_SIZE])
    body = payload[MSG_HEADER_SIZE:MSG_HEADER_SIZE + plen]
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = body.hex()
    return {"next_hop": next_hop, "payload": text, "payload_bytes": bytes(body)}


# MSG_ACK: u16 acked_mid (same shape as ACK)
def pack_msg_ack(acked_mid):
    return struct.pack("<H", acked_mid)

def unpack_msg_ack(payload):
    if len(payload) < 2:
        return None
    return {"acked_mid": struct.unpack("<H", payload[:2])[0]}


# Dispatch table for unpacking by type
UNPACKERS = {
    PKT_HELLO:     unpack_hello,
    PKT_BEACON:    unpack_beacon,
    PKT_STATE:     unpack_state,
    PKT_ACK:       unpack_ack,
    PKT_LINK:      unpack_link,
    PKT_RT:        unpack_rt,
    PKT_MSG:       unpack_msg,
    PKT_MSG_ACK:   unpack_msg_ack,
    # PING, PONG, ROUTE_REQ have no payload
}


# ── Serial frame layer (Pi ↔ Heltec) ──────────────────────────────────────────
FRAME_START_1 = 0xAA
FRAME_START_2 = 0x55

FRAME_TYPE_RECV = ord('R')   # radio → Pi (binary packet, with RxMeta prefix)
FRAME_TYPE_SEND = ord('S')   # Pi → radio (binary packet to transmit)
FRAME_TYPE_INFO = ord('I')   # ASCII log line, either direction


def crc8(data):
    """Same polynomial as the Heltec firmware (CRC-8/CCITT, poly 0x07)."""
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def encode_frame(ftype, payload):
    """Build a serial frame: AA 55 <type> <len_lo> <len_hi> <payload> <crc>."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    n = len(payload)
    return bytes([FRAME_START_1, FRAME_START_2, ftype, n & 0xFF, (n >> 8) & 0xFF]) \
           + bytes(payload) + bytes([crc8(payload)])


def encode_send_frame(packet_bytes):
    return encode_frame(FRAME_TYPE_SEND, packet_bytes)


# RxMeta prefix: int16 rssi, int16 snr_x10
RX_META_FMT = "<hh"
RX_META_SIZE = struct.calcsize(RX_META_FMT)  # 4

def parse_recv_payload(payload):
    """Strip the 4-byte RxMeta prefix from an 'R' frame payload.
    Returns (rssi, snr_float, packet_bytes) or None."""
    if len(payload) < RX_META_SIZE:
        return None
    rssi, snr_x10 = struct.unpack(RX_META_FMT, payload[:RX_META_SIZE])
    return rssi, snr_x10 / 10.0, bytes(payload[RX_META_SIZE:])


class FrameParser:
    """
    Streaming parser for the Heltec serial protocol.
    Feed bytes in, get complete frames out.

    Usage:
        parser = FrameParser()
        for frame_type, payload in parser.feed(byte_chunk):
            ...
    """

    # States
    _S_WAIT1 = 0
    _S_WAIT2 = 1
    _S_TYPE  = 2
    _S_LEN_LO = 3
    _S_LEN_HI = 4
    _S_PAYLOAD = 5
    _S_CRC = 6

    def __init__(self, max_frame=MAX_PKT_SIZE + 16):
        self._state = self._S_WAIT1
        self._ftype = 0
        self._flen = 0
        self._read = 0
        self._buf = bytearray()
        self._max = max_frame

    def feed(self, data):
        """Feed raw bytes. Yields (frame_type, payload_bytes) for each complete frame."""
        for b in data:
            yield from self._feed_byte(b)

    def _feed_byte(self, b):
        if self._state == self._S_WAIT1:
            if b == FRAME_START_1:
                self._state = self._S_WAIT2
        elif self._state == self._S_WAIT2:
            if b == FRAME_START_2:
                self._state = self._S_TYPE
            elif b != FRAME_START_1:
                self._state = self._S_WAIT1
        elif self._state == self._S_TYPE:
            self._ftype = b
            self._state = self._S_LEN_LO
        elif self._state == self._S_LEN_LO:
            self._flen = b
            self._state = self._S_LEN_HI
        elif self._state == self._S_LEN_HI:
            self._flen |= (b << 8)
            if self._flen > self._max:
                self._reset()
                return
            self._buf = bytearray()
            self._read = 0
            self._state = self._S_CRC if self._flen == 0 else self._S_PAYLOAD
        elif self._state == self._S_PAYLOAD:
            self._buf.append(b)
            self._read += 1
            if self._read >= self._flen:
                self._state = self._S_CRC
        elif self._state == self._S_CRC:
            if b == crc8(bytes(self._buf)):
                yield (self._ftype, bytes(self._buf))
            self._reset()

    def _reset(self):
        self._state = self._S_WAIT1
        self._buf = bytearray()
        self._read = 0
