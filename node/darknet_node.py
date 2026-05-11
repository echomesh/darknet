"""
DarkNet Node Daemon v3 — binary protocol
----------------------------------------
- Binary PktHeader+payload over LoRa (see protocol.py / protocol.h)
- Framed binary serial to Heltec bridge
- Numeric node IDs 0-254, mapped to friendly names via ~/.darknet/nodes.json
- UI socket still speaks JSON (no airtime concern there)
"""

import serial
import serial.tools.list_ports
import threading
import json
import time
import socket
import os
import sys
import logging
import argparse
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer


from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
import base64

# Make sibling routing/ and protocol/ importable
sys.path.insert(0, str(Path(__file__).parent.parent))
from protocol import protocol as P
from routing.router import RootRouter, RouteTable, MessageRouter

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("darknet")

# ── Config ────────────────────────────────────────────────────────────────────
DARKNET_DIR     = Path.home() / ".darknet"
IDENTITY_FILE   = DARKNET_DIR / "identity.json"
NODES_FILE      = DARKNET_DIR / "nodes.json"
STATE_SOCKET    = "/tmp/darknet.sock"
HELLO_INTERVAL  = 30
PING_INTERVAL   = 15
OFFLINE_TIMEOUT = 60
ROUTE_BROADCAST = 60
ROUTE_REQ_DELAY = 10
LORA_BAUD       = 115200

STATUS_ONLINE  = "online"
STATUS_RELAY   = "relay"
STATUS_PENDING = "pending"
STATUS_REVOKED = "revoked"
STATUS_OFFLINE = "offline"

SOCK = "/tmp/darknet.sock"

def daemon_request(cmd: str):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    s.sendall(cmd.encode())
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    return data


# ── Identity ──────────────────────────────────────────────────────────────────

def b64(data):
    return base64.urlsafe_b64encode(data).decode()

def unb64(s):
    return base64.urlsafe_b64decode(s.encode())

def load_or_create_identity(node_name):
    DARKNET_DIR.mkdir(parents=True, exist_ok=True)
    if IDENTITY_FILE.exists():
        with open(IDENTITY_FILE) as f:
            d = json.load(f)
        privkey = Ed25519PrivateKey.from_private_bytes(unb64(d["privkey_b64"]))
        if node_name and node_name != d.get("node_name"):
            d["node_name"] = node_name
            with open(IDENTITY_FILE, "w") as f:
                json.dump(d, f, indent=2)
            log.info(f"Updated identity: {node_name}")
        else:
            log.info(f"Loaded identity: {d.get('node_name')}")
        return d.get("node_name", node_name), privkey
    privkey = Ed25519PrivateKey.generate()
    pubkey  = privkey.public_key()
    data = {
        "node_name":   node_name,
        "privkey_b64": b64(privkey.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
        "pubkey_b64":  b64(pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw)),
    }
    with open(IDENTITY_FILE, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(IDENTITY_FILE, 0o600)
    log.info(f"Generated identity: {node_name}")
    return node_name, privkey

def get_pubkey_bytes(privkey):
    return privkey.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


# ── Node name ↔ byte-ID mapping ───────────────────────────────────────────────

class NodeMap:
    """
    Map between friendly names ("NODE-00", "tbeam-relay-01") and byte IDs (0-254).
    Backed by ~/.darknet/nodes.json. UI uses names; radio uses bytes.
    """

    def __init__(self, path=NODES_FILE):
        self.path = path
        self._name_to_id = {}
        self._id_to_name = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                with open(self.path) as f:
                    data = json.load(f)
                for name, nid in data.items():
                    nid = int(nid)
                    self._name_to_id[name] = nid
                    self._id_to_name[nid] = name
                log.info(f"Loaded {len(data)} node mappings")
            except Exception as e:
                log.error(f"Failed to load {self.path}: {e}")

    def _save(self):
        try:
            data = dict(sorted(self._name_to_id.items(), key=lambda kv: kv[1]))
            with open(self.path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            log.error(f"Failed to save {self.path}: {e}")

    def name_to_id(self, name):
        with self._lock:
            return self._name_to_id.get(name)

    def id_to_name(self, nid):
        with self._lock:
            return self._id_to_name.get(nid, f"node-0x{nid:02X}")

    def has_id(self, nid):
        with self._lock:
            return nid in self._id_to_name

    def assign(self, name, nid):
        """Assign a name to a specific ID. Persists to disk."""
        with self._lock:
            # Remove old mappings if any
            if name in self._name_to_id:
                old = self._name_to_id[name]
                self._id_to_name.pop(old, None)
            if nid in self._id_to_name:
                old_name = self._id_to_name[nid]
                self._name_to_id.pop(old_name, None)
            self._name_to_id[name] = nid
            self._id_to_name[nid] = name
            self._save()

    def all(self):
        with self._lock:
            return dict(self._id_to_name)


# ── Serial discovery ──────────────────────────────────────────────────────────

def find_lora_port():
    for p in serial.tools.list_ports.comports():
        if any(x in (p.description or "").lower() for x in ["cp210", "ch340", "silicon labs"]):
            return p.device
    for path in ["/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyACM0"]:
        if os.path.exists(path):
            return path
    raise RuntimeError("No LoRa serial port found")


# ── Node info ─────────────────────────────────────────────────────────────────

class NodeInfo:
    def __init__(self, node_id, name=None):
        self.node_id   = node_id          # byte
        self.name      = name or f"node-0x{node_id:02X}"
        self.pubkey    = b""
        self.status    = STATUS_OFFLINE
        self.rssi      = 0
        self.snr       = 0.0
        self.last_seen = 0.0
        self.hops      = 0
        self.state     = {}
        self.is_relay  = False
        self.is_root   = False

    def is_online(self):
        return time.time() - self.last_seen < OFFLINE_TIMEOUT

    def effective_status(self):
        if self.status == STATUS_REVOKED:
            return STATUS_REVOKED
        if not self.is_online():
            return STATUS_OFFLINE
        return self.status

    def to_dict(self):
        return {
            "node_id":   self.name,            # UI uses name as ID string
            "byte_id":   self.node_id,         # numeric ID for diagnostics
            "pubkey":    b64(self.pubkey) if self.pubkey else "",
            "status":    self.effective_status(),
            "rssi":      self.rssi,
            "snr":       self.snr,
            "last_seen": self.last_seen,
            "hops":      self.hops,
            "state":     self.state,
            "is_relay":  self.is_relay,
            "is_root":   self.is_root,
        }


# __ 

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/nodes":
            data = daemon_request("GET_NODES")
            self._send(data)

        elif self.path == "/api/inbox":
            data = daemon_request("GET_INBOX")
            self._send(data)

    def do_POST(self):
        length = int(self.headers['Content-Length'])
        body = self.rfile.read(length).decode()

        if self.path == "/api/send_msg":
            daemon_request("SEND_MSG:" + body)
            self._send(b"OK")

        elif self.path == "/api/ping":
            daemon_request("PING:" + body)
            self._send(b"OK")

    def _send(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data if isinstance(data, bytes) else data.encode())

# ── Main daemon ───────────────────────────────────────────────────────────────

class DarkNetNode:
    def __init__(self, node_name, my_byte_id, lora_port=None,
                 is_root=False, is_relay=False):
        self.node_name, self.privkey = load_or_create_identity(node_name)
        self.pubkey_bytes = get_pubkey_bytes(self.privkey)
        self.my_id        = my_byte_id
        self.is_root      = is_root
        self.is_relay     = is_relay
        self.nodes        = {}                # byte_id -> NodeInfo
        self._lock        = threading.Lock()
        self._running     = False
        self._ser         = None
        self._ser_lock    = threading.Lock()
        self._state       = STATUS_ONLINE
        self._pending     = {}                # mid -> ts
        self._seen_mids   = {}                # (mid, src) -> ts
        self._inbox       = []
        self._known_pubkeys = set()           # byte_ids we've seen pubkey for

        self.node_map     = NodeMap()
        # Ensure our own mapping is present
        if not self.node_map.has_id(my_byte_id):
            self.node_map.assign(node_name, my_byte_id)

        # Routing modules — note: these may need updating to use byte IDs
        # internally. For now we pass byte IDs as integers.
        self.route_table  = RouteTable(self.my_id)
        self.msg_router   = MessageRouter(self.my_id, self.route_table)
        self.root_router  = RootRouter(self.my_id) if is_root else None
        self._route_req_sent = False

        # Self entry in node table
        me = NodeInfo(self.my_id, self.node_name)
        me.status    = STATUS_ONLINE
        me.pubkey    = self.pubkey_bytes
        me.last_seen = time.time()
        me.is_relay  = is_relay
        me.is_root   = is_root
        self.nodes[self.my_id] = me

        self._port   = lora_port or find_lora_port()
        self._parser = P.FrameParser()
        log.info(f"Node: {node_name} (id=0x{my_byte_id:02X}) | "
                 f"root={is_root} relay={is_relay} | {self._port}")

    # ── Send helpers ──────────────────────────────────────────────────────────

    def _send_packet(self, dst, ptype, payload=b"", mid=None, flags=0):
        """Build and transmit a packet over the radio."""
        pkt, mid = P.build_packet(self.my_id, dst, ptype, payload,
                                  mid=mid, flags=flags)
        if len(pkt) > P.MAX_PKT_SIZE:
            log.warning(f"Pkt too large: {len(pkt)}b [{P.PKT_NAMES.get(ptype)}]")
            return None
        frame = P.encode_send_frame(pkt)
        with self._ser_lock:
            if self._ser and self._ser.is_open:
                try:
                    self._ser.write(frame)
                except Exception as e:
                    log.error(f"Serial write: {e}")
                    return None
        return mid

    # ── Receive ───────────────────────────────────────────────────────────────

    def _on_lora_recv(self, pkt_bytes, rssi, snr):
        hdr = P.unpack_header(pkt_bytes)
        if hdr is None:
            log.debug(f"Invalid pkt ({len(pkt_bytes)}b)")
            return

        from_id  = hdr["src"]
        ptype    = hdr["type"]
        if from_id == self.my_id:
            return

        # Update node table
        with self._lock:
            if from_id not in self.nodes:
                name = self.node_map.id_to_name(from_id)
                self.nodes[from_id] = NodeInfo(from_id, name)
                log.info(f"New node: {name} (0x{from_id:02X})")
            n = self.nodes[from_id]
            n.last_seen = time.time()
            n.rssi      = rssi
            n.snr       = snr
            n.hops      = hdr["hops"]
            if n.status != STATUS_REVOKED:
                n.status = STATUS_ONLINE if n.hops == 0 else STATUS_RELAY

        # Hand off to routing layer for direct-neighbour discovery
        if self.is_root:
            self.root_router.apply_hello(from_id, rssi, snr)
            if self.root_router.recalculate():
                self._broadcast_route_table()

        if not self.is_root and self.route_table.default_gateway is None:
            self.route_table.set_default_gateway(from_id)
            self.route_table.add_direct(from_id, rssi)

        key = (hdr["mid"], hdr["src"])

        if key in self._seen_mids:
            return

        self._seen_mids[key] = time.time()

        # Dispatch
        handlers = {
            P.PKT_HELLO:     self._handle_hello,
            P.PKT_PING:      self._handle_ping,
            P.PKT_PONG:      self._handle_pong,
            P.PKT_BEACON:    self._handle_beacon,
            P.PKT_STATE:     self._handle_state,
            P.PKT_ACK:       self._handle_ack,
            P.PKT_LINK:      self._handle_link,
            P.PKT_RT:        self._handle_rt,
            P.PKT_ROUTE_REQ: self._handle_route_req,
            P.PKT_MSG:       self._handle_msg,
            P.PKT_MSG_ACK:   self._handle_msg_ack,
            P.PKT_RELAY_CTRL: self._handle_relay_ctrl,
            P.PKT_NETSTATE: self._handle_netstate,
        }
        h = handlers.get(ptype)
        if h:
            h(hdr, from_id, rssi, snr)
        else:
            log.warning(f"Unknown pkt type 0x{ptype:02X} from 0x{from_id:02X}")

    # ── Handlers ──────────────────────────────────────────────────────────────

    def _handle_hello(self, hdr, from_id, rssi, snr):
        body = P.unpack_hello(hdr["payload"])
        if body is None:
            return
        log.info(f"HELLO from {self.node_map.id_to_name(from_id)} "
                f"(root={body['is_root']} relay={body['is_relay']})")
        
        need_to_send_pubkey = False
        with self._lock:
            n = self.nodes[from_id]
            n.is_relay = body["is_relay"]
            n.is_root  = body["is_root"]
            if body["pubkey"] and not n.pubkey:
                n.pubkey = body["pubkey"]
                self._known_pubkeys.add(from_id)
                log.info(f"Got pubkey for 0x{from_id:02X}")
            # If THEY didn't include their pubkey AND we don't have it,
            # they need to know we want it. But replying with our own
            # HELLO doesn't help that — only kicks off a storm.
            # Just don't reply.

        # Trigger one-time route table request (still useful)
        if not self.is_root and not self._route_req_sent:
            threading.Timer(ROUTE_REQ_DELAY, self._request_route_table).start()
            self._route_req_sent = True

        # NO REPLY HERE.
        # Periodic _broadcast_hello() (every HELLO_INTERVAL) covers pubkey distribution.
        # Including FLAG_HAS_PUBKEY in every periodic broadcast means new nodes
        # learn pubkeys within one HELLO interval (~30s) without storms.

    def _handle_ping(self, hdr, from_id, rssi, snr):
        self._send_packet(from_id, P.PKT_PONG)

    def _handle_pong(self, hdr, from_id, rssi, snr):
        pass

    def _handle_beacon(self, hdr, from_id, rssi, snr):
        body = P.unpack_beacon(hdr["payload"])
        if body is None:
            return
        with self._lock:
            n = self.nodes[from_id]
            n.is_relay = body["is_relay"]
            if body["lat"] != 0.0 or body["lon"] != 0.0:
                n.state["lat"] = body["lat"]
                n.state["lng"] = body["lon"]
                n.state["sat"] = body["sats"]
        log.info(f"BEACON from 0x{from_id:02X} rssi={rssi} "
                 f"{'GPS:%.4f,%.4f' % (body['lat'], body['lon']) if body['lat'] else 'no fix'}")

    def _handle_state(self, hdr, from_id, rssi, snr):
        body = P.unpack_state(hdr["payload"])
        if body is None:
            return
        with self._lock:
            self.nodes[from_id].state["status"] = body["status_name"]
        # ACK the state update
        self._send_packet(from_id, P.PKT_ACK, P.pack_ack(hdr["mid"]))
        log.info(f"STATE from 0x{from_id:02X}: {body['status_name']}")

    def _handle_ack(self, hdr, from_id, rssi, snr):
        body = P.unpack_ack(hdr["payload"])
        if body is None:
            return
        with self._lock:
            self._pending.pop(body["acked_mid"], None)
            if from_id in self.nodes and self.nodes[from_id].status == STATUS_PENDING:
                self.nodes[from_id].status = STATUS_ONLINE

    def _handle_link(self, hdr, from_id, rssi, snr):
        if not self.is_root:
            return
        body = P.unpack_link(hdr["payload"])
        if body is None:
            return
        # Convert to format the existing router expects
        nb = [{"node_id": e["id"], "rssi": e["rssi"], "snr": e["snr"]}
              for e in body["neighbours"]]
        self.root_router.apply_link_update(from_id, nb)
        if self.root_router.recalculate():
            self._broadcast_route_table()

    def _handle_rt(self, hdr, from_id, rssi, snr):
        body = P.unpack_rt(hdr["payload"])
        if body is None:
            return
        routes = {dest: {"next_hop": r["next_hop"], "hops": r["hops"], "cost": 0}
                  for dest, r in body["routes"].items()}
        self.route_table.update_from_root(routes, body["gateway"])
        log.info(f"RT from 0x{from_id:02X}: {len(routes)} routes")

    def _handle_route_req(self, hdr, from_id, rssi, snr):
        if self.is_root:
            self._broadcast_route_table()
    
    def _handle_relay_ctrl(self, hdr, from_id, rssi, snr):
        log.info(f"RELAY_CTRL from 0x{from_id:02X}")

    def _handle_msg(self, hdr, from_id, rssi, snr):
        body = P.unpack_msg(hdr["payload"])
        if body is None:
            return
        dst = hdr["dst"]
        mid = hdr["mid"]
        if dst == self.my_id:
            from_name = self.node_map.id_to_name(from_id)
            log.info(f"📨 MSG from {from_name}: {body['payload'][:60]}")
            with self._lock:
                if not any(m["mid"] == mid for m in self._inbox):
                    self._inbox.append({
                        "from": from_name,
                        "from_id": from_id,
                        "payload": body["payload"],
                        "mid": mid,
                        "ts": time.time(),
                    })
            # ACK
            self._send_packet(from_id, P.PKT_MSG_ACK, P.pack_msg_ack(mid))
            return

        # Forward
        key = (mid, hdr["src"])
        if key in self._seen_mids:
            return
        self._seen_mids[key] = time.time()
        if hdr["ttl"] == 0 or hdr["hops"] >= P.MAX_HOPS:
            return

        # Look up next hop
        next_hop = None
        if dst in self.route_table.routes:
            next_hop = self.route_table.routes[dst].get("next_hop")
        if next_hop is None and self.route_table.default_gateway is not None:
            next_hop = self.route_table.default_gateway
        if next_hop is None:
            log.warning(f"No route to forward MSG to 0x{dst:02X}")
            return

        # Repack with bumped hops/ttl and new next_hop
        new_payload = P.pack_msg(next_hop, body["payload_bytes"])
        # We use original src/mid so dedup works mesh-wide
        pkt, _ = P.build_packet(hdr["src"], dst, P.PKT_MSG, new_payload,
                                mid=mid, hops=hdr["hops"] + 1,
                                ttl=hdr["ttl"] - 1, flags=hdr["flags"])
        frame = P.encode_send_frame(pkt)
        with self._ser_lock:
            if self._ser and self._ser.is_open:
                self._ser.write(frame)
        log.info(f"Fwd MSG mid={mid} → 0x{next_hop:02X}")

    def _handle_msg_ack(self, hdr, from_id, rssi, snr):
        body = P.unpack_msg_ack(hdr["payload"])
        if body is None:
            return
        with self._lock:
            self._pending.pop(body["acked_mid"], None)
        log.info(f"MSG_ACK from 0x{from_id:02X} for mid={body['acked_mid']}")

    def _handle_netstate(self, hdr, from_id, rssi, snr):
        body = P.unpack_netstate(hdr["payload"])
        if body is None:
            return

        key = body["key"]
        incoming_version = body["version"]

        with self._lock:
            local = self._network_state.get(key)

            if (local is None or
                incoming_version > local["version"]):

                self._network_state[key] = {
                    "value": body["value"],
                    "version": incoming_version,
                    "updated_by": from_id,
                    "updated_at": time.time()
                }

                log.info(
                    f"NETSTATE {key}={body['value']} v{incoming_version} "
                    f"from 0x{from_id:02X}"
                )

                # Rebroadcast
                self._send_packet(
                    P.BROADCAST_ID,
                    P.PKT_NETSTATE,
                    hdr["payload"],
                    mid=hdr["mid"]
                )

    def set_flame(self, value):
        with self._lock:
            current = self._network_state["flame"]

            version = current["version"] + 1

            self._network_state["flame"] = {
                "value": value,
                "version": version,
                "updated_by": self.my_id,
                "updated_at": time.time()
            }

        payload = P.pack_netstate(
            "flame",
            value,
            version
        )

        self._send_packet(
            P.BROADCAST_ID,
            P.PKT_NETSTATE,
            payload
        )

    # ── Broadcasts ────────────────────────────────────────────────────────────

    def _broadcast_hello(self):
        # Always include pubkey in periodic broadcasts (small cost,
        # helps new nodes learn ours)
        flags = P.FLAG_HAS_PUBKEY
        payload = P.pack_hello(self.is_root, self.is_relay, self.pubkey_bytes)
        self._send_packet(P.BROADCAST_ID, P.PKT_HELLO, payload, flags=flags)
        log.info("Broadcast HELLO")

    def _broadcast_route_table(self):
        if not self.is_root:
            return
        # Reformat router output into byte-id keyed dict
        routes = {}
        for dest, r in self.root_router.routes.items():
            routes[int(dest)] = {"next_hop": int(r["next_hop"]), "hops": int(r["hops"])}

        # Also apply locally
        full = {dest: {"next_hop": r["next_hop"], "hops": r["hops"], "cost": r.get("cost", 0)}
                for dest, r in routes.items()}
        self.route_table.update_from_root(full, self.my_id)

        payload = P.pack_rt(self.my_id, routes)
        self._send_packet(P.BROADCAST_ID, P.PKT_RT, payload)
        log.info(f"Broadcast RT: {len(routes)} routes")

    def _request_route_table(self):
        self._send_packet(P.BROADCAST_ID, P.PKT_ROUTE_REQ)
        log.info("Requested route table")

    def _report_links(self):
        with self._lock:
            nb = [(nid, n.rssi, int(n.snr))
                  for nid, n in self.nodes.items()
                  if nid != self.my_id and n.is_online()]
        if nb:
            payload = P.pack_link(nb)
            self._send_packet(P.BROADCAST_ID, P.PKT_LINK, payload)

    def broadcast_state(self, status_name):
        status_code = P.STATUS_FROM_NAME.get(status_name.lower(), P.STATUS_ONLINE)
        with self._lock:
            self._state = status_name
            self.nodes[self.my_id].state["status"] = status_name
        payload = P.pack_state(status_code)
        mid = self._send_packet(P.BROADCAST_ID, P.PKT_STATE, payload)
        if mid is not None:
            with self._lock:
                self._pending[mid] = time.time()
        log.info(f"State: {status_name}")

    def send_message(self, to_name, payload):
        """Send a message to a node by name. Returns True on success."""
        to_id = self.node_map.name_to_id(to_name)
        if to_id is None:
            log.warning(f"Unknown destination: {to_name}")
            return False

        # Direct neighbour?
        with self._lock:
            direct = (to_id in self.nodes
                      and self.nodes[to_id].is_online()
                      and self.nodes[to_id].hops == 0)

        if direct:
            next_hop = to_id
        elif to_id in self.route_table.routes:
            next_hop = self.route_table.routes[to_id]["next_hop"]
        elif self.route_table.default_gateway is not None:
            next_hop = self.route_table.default_gateway
        else:
            log.warning(f"No route to {to_name}")
            return False

        msg_payload = P.pack_msg(next_hop, payload)
        mid = self._send_packet(to_id, P.PKT_MSG, msg_payload)
        if mid is None:
            return False
        with self._lock:
            self._pending[mid] = time.time()
        log.info(f"MSG → {to_name} (0x{to_id:02X}) via 0x{next_hop:02X}")
        return True

    # ── Serial loops ──────────────────────────────────────────────────────────

    def _rx_loop(self):
        while self._running:
            try:
                chunk = self._ser.read(256)
                if not chunk:
                    continue
                for ftype, payload in self._parser.feed(chunk):
                    self._on_frame(ftype, payload)
            except serial.SerialException as e:
                log.error(f"Serial: {e}")
                time.sleep(1)
            except Exception as e:
                log.error(f"RX: {e}")
                time.sleep(0.1)

    def _on_frame(self, ftype, payload):
        if ftype == P.FRAME_TYPE_RECV:
            parsed = P.parse_recv_payload(payload)
            if parsed is None:
                log.warning("Bad RECV frame (too short for RxMeta)")
                return
            rssi, snr, pkt_bytes = parsed
            self._on_lora_recv(pkt_bytes, rssi, snr)
        elif ftype == P.FRAME_TYPE_INFO:
            text = payload.decode("utf-8", errors="replace")
            log.info(f"Heltec: {text}")
            if text == "READY":
                # Heltec just rebooted — re-broadcast our HELLO
                time.sleep(0.5)
                self._broadcast_hello()
        else:
            log.warning(f"Unknown frame type 0x{ftype:02X}")

    def _hello_loop(self):
        time.sleep(5)
        while self._running:
            self._broadcast_hello()
            time.sleep(HELLO_INTERVAL)

    def _ping_loop(self):
        time.sleep(10)
        while self._running:
            self._send_packet(P.BROADCAST_ID, P.PKT_PING)
            time.sleep(PING_INTERVAL)

    def _link_report_loop(self):
        time.sleep(20)
        while self._running:
            if not self.is_root:
                self._report_links()
            time.sleep(30)

    def _route_broadcast_loop(self):
        time.sleep(15)
        while self._running:
            if self.is_root:
                self.root_router.recalculate()
                self._broadcast_route_table()
            time.sleep(ROUTE_BROADCAST)

    def _expire_loop(self):
        while self._running:
            now = time.time()
            with self._lock:
                for k in [k for k, t in self._pending.items() if now - t > 60]:
                    del self._pending[k]
                for k in [k for k, t in self._seen_mids.items() if now - t > 60]:
                    del self._seen_mids[k]
                self.nodes[self.my_id].last_seen = now
            self.route_table.expire()
            time.sleep(5)

    # ── UI socket (still JSON) ────────────────────────────────────────────────

    def _socket_server(self):
        if os.path.exists(STATE_SOCKET):
            os.remove(STATE_SOCKET)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(STATE_SOCKET)
        srv.listen(5)
        srv.settimeout(1)
        log.info(f"UI socket: {STATE_SOCKET}")
        while self._running:
            try:
                conn, _ = srv.accept()
                try:
                    cmd = conn.recv(2048).decode().strip()
                    if cmd == "GET_NODES":
                        with self._lock:
                            data = [n.to_dict() for n in self.nodes.values()]
                        conn.sendall(json.dumps(data).encode())
                    elif cmd == "GET_ROUTES":
                        conn.sendall(json.dumps(self.route_table.to_dict()).encode())
                    elif cmd == "GET_INBOX":
                        with self._lock:
                            conn.sendall(json.dumps(self._inbox).encode())
                    elif cmd.startswith("SET_STATE:"):
                        st = json.loads(cmd[10:])
                        self.broadcast_state(st.get("status", "online"))
                        conn.sendall(b"OK")
                    elif cmd.startswith("SEND_MSG:"):
                        try:
                            data = json.loads(cmd[9:])
                            ok = self.send_message(
                                data["to"],
                                data["payload"]
                            )
                            conn.sendall(b"OK" if ok else b"ERR:send_failed")
                        except Exception as e:
                            conn.sendall(f"ERR:{e}".encode())
                    elif cmd.startswith("SEND_RAW:"):
                        hex_data = cmd[9:]
                        try:
                            raw = bytes.fromhex(hex_data)
                        except ValueError:
                            conn.sendall(b"ERR:bad_hex")
                        else:
                            if len(raw) > P.MAX_PKT_SIZE:
                                conn.sendall(b"ERR:too_large")
                            else:
                                frame = P.encode_send_frame(raw)
                                with self._ser_lock:
                                    if self._ser and self._ser.is_open:
                                        try:
                                            self._ser.write(frame)
                                            conn.sendall(b"OK")
                                        except Exception as e:
                                            conn.sendall(f"ERR:write_failed:{e}".encode())
                                    else:
                                        conn.sendall(b"ERR:no_serial")
                    else:
                        conn.sendall(b"ERR:unknown_cmd")
                finally:
                    conn.close()
            except socket.timeout:
                continue
            except Exception as e:
                log.error(f"Socket: {e}")

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        self._running = True
        self._ser = serial.Serial(self._port, LORA_BAUD, timeout=0.1)
        time.sleep(2)
        for fn in [self._rx_loop, self._hello_loop, self._ping_loop,
                   self._link_report_loop, self._route_broadcast_loop,
                   self._expire_loop, self._socket_server]:
            threading.Thread(target=fn, daemon=True).start()
        log.info(f"DarkNet started: {self.node_name} (id=0x{self.my_id:02X})")

    def stop(self):
        self._running = False
        if self._ser:
            self._ser.close()

    def get_nodes(self):
        with self._lock:
            return [n.to_dict() for n in self.nodes.values()]


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--node-name", default=socket.gethostname(),
                        help="Friendly node name")
    parser.add_argument("--node-id",   type=lambda x: int(x, 0), required=True,
                        help="Byte node ID 0-254 (decimal or 0x-prefixed hex)")
    parser.add_argument("--port",      default=None)
    parser.add_argument("--root",      action="store_true")
    parser.add_argument("--relay",     action="store_true")
    args = parser.parse_args()

    if not (0 <= args.node_id <= 254):
        log.error("--node-id must be 0-254 (255 is reserved for broadcast)")
        sys.exit(1)

    node = DarkNetNode(args.node_name, args.node_id, args.port,
                       args.root, args.relay)
    node.start()

    try:
        while True:
            tag = "[ROOT]" if node.is_root else "[RELAY]" if node.is_relay else ""
            print(f"\n── {node.node_name} (0x{node.my_id:02X}) {tag} ──")
            for n in sorted(node.get_nodes(), key=lambda x: x["byte_id"]):
                print(f"  0x{n['byte_id']:02X} {n['node_id']:18} "
                      f"{n['status']:8} rssi={n['rssi']:4} hops={n['hops']}")
            with node._lock:
                recent = [m for m in node._inbox if time.time() - m["ts"] < 30]
                for msg in recent[-3:]:
                    print(f"  📨 {msg['from']}: {msg['payload'][:50]}")
            time.sleep(5)
    except KeyboardInterrupt:
        node.stop()
        print("\nStopped.")
