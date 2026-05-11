"""
DarkNet Router
--------------
Dijkstra-based route calculation on root node.
Route table broadcast to all nodes.
Each node caches routes with TTL.

Packet types added:
  ROUTE_TABLE  — root broadcasts full route table
  ROUTE_REQ    — node requests route table from root
  MSG          — addressed message with next_hop routing
  MSG_ACK      — message delivery acknowledgement
"""

import heapq
import time
import json
import logging
from typing import Dict, Optional, List, Tuple

log = logging.getLogger("darknet.router")

ROUTE_TTL     = 300   # seconds before route expires
DEFAULT_GW_ID = "*"   # wildcard default gateway key


# ── Link state graph ──────────────────────────────────────────────────────────

class LinkStateGraph:
    """
    Maintains the network topology as a weighted graph.
    Edge weight = inverse RSSI (stronger signal = lower cost).
    """

    def __init__(self):
        # {node_id: {neighbour_id: {"rssi": int, "snr": float, "last_seen": float}}}
        self.edges: Dict[str, Dict[str, dict]] = {}

    def update_link(self, node_a: str, node_b: str, rssi: int, snr: float = 0.0):
        """Report a bidirectional link between two nodes."""
        now = time.time()
        for src, dst in [(node_a, node_b), (node_b, node_a)]:
            if src not in self.edges:
                self.edges[src] = {}
            self.edges[src][dst] = {
                "rssi":      rssi,
                "snr":       snr,
                "last_seen": now,
                "cost":      self._rssi_to_cost(rssi),
            }

    def expire_links(self, max_age: float = 120.0):
        """Remove links not seen recently."""
        now = time.time()
        for node in list(self.edges.keys()):
            stale = [
                nb for nb, info in self.edges[node].items()
                if now - info["last_seen"] > max_age
            ]
            for nb in stale:
                del self.edges[node][nb]
                log.debug(f"[router] Expired link {node} ↔ {nb}")

    def nodes(self) -> List[str]:
        return list(self.edges.keys())

    def neighbours(self, node: str) -> Dict[str, dict]:
        return self.edges.get(node, {})

    @staticmethod
    def _rssi_to_cost(rssi: int) -> float:
        """Convert RSSI to routing cost. Stronger = lower cost."""
        # RSSI is negative (e.g. -72). Map to positive cost.
        # -50 → cost 1 (excellent)
        # -100 → cost 51 (poor)
        # -120 → cost 71 (very poor)
        return max(1, abs(rssi) - 49)

    def to_dict(self) -> dict:
        return self.edges


# ── Dijkstra ──────────────────────────────────────────────────────────────────

def dijkstra(graph: LinkStateGraph, source: str) -> Dict[str, dict]:
    """
    Run Dijkstra from source node.
    Returns {destination: {"next_hop": str, "cost": float, "hops": int}}
    """
    dist     = {source: 0.0}
    hops     = {source: 0}
    prev     = {source: None}
    visited  = set()
    pq       = [(0.0, source)]  # (cost, node)

    while pq:
        cost, node = heapq.heappop(pq)

        if node in visited:
            continue
        visited.add(node)

        for nb, info in graph.neighbours(node).items():
            new_cost = cost + info["cost"]
            if nb not in dist or new_cost < dist[nb]:
                dist[nb]  = new_cost
                hops[nb]  = hops[node] + 1
                prev[nb]  = node
                heapq.heappush(pq, (new_cost, nb))

    # Build route table
    routes = {}
    for dest in dist:
        if dest == source:
            continue
        # Trace back to find first hop
        next_hop = dest
        cursor   = dest
        while prev.get(cursor) != source and prev.get(cursor) is not None:
            next_hop = cursor
            cursor   = prev[cursor]
        if prev.get(cursor) == source:
            next_hop = cursor

        routes[dest] = {
            "next_hop": next_hop,
            "cost":     dist[dest],
            "hops":     hops[dest],
        }

    return routes


# ── Route table ───────────────────────────────────────────────────────────────

class RouteTable:
    """
    Per-node route cache.
    Populated from ROUTE_TABLE packets from root,
    or built locally from direct neighbours.
    """

    def __init__(self, local_node_id: str):
        self.local_node_id = local_node_id
        self.routes: Dict[str, dict] = {}
        self.default_gateway: Optional[str] = None
        self._updated_at: float = 0.0

    def update_from_root(self, routes: dict, default_gw: str = None):
        """Apply a route table received from root."""
        now = time.time()
        self.routes = {}
        for dest, info in routes.items():
            self.routes[dest] = {
                "next_hop": info["next_hop"],
                "cost":     info.get("cost", 999),
                "hops":     info.get("hops", 99),
                "expires":  now + ROUTE_TTL,
            }
        if default_gw:
            self.default_gateway = default_gw
        self._updated_at = now
        log.info(f"[router] Route table updated: {len(self.routes)} routes, gw={self.default_gateway}")

    def add_direct(self, node_id: str, rssi: int):
        """Add a directly reachable neighbour."""
        self.routes[node_id] = {
            "next_hop": "direct",
            "cost":     abs(rssi) - 49,
            "hops":     0,
            "expires":  time.time() + ROUTE_TTL,
        }

    def set_default_gateway(self, node_id: str):
        """Set default gateway — first relay heard."""
        if self.default_gateway is None:
            self.default_gateway = node_id
            log.info(f"[router] Default gateway set: {node_id}")

    def next_hop(self, destination: str) -> Optional[str]:
        """
        Get next hop toward destination.
        Falls back to default gateway if no specific route.
        Returns None if completely unreachable.
        """
        now = time.time()

        # Direct neighbour
        if destination in self.routes:
            route = self.routes[destination]
            if route["expires"] > now:
                nh = route["next_hop"]
                return destination if nh == "direct" else nh

        # Default gateway fallback
        if self.default_gateway:
            log.debug(f"[router] No route to {destination}, using default gw {self.default_gateway}")
            return self.default_gateway

        return None

    def is_stale(self) -> bool:
        """True if route table needs refreshing."""
        return time.time() - self._updated_at > ROUTE_TTL

    def expire(self):
        """Remove expired routes."""
        now = time.time()
        expired = [d for d, r in self.routes.items() if r["expires"] < now]
        for d in expired:
            del self.routes[d]

    def to_dict(self) -> dict:
        return {
            "local":   self.local_node_id,
            "gateway": self.default_gateway,
            "routes":  self.routes,
            "age":     time.time() - self._updated_at,
        }

    def serialise_for_broadcast(self) -> dict:
        """Compact form for inclusion in ROUTE_TABLE packet."""
        return {
            dest: {
                "next_hop": r["next_hop"],
                "cost":     r["cost"],
                "hops":     r["hops"],
            }
            for dest, r in self.routes.items()
        }


# ── Root route manager ────────────────────────────────────────────────────────

class RootRouter:
    """
    Runs on root node (node-00).
    Maintains full topology, recalculates routes on change,
    broadcasts route table to mesh.
    """

    def __init__(self, root_node_id: str):
        self.root_node_id = root_node_id
        self.graph        = LinkStateGraph()
        self.routes       = {}   # current calculated routes
        self._dirty       = False

    def apply_link_update(self, reporter: str, neighbours: list):
        """
        Called when a LINK packet arrives from any node.
        neighbours = [{"node_id": str, "rssi": int, "snr": float}]
        """
        for nb in neighbours:
            self.graph.update_link(
                reporter,
                nb["node_id"],
                nb.get("rssi", -100),
                nb.get("snr", 0.0),
            )
        self._dirty = True
        log.debug(f"[router] Link update from {reporter}: {[n['node_id'] for n in neighbours]}")

    def apply_hello(self, from_node: str, rssi: int, snr: float):
        """Direct link to root from a node."""
        self.graph.update_link(self.root_node_id, from_node, rssi, snr)
        self._dirty = True

    def recalculate(self) -> bool:
        """
        Run Dijkstra if topology has changed.
        Returns True if routes changed.
        """
        if not self._dirty:
            return False

        self.graph.expire_links()
        new_routes = dijkstra(self.graph, self.root_node_id)

        changed       = new_routes != self.routes
        self.routes   = new_routes
        self._dirty   = False

        if changed:
            log.info(f"[router] Routes recalculated: {len(self.routes)} destinations")
            for dest, r in sorted(self.routes.items()):
                log.info(f"  → {dest:12} via {r['next_hop']:12} hops={r['hops']} cost={r['cost']:.0f}")

        return changed

    def build_route_table_packet(self) -> dict:
        """
        Build ROUTE_TABLE packet for broadcast.
        Each node gets its specific next_hop toward every destination.
        """
        # For simplicity, broadcast full table — each node uses what it needs
        return {
            "routes":      self.routes,
            "topology":    self.graph.to_dict(),
            "root":        self.root_node_id,
            "computed_at": time.time(),
        }

    def route_to(self, destination: str) -> Optional[dict]:
        return self.routes.get(destination)

    def all_nodes(self) -> List[str]:
        return self.graph.nodes()


# ── Message routing ───────────────────────────────────────────────────────────

class MessageRouter:
    """
    Handles MSG packet construction and forwarding logic.
    Used by both root and relay nodes.
    """

    def __init__(self, local_node_id: str, route_table: RouteTable):
        self.local_node_id = local_node_id
        self.route_table   = route_table

    def build_message(self, to: str, payload: str, mid: str) -> Optional[dict]:
        """
        Build a routed MSG packet.
        Returns None if no route available.
        """
        next_hop = self.route_table.next_hop(to)
        if next_hop is None:
            log.warning(f"[router] No route to {to}")
            return None

        return {
            "t":        "MSG",
            "from":     self.local_node_id,
            "to":       to,
            "next_hop": next_hop,
            "payload":  payload,
            "mid":      mid,
            "hops":     0,
            "ttl":      10,
        }

    def should_forward(self, pkt: dict) -> bool:
        """
        Should this node forward this MSG packet?
        Only forward if we are the next_hop.
        """
        return pkt.get("next_hop") == self.local_node_id

    def forward(self, pkt: dict) -> Optional[dict]:
        """
        Forward a MSG packet toward its destination.
        Updates next_hop to the next node on the path.
        Returns None if TTL expired or no route.
        """
        ttl = pkt.get("ttl", 0) - 1
        if ttl <= 0:
            log.warning(f"[router] TTL expired: {pkt.get('mid')}")
            return None

        destination = pkt.get("to")
        if destination == self.local_node_id:
            # We ARE the destination — don't forward
            return None

        next_hop = self.route_table.next_hop(destination)
        if next_hop is None:
            log.warning(f"[router] Cannot forward to {destination}, no route")
            return None

        pkt = dict(pkt)
        pkt["next_hop"] = next_hop
        pkt["hops"]     = pkt.get("hops", 0) + 1
        pkt["ttl"]      = ttl
        return pkt


# ── Self-test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    print("=== DarkNet Router Self-Test ===\n")

    # Build a test topology:
    # node-00 (root) — relay-1 — relay-2 — node-01
    #                          ↘ relay-3 — node-02

    router = RootRouter("node-00")
    router.apply_hello("relay-1", rssi=-72, snr=9.5)
    router.apply_link_update("relay-1", [
        {"node_id": "node-00", "rssi": -72, "snr": 9.5},
        {"node_id": "relay-2", "rssi": -85, "snr": 7.0},
        {"node_id": "relay-3", "rssi": -88, "snr": 6.5},
    ])
    router.apply_link_update("relay-2", [
        {"node_id": "relay-1", "rssi": -85, "snr": 7.0},
        {"node_id": "node-01", "rssi": -90, "snr": 5.5},
    ])
    router.apply_link_update("relay-3", [
        {"node_id": "relay-1", "rssi": -88, "snr": 6.5},
        {"node_id": "node-02", "rssi": -91, "snr": 5.0},
    ])

    changed = router.recalculate()
    print(f"Routes changed: {changed}\n")

    print("Route table from root:")
    for dest, r in sorted(router.routes.items()):
        print(f"  {dest:12} → via {r['next_hop']:12} hops={r['hops']} cost={r['cost']:.0f}")

    print("\nMessage routing test:")
    rt = RouteTable("node-00")
    rt.update_from_root(router.routes)

    mr = MessageRouter("node-00", rt)
    msg = mr.build_message("node-01", "hello node-01", "test-001")
    print(f"  node-00 → node-01: {msg}")

    print("\nForward test (relay-1 forwarding toward node-01):")
    rt2 = RouteTable("relay-1")
    rt2.update_from_root(router.routes)
    mr2 = MessageRouter("relay-1", rt2)

    if msg and mr2.should_forward({**msg, "next_hop": "relay-1"}):
        forwarded = mr2.forward({**msg, "next_hop": "relay-1"})
        print(f"  relay-1 forwards: {forwarded}")
