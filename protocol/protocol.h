// protocol.h — DarkNet binary protocol v1
// Shared between Heltec bridge, T-Beam relay, and Pi daemon (via protocol.py).
// Both sides MUST stay in sync byte-for-byte.

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// ─── Constants ────────────────────────────────────────────────────────────────
#define DARKNET_MAGIC     0xDA
#define DARKNET_VERSION   1
#define BROADCAST_ID      0xFF
#define MAX_PKT_SIZE      240
#define MAX_HOPS          5

// ─── Packet types ─────────────────────────────────────────────────────────────
typedef enum {
    PKT_HELLO        = 0x01,
    PKT_PING         = 0x02,
    PKT_PONG         = 0x03,
    PKT_BEACON       = 0x04,
    PKT_STATE        = 0x05,
    PKT_ACK          = 0x06,
    PKT_LINK         = 0x07,
    PKT_RT           = 0x08,
    PKT_ROUTE_REQ    = 0x09,
    PKT_MSG          = 0x0A,
    PKT_MSG_ACK      = 0x0B,
    // Relay control plane (added in protocol v1.1)
    PKT_RELAY_CTRL   = 0x0C,
    PKT_RELAY_STATUS = 0x0D,
    PKT_NETSTATE     = 0x0E,
} PktType;

// ─── Status codes (in STATE payload) ──────────────────────────────────────────
typedef enum {
    STATUS_ONLINE  = 0,
    STATUS_BUSY    = 1,
    STATUS_AWAY    = 2,
    STATUS_OFFLINE = 3,
} NodeStatus;

// ─── Flag bits (in PktHeader.flags) ───────────────────────────────────────────
#define FLAG_SIGNED      0x01
#define FLAG_ENCRYPTED   0x02
#define FLAG_HAS_PUBKEY  0x04   // HELLO carries 32-byte pubkey appended

// ─── Packet header (12 bytes) ─────────────────────────────────────────────────
typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint8_t  version;
    uint8_t  src;
    uint8_t  dst;
    uint8_t  type;
    uint8_t  hops;
    uint8_t  ttl;
    uint8_t  flags;
    uint16_t mid;
    uint16_t len;
} PktHeader;

#define MAX_PAYLOAD_SIZE (MAX_PKT_SIZE - sizeof(PktHeader))

// ─── HELLO payload ────────────────────────────────────────────────────────────
typedef struct __attribute__((packed)) {
    uint8_t is_root;
    uint8_t is_relay;
} HelloPayload;

// ─── BEACON payload (10 bytes) ────────────────────────────────────────────────
typedef struct __attribute__((packed)) {
    float   lat;
    float   lon;
    uint8_t sats;
    uint8_t is_relay;
} BeaconPayload;

// ─── STATE payload (1 byte) ───────────────────────────────────────────────────
typedef struct __attribute__((packed)) {
    uint8_t status;
} StatePayload;

// ─── ACK / MSG_ACK payload (2 bytes) ──────────────────────────────────────────
typedef struct __attribute__((packed)) {
    uint16_t acked_mid;
} AckPayload;

// ─── LINK payload ─────────────────────────────────────────────────────────────
typedef struct __attribute__((packed)) {
    uint8_t count;
} LinkHeader;

typedef struct __attribute__((packed)) {
    uint8_t id;
    int8_t  rssi;
    int8_t  snr;
} LinkEntry;

// ─── RT payload ───────────────────────────────────────────────────────────────
typedef struct __attribute__((packed)) {
    uint8_t gateway;
    uint8_t count;
} RtHeader;

typedef struct __attribute__((packed)) {
    uint8_t dest;
    uint8_t next_hop;
    uint8_t hops;
} RtEntry;

// ─── MSG payload ──────────────────────────────────────────────────────────────
typedef struct __attribute__((packed)) {
    uint8_t next_hop;
    uint8_t payload_len;
} MsgHeader;

// ═════════════════════════════════════════════════════════════════════════════
// RELAY CONTROL PLANE (protocol v1.1)
// ═════════════════════════════════════════════════════════════════════════════

// ─── Relay modes ──────────────────────────────────────────────────────────────
// Default on boot is RELAY_MODE_FLOOD.
typedef enum {
    RELAY_MODE_OFF       = 0,  // Don't relay anything (still HELLO/BEACON so visible)
    RELAY_MODE_FLOOD     = 1,  // Dedup + TTL, repeat everything (legacy behaviour)
    RELAY_MODE_ROUTED    = 2,  // Only relay if dst is a recently-heard neighbour
    RELAY_MODE_STORE_FWD = 3,  // FLOOD + hold MSGs for offline destinations
    RELAY_MODE_SELECTIVE = 4,  // FLOOD but apply type_mask filter
} RelayMode;

// ─── Bit positions in RelayCtrl.type_mask ─────────────────────────────────────
// If a bit is set, packets of that type ARE relayed. Used only in SELECTIVE mode.
#define RELAY_TYPE_BIT(t)  (1u << ((t) & 0x1F))
#define RELAY_TYPE_MASK_ALL   0xFFFFFFFFu

// ─── RELAY_CTRL payload ───────────────────────────────────────────────────────
// Sent Pi → relay. dst = broadcast (sets default for all relays) or specific ID.
// Signed: 8-byte HMAC-SHA256(key, header || payload_without_hmac) appended.
// Recipients track highest nonce per source and reject replays (nonce <= last_seen).
//
// Layout (34 bytes total: 26 bytes of params + 8-byte HMAC):
typedef struct __attribute__((packed)) {
    uint32_t nonce;          // monotonically increasing per sender (replay protection)
    uint8_t  mode;           // RelayMode
    uint8_t  flags;          // Reserved, set to 0
    int8_t   rssi_floor;     // Min RSSI to consider relaying (e.g. -120 = effectively off)
    uint8_t  duty_cap_pct;   // Max % of time spent transmitting (1-100, 0 = unlimited)
    uint32_t type_mask;      // Bitmask of relayable PktTypes (SELECTIVE mode)
    uint16_t sf_queue_max;   // STORE_FWD: max queued packets (capped at relay's hard max)
    uint32_t sf_ttl_seconds; // STORE_FWD: how long to hold packets
    uint8_t  max_hops_added; // Max hops this relay will add (typically 1)
    uint8_t  reserved[7];    // Pad to 28 bytes, future use
    // HMAC-SHA256 truncated to 8 bytes follows
    uint8_t  hmac[8];
} RelayCtrl;

// ─── RELAY_STATUS payload ─────────────────────────────────────────────────────
// Sent relay → Pi (broadcast). Either unsolicited heartbeat or response to a
// RELAY_CTRL (so the Pi gets confirmation of the applied state).
typedef struct __attribute__((packed)) {
    uint8_t  mode;
    uint8_t  flags;
    int8_t   rssi_floor;
    uint8_t  duty_cap_pct;
    uint32_t type_mask;
    uint16_t sf_queue_depth;   // currently held packets
    uint16_t sf_queue_max;
    uint32_t relayed_count;    // packets successfully relayed since boot
    uint32_t dropped_count;    // packets dropped by policy since boot
    uint32_t uptime_seconds;
    uint32_t last_nonce;       // highest accepted nonce (helps Pi catch up after reflash)
    uint8_t  max_hops_added;
    uint8_t  reserved[3];
} RelayStatus;

// ─── Helpers ──────────────────────────────────────────────────────────────────

static inline int pkt_init(uint8_t* buf, uint8_t src, uint8_t dst,
                           uint8_t type, uint16_t mid, uint8_t flags,
                           const void* payload, uint16_t payload_len) {
    if (sizeof(PktHeader) + payload_len > MAX_PKT_SIZE) return -1;
    PktHeader* h = (PktHeader*)buf;
    h->magic   = DARKNET_MAGIC;
    h->version = DARKNET_VERSION;
    h->src     = src;
    h->dst     = dst;
    h->type    = type;
    h->hops    = 0;
    h->ttl     = MAX_HOPS;
    h->flags   = flags;
    h->mid     = mid;
    h->len     = payload_len;
    if (payload_len && payload) {
        memcpy(buf + sizeof(PktHeader), payload, payload_len);
    }
    return sizeof(PktHeader) + payload_len;
}

static inline int pkt_validate(const uint8_t* buf, size_t total_len) {
    if (total_len < sizeof(PktHeader)) return 0;
    const PktHeader* h = (const PktHeader*)buf;
    if (h->magic != DARKNET_MAGIC) return 0;
    if (h->version != DARKNET_VERSION) return 0;
    if (sizeof(PktHeader) + h->len > total_len) return 0;
    return 1;
}
