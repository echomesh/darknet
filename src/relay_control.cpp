// relay_control.cpp — Relay policy engine implementation
//
// Uses mbedTLS (bundled with ESP-IDF / Arduino-ESP32) for HMAC-SHA256.
// If you move this to another platform without mbedTLS, swap the helper at the
// bottom for any HMAC-SHA256 implementation that produces a 32-byte tag.

#include "relay_control.h"
#include <Arduino.h>
#include <string.h>
#include "mbedtls/md.h"

// ─────────────────────────────────────────────────────────────
// State
// ─────────────────────────────────────────────────────────────
static uint8_t        s_my_id = 0;
static const uint8_t* s_key = nullptr;
static size_t         s_key_len = 0;
static relay_tx_fn    s_tx = nullptr;

// Current policy (defaults: full FLOOD, no filters, no caps)
static uint8_t  s_mode          = RELAY_MODE_FLOOD;
static uint8_t  s_flags_unused  = 0;
static int8_t   s_rssi_floor    = -128;   // hear anything we can decode
static uint8_t  s_duty_cap_pct  = 0;      // 0 = unlimited
static uint32_t s_type_mask     = RELAY_TYPE_MASK_ALL;
static uint16_t s_sf_queue_max  = 8;
static uint32_t s_sf_ttl_s      = 1800;   // 30 min
static uint8_t  s_max_hops_add  = 1;

// Per-source replay protection
struct NonceEntry { uint8_t src; uint32_t last_nonce; uint32_t ts; };
#define NONCE_TABLE_SIZE 16
static NonceEntry s_nonces[NONCE_TABLE_SIZE] = {};

// Recently-heard neighbours (for ROUTED mode)
struct NbrEntry { uint8_t id; uint32_t last_heard; };
#define NBR_TABLE_SIZE 32
#define NBR_TTL_MS     (10 * 60 * 1000)   // 10 min
static NbrEntry s_nbrs[NBR_TABLE_SIZE] = {};

// Store-and-forward queue
struct SfEntry {
    uint8_t  dst;
    uint32_t enqueued_at;
    uint16_t len;
    uint8_t  pkt[MAX_PKT_SIZE];
};
static SfEntry s_sf[SF_QUEUE_HARD_MAX] = {};
static uint16_t s_sf_depth = 0;

// Counters / housekeeping
static uint32_t s_relayed_count = 0;
static uint32_t s_dropped_count = 0;
static uint32_t s_boot_ms       = 0;
static uint32_t s_last_status_ms = 0;

// Duty-cycle accounting: simple sliding-window estimate.
// Track airtime over the last DUTY_WINDOW_MS; if it exceeds the cap, suppress relays.
#define DUTY_WINDOW_MS 60000
static uint32_t s_window_start_ms = 0;
static uint32_t s_window_airtime_ms = 0;

// Highest nonce we've seen from any source — exported in STATUS so the Pi can
// catch up after a relay reflash without us tracking per-sender there.
static uint32_t s_last_accepted_nonce = 0;

// ─────────────────────────────────────────────────────────────
// Forward decls
// ─────────────────────────────────────────────────────────────
static bool  verify_ctrl_hmac(const uint8_t* pkt, size_t len);
static bool  check_and_record_nonce(uint8_t src, uint32_t nonce);
static void  apply_ctrl(const RelayCtrl* c);
static void  remember_neighbour(uint8_t id);
static bool  neighbour_known(uint8_t id);
static void  sf_enqueue(const uint8_t* pkt, size_t len, uint8_t dst);
static void  sf_flush_for(uint8_t dst);
static void  sf_gc();
static bool  duty_allows();
static void  emit_status();

// ─────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────
void relay_ctrl_init(uint8_t my_id,
                     const uint8_t* admin_key, size_t key_len,
                     relay_tx_fn tx) {
    s_my_id = my_id;
    s_key = admin_key;
    s_key_len = key_len;
    s_tx = tx;
    s_boot_ms = millis();
    s_last_status_ms = s_boot_ms;
    s_window_start_ms = s_boot_ms;
}

bool relay_should_relay(const uint8_t* pkt, size_t len, int16_t rssi) {
    const PktHeader* h = (const PktHeader*)pkt;

    // Universal gates
    if (s_mode == RELAY_MODE_OFF) {
        s_dropped_count++;
        return false;
    }
    if (rssi < s_rssi_floor) {
        s_dropped_count++;
        return false;
    }
    if (!duty_allows()) {
        s_dropped_count++;
        return false;
    }

    // Mode-specific
    switch (s_mode) {
        case RELAY_MODE_FLOOD:
            return true;

        case RELAY_MODE_SELECTIVE: {
            if (!(s_type_mask & RELAY_TYPE_BIT(h->type))) {
                s_dropped_count++;
                return false;
            }
            return true;
        }

        case RELAY_MODE_ROUTED: {
            // Always relay broadcasts (HELLO/BEACON/RT need to propagate)
            if (h->dst == BROADCAST_ID) return true;
            // Otherwise only relay if we've recently heard the destination
            if (neighbour_known(h->dst)) return true;
            s_dropped_count++;
            return false;
        }

        case RELAY_MODE_STORE_FWD: {
            // Broadcasts: behave like FLOOD
            if (h->dst == BROADCAST_ID) return true;
            // Known neighbour: relay normally
            if (neighbour_known(h->dst)) return true;
            // Unknown destination: only store MSGs (storing HELLOs makes no sense)
            if (h->type == PKT_MSG) {
                sf_enqueue(pkt, len, h->dst);
            }
            // We've handled it (either stored or ignored), don't relay now
            return false;
        }

        default:
            return false;
    }
}

bool relay_ctrl_handle_packet(const uint8_t* pkt, size_t len) {
    const PktHeader* h = (const PktHeader*)pkt;
    if (h->type != PKT_RELAY_CTRL) return false;
    if (h->len != sizeof(RelayCtrl)) return true;   // malformed, consumed
    if (len < sizeof(PktHeader) + sizeof(RelayCtrl)) return true;

    // Address filter: targeted at us, or broadcast
    if (h->dst != s_my_id && h->dst != BROADCAST_ID) return true;

    const RelayCtrl* c = (const RelayCtrl*)(pkt + sizeof(PktHeader));

    // Verify HMAC
    if (!verify_ctrl_hmac(pkt, len)) {
        s_dropped_count++;
        return true;
    }

    // Replay protection
    if (!check_and_record_nonce(h->src, c->nonce)) {
        return true;
    }

    apply_ctrl(c);

    // Echo a STATUS so the Pi gets confirmation
    emit_status();
    return true;
}

void relay_ctrl_on_hello(uint8_t src) {
    remember_neighbour(src);
    if (s_mode == RELAY_MODE_STORE_FWD && s_sf_depth > 0) {
        sf_flush_for(src);
    }
}

void relay_ctrl_note_tx(size_t airtime_ms) {
    uint32_t now = millis();
    if ((now - s_window_start_ms) >= DUTY_WINDOW_MS) {
        s_window_start_ms = now;
        s_window_airtime_ms = 0;
    }
    s_window_airtime_ms += airtime_ms;
    s_relayed_count++;
}

void relay_ctrl_loop() {
    uint32_t now = millis();

    // Periodic status heartbeat
    if ((now - s_last_status_ms) >= STATUS_HEARTBEAT_MS) {
        s_last_status_ms = now;
        emit_status();
    }

    // Periodic SF garbage collection
    static uint32_t last_gc = 0;
    if ((now - last_gc) >= 30000) {
        last_gc = now;
        sf_gc();
    }
}

void relay_ctrl_get_status(RelayStatus* out) {
    memset(out, 0, sizeof(*out));
    out->mode          = s_mode;
    out->flags         = s_flags_unused;
    out->rssi_floor    = s_rssi_floor;
    out->duty_cap_pct  = s_duty_cap_pct;
    out->type_mask     = s_type_mask;
    out->sf_queue_depth = s_sf_depth;
    out->sf_queue_max  = s_sf_queue_max;
    out->relayed_count = s_relayed_count;
    out->dropped_count = s_dropped_count;
    out->uptime_seconds = (millis() - s_boot_ms) / 1000;
    out->last_nonce    = s_last_accepted_nonce;
    out->max_hops_added = s_max_hops_add;
}

uint8_t  relay_ctrl_get_mode()      { return s_mode; }
uint16_t relay_ctrl_get_sf_depth()  { return s_sf_depth; }
uint32_t relay_ctrl_get_dropped()   { return s_dropped_count; }

// ═════════════════════════════════════════════════════════════
// Internal helpers
// ═════════════════════════════════════════════════════════════

static void apply_ctrl(const RelayCtrl* c) {
    if (c->mode <= RELAY_MODE_SELECTIVE) s_mode = c->mode;
    s_rssi_floor    = c->rssi_floor;
    s_duty_cap_pct  = c->duty_cap_pct;
    s_type_mask     = c->type_mask;
    s_sf_queue_max  = (c->sf_queue_max < SF_QUEUE_HARD_MAX)
                      ? c->sf_queue_max : SF_QUEUE_HARD_MAX;
    s_sf_ttl_s      = (c->sf_ttl_seconds < SF_TTL_HARD_MAX_S)
                      ? c->sf_ttl_seconds : SF_TTL_HARD_MAX_S;
    s_max_hops_add  = c->max_hops_added > 0 ? c->max_hops_added : 1;
}

// ─── Neighbour tracking ──────────────────────────────────────
static void remember_neighbour(uint8_t id) {
    uint32_t now = millis();
    int slot = -1;
    uint32_t oldest = UINT32_MAX;
    int oldest_slot = 0;

    for (int i = 0; i < NBR_TABLE_SIZE; i++) {
        if (s_nbrs[i].id == id) { slot = i; break; }
        if (s_nbrs[i].last_heard == 0) { slot = i; break; }
        if (s_nbrs[i].last_heard < oldest) {
            oldest = s_nbrs[i].last_heard;
            oldest_slot = i;
        }
    }
    if (slot < 0) slot = oldest_slot;
    s_nbrs[slot].id = id;
    s_nbrs[slot].last_heard = now;
}

static bool neighbour_known(uint8_t id) {
    uint32_t now = millis();
    for (int i = 0; i < NBR_TABLE_SIZE; i++) {
        if (s_nbrs[i].id != id) continue;
        if (s_nbrs[i].last_heard == 0) continue;
        if ((now - s_nbrs[i].last_heard) > NBR_TTL_MS) continue;
        return true;
    }
    return false;
}

// ─── Store-and-forward queue ─────────────────────────────────
static void sf_enqueue(const uint8_t* pkt, size_t len, uint8_t dst) {
    if (s_sf_depth >= s_sf_queue_max) {
        // Drop oldest to make room
        uint32_t oldest = UINT32_MAX;
        int idx = 0;
        for (int i = 0; i < SF_QUEUE_HARD_MAX; i++) {
            if (s_sf[i].len == 0) continue;
            if (s_sf[i].enqueued_at < oldest) {
                oldest = s_sf[i].enqueued_at;
                idx = i;
            }
        }
        s_sf[idx].len = 0;
        s_sf_depth--;
    }
    for (int i = 0; i < SF_QUEUE_HARD_MAX; i++) {
        if (s_sf[i].len == 0) {
            s_sf[i].dst = dst;
            s_sf[i].enqueued_at = millis();
            s_sf[i].len = (uint16_t)len;
            memcpy(s_sf[i].pkt, pkt, len);
            s_sf_depth++;
            return;
        }
    }
}

static void sf_flush_for(uint8_t dst) {
    if (!s_tx) return;
    for (int i = 0; i < SF_QUEUE_HARD_MAX; i++) {
        if (s_sf[i].len == 0) continue;
        if (s_sf[i].dst != dst) continue;
        if (s_tx(s_sf[i].pkt, s_sf[i].len)) {
            s_relayed_count++;
        }
        s_sf[i].len = 0;
        s_sf_depth--;
    }
}

static void sf_gc() {
    uint32_t now = millis();
    uint32_t ttl_ms = s_sf_ttl_s * 1000UL;
    for (int i = 0; i < SF_QUEUE_HARD_MAX; i++) {
        if (s_sf[i].len == 0) continue;
        if ((now - s_sf[i].enqueued_at) > ttl_ms) {
            s_sf[i].len = 0;
            s_sf_depth--;
            s_dropped_count++;
        }
    }
}

// ─── Duty cycle ──────────────────────────────────────────────
static bool duty_allows() {
    if (s_duty_cap_pct == 0) return true;
    uint32_t now = millis();
    if ((now - s_window_start_ms) >= DUTY_WINDOW_MS) return true;
    uint32_t allowed = (DUTY_WINDOW_MS * s_duty_cap_pct) / 100;
    return s_window_airtime_ms < allowed;
}

// ─── Nonce / replay ──────────────────────────────────────────
static bool check_and_record_nonce(uint8_t src, uint32_t nonce) {
    int slot = -1;
    uint32_t oldest = UINT32_MAX;
    int oldest_slot = 0;
    for (int i = 0; i < NONCE_TABLE_SIZE; i++) {
        if (s_nonces[i].ts != 0 && s_nonces[i].src == src) { slot = i; break; }
        if (s_nonces[i].ts == 0) { slot = i; break; }
        if (s_nonces[i].ts < oldest) {
            oldest = s_nonces[i].ts;
            oldest_slot = i;
        }
    }
    if (slot < 0) slot = oldest_slot;

    if (s_nonces[slot].src == src && s_nonces[slot].ts != 0) {
        if (nonce <= s_nonces[slot].last_nonce) {
            return false;   // replay
        }
    }
    s_nonces[slot].src = src;
    s_nonces[slot].last_nonce = nonce;
    s_nonces[slot].ts = millis();
    if (nonce > s_last_accepted_nonce) s_last_accepted_nonce = nonce;
    return true;
}

// ─── HMAC-SHA256 ─────────────────────────────────────────────
// Computes HMAC over (header + RelayCtrl bytes with hmac field zeroed).
// Compares first 8 bytes against c->hmac.
static bool verify_ctrl_hmac(const uint8_t* pkt, size_t len) {
    if (!s_key || s_key_len == 0) return false;

    const PktHeader* h = (const PktHeader*)pkt;
    if (h->len != sizeof(RelayCtrl)) return false;

    // Build the message to sign: header bytes + payload with hmac zeroed
    uint8_t buf[sizeof(PktHeader) + sizeof(RelayCtrl)];
    memcpy(buf, pkt, sizeof(buf));
    RelayCtrl* c = (RelayCtrl*)(buf + sizeof(PktHeader));
    uint8_t supplied[8];
    memcpy(supplied, c->hmac, 8);
    memset(c->hmac, 0, 8);

    uint8_t mac[32];
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) return false;

    if (mbedtls_md_hmac(info, s_key, s_key_len,
                        buf, sizeof(buf), mac) != 0) {
        return false;
    }

    // Constant-time compare of the first 8 bytes
    uint8_t diff = 0;
    for (int i = 0; i < 8; i++) diff |= (mac[i] ^ supplied[i]);
    return diff == 0;
}

// ─── Emit STATUS ─────────────────────────────────────────────
static void emit_status() {
    if (!s_tx) return;
    uint8_t pkt[sizeof(PktHeader) + sizeof(RelayStatus)];
    RelayStatus st;
    relay_ctrl_get_status(&st);

    uint16_t mid = (uint16_t)esp_random();
    int total = pkt_init(pkt, s_my_id, BROADCAST_ID,
                         PKT_RELAY_STATUS, mid, 0,
                         &st, sizeof(st));
    if (total > 0) s_tx(pkt, total);
}
