"""
DarkNet Touch UI v2
-------------------
Added:
  - Messaging — tap any node to send a message
  - Inbox panel — shows recent received messages
  - Hop count shown on relay nodes
  - Cleaner colour scheme
  - Own node highlighted differently

Colours:
  GREEN   — online, direct (0 hops)
  TEAL    — online, via relay (1+ hops)
  ORANGE  — message pending / unacked
  RED     — revoked
  DARK    — offline
  PURPLE  — relay node (T-beam etc)
"""

import os
import sys
import time
import json
import threading
import socket
import math

import pygame

# ── Display mode detection ────────────────────────────────────────────────────
WAYLAND  = bool(os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY"))
TFT_DEV  = os.environ.get("TFT_DEV", "/dev/fb0")
TFT_MODE = (not WAYLAND) and os.path.exists(TFT_DEV)

if TFT_MODE:
    os.environ["SDL_VIDEODRIVER"] = "offscreen"
elif WAYLAND:
    os.environ["SDL_VIDEODRIVER"] = "wayland"
    os.environ["XDG_RUNTIME_DIR"] = os.environ.get("XDG_RUNTIME_DIR", "/run/user/1000")
else:
    os.environ["SDL_VIDEODRIVER"] = "offscreen"

# ── Constants ─────────────────────────────────────────────────────────────────
SCREEN_W = 320
SCREEN_H = 240
BTN_PINS = [17, 22, 23, 27]

C_BG      = (8,   10,  14)
C_ONLINE  = (30,  190, 80)    # green  — direct
C_RELAY   = (0,   160, 180)   # teal   — via relay
C_RNODE   = (120, 60,  200)   # purple — relay node (T-beam)
C_PENDING = (220, 100, 0)     # orange — unacked
C_REVOKED = (180, 30,  30)    # red
C_OFFLINE = (30,  32,  38)    # dark
C_SELF    = (50,  50,  160)   # blue   — own node
C_TEXT    = (240, 240, 240)
C_DIM     = (90,  90,  100)
C_ACCENT  = (50,  120, 210)
C_BORDER  = (50,  55,  65)
C_HEADER  = (15,  17,  22)
C_SELECT  = (60,  130, 220)
C_INBOX   = (20,  22,  30)
C_MSG_IN  = (30,  190, 80)
C_MSG_OUT = (50,  120, 210)

DAEMON_SOCKET = "/tmp/darknet.sock"

# ── Daemon comms ──────────────────────────────────────────────────────────────

def get_nodes():
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(DAEMON_SOCKET)
        s.sendall(b"GET_NODES")
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        return json.loads(data)
    except Exception:
        return []

def get_inbox():
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(DAEMON_SOCKET)
        s.sendall(b"GET_INBOX")
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        return json.loads(data)
    except Exception:
        return []

def set_state(state: dict):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(DAEMON_SOCKET)
        s.sendall(f"SET_STATE:{json.dumps(state)}".encode())
        s.recv(64)
        s.close()
    except Exception:
        pass

def send_msg(to: str, payload: str):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(DAEMON_SOCKET)
        req = json.dumps({"to": to, "payload": payload})
        s.sendall(f"SEND_MSG:{req}".encode())
        resp = s.recv(64).decode()
        s.close()
        return resp == "OK"
    except Exception:
        return False

# ── GPIO ──────────────────────────────────────────────────────────────────────

try:
    import RPi.GPIO as GPIO
    GPIO.setmode(GPIO.BCM)
    for pin in BTN_PINS:
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO_AVAILABLE = True
except Exception:
    GPIO_AVAILABLE = False

def read_buttons():
    if not GPIO_AVAILABLE:
        return None
    for i, pin in enumerate(BTN_PINS):
        if GPIO.input(pin) == GPIO.LOW:
            return i
    return None

# ── TFT ───────────────────────────────────────────────────────────────────────

class TFTWriter:
    def __init__(self, device=TFT_DEV):
        self.device   = device
        self.buf_size = SCREEN_W * SCREEN_H * 2

    def write(self, surface):
        try:
            rgb = pygame.image.tostring(surface, "RGB")
            buf = bytearray(self.buf_size)
            for i in range(SCREEN_W * SCREEN_H):
                r = rgb[i*3]; g = rgb[i*3+1]; b = rgb[i*3+2]
                px = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
                buf[i*2] = px & 0xFF; buf[i*2+1] = (px >> 8) & 0xFF
            with open(self.device, "wb") as f:
                f.write(buf)
        except Exception:
            pass

# ── Node colour logic ─────────────────────────────────────────────────────────

def node_colour(node: dict, is_self: bool) -> tuple:
    status   = node.get("status", "offline")
    is_relay = node.get("is_relay", False)
    hops     = node.get("hops", 0)

    if status == "revoked":  return C_REVOKED
    if status == "offline":  return C_OFFLINE
    if status == "pending":  return C_PENDING
    if is_self:              return C_SELF
    if is_relay:             return C_RNODE
    if hops > 0:             return C_RELAY
    return C_ONLINE

# ── UI modes ──────────────────────────────────────────────────────────────────

MODE_NODES   = "nodes"
MODE_INBOX   = "inbox"
MODE_COMPOSE = "compose"
MODE_STATE   = "state"

# ── UI class ──────────────────────────────────────────────────────────────────

class DarkNetUI:
    def __init__(self, local_node_id: str, fullscreen: bool = True):
        self.local_node_id = local_node_id
        self.nodes         = []
        self.inbox         = []
        self.selected      = 0
        self.mode          = MODE_NODES
        self.compose_to    = ""
        self.compose_msg   = ""
        self.modal_options = []
        self.modal_sel     = 0
        self.status_msg    = ""
        self.status_time   = 0
        self._last_btn     = None
        self._btn_debounce = 0
        self._tft          = TFTWriter() if TFT_MODE else None
        self._last_inbox   = 0
        self._unread       = 0
        self._last_inbox_count = 0

        pygame.init()
        pygame.mouse.set_visible(False)

        if TFT_MODE:
            self.screen = pygame.Surface((SCREEN_W, SCREEN_H))
            pygame.display.set_mode((1, 1))
        elif fullscreen:
            self.screen = pygame.display.set_mode((SCREEN_W, SCREEN_H), pygame.FULLSCREEN)
        else:
            self.screen = pygame.display.set_mode((SCREEN_W, SCREEN_H))

        pygame.display.set_caption("DarkNet")
        self.font_lg  = pygame.font.SysFont("monospace", 18, bold=True)
        self.font_md  = pygame.font.SysFont("monospace", 14)
        self.font_sm  = pygame.font.SysFont("monospace", 11)
        self.font_xs  = pygame.font.SysFont("monospace", 10)
        self._clock   = pygame.time.Clock()
        self._last_refresh = 0

        print(f"[UI] {'TFT' if TFT_MODE else 'Wayland' if WAYLAND else 'window'} | {local_node_id}")

    # ── Layout ────────────────────────────────────────────────────────────────

    def _node_rects(self):
        n    = max(len(self.nodes), 1)
        cols = 2 if n > 2 else n
        rows = math.ceil(n / cols)
        pad  = 6
        top  = 26
        bw   = (SCREEN_W - pad * (cols + 1)) // cols
        bh   = (SCREEN_H - top - pad * (rows + 1)) // rows
        rects = []
        for i in range(len(self.nodes)):
            col = i % cols; row = i // cols
            rects.append(pygame.Rect(
                pad + col * (bw + pad),
                top + pad + row * (bh + pad),
                bw, bh
            ))
        return rects

    # ── Draw ──────────────────────────────────────────────────────────────────

    def _draw_header(self):
        pygame.draw.rect(self.screen, C_HEADER, (0, 0, SCREEN_W, 24))
        local = next((n for n in self.nodes if n["node_id"] == self.local_node_id), None)
        dot   = node_colour(local, True) if local else C_OFFLINE
        pygame.draw.circle(self.screen, dot, (10, 12), 5)
        self.screen.blit(self.font_xs.render(self.local_node_id, True, C_TEXT), (20, 6))

        # Unread badge
        if self._unread > 0:
            badge = self.font_xs.render(f"📨{self._unread}", True, C_MSG_IN)
            self.screen.blit(badge, (SCREEN_W // 2 - badge.get_width() // 2, 5))

        ts = time.strftime("%H:%M")
        ts_s = self.font_xs.render(ts, True, C_DIM)
        self.screen.blit(ts_s, (SCREEN_W - ts_s.get_width() - 4, 6))

        if self.status_msg and time.time() - self.status_time < 3:
            msg = self.font_xs.render(self.status_msg, True, C_ACCENT)
            self.screen.blit(msg, (SCREEN_W // 2 - msg.get_width() // 2, 6))

        flame = 0

        local = next(
            (n for n in self.nodes if n["node_id"] == self.local_node_id),
            None
        )

        if local:
            flame = local.get("network_state", {}).get("flame", {}).get("value", 0)

        flame_s = self.font_xs.render(f"🔥 {flame}", True, (255,180,40))
        self.screen.blit(flame_s, (SCREEN_W - 80, 6))

    def _draw_node(self, node, rect, selected):
        is_self  = node["node_id"] == self.local_node_id
        status   = node.get("status", "offline")
        col      = node_colour(node, is_self)
        is_dim   = status == "offline"

        if selected and self.mode == MODE_NODES:
            pygame.draw.rect(self.screen, C_SELECT, rect.inflate(4, 4), border_radius=12)
        if status in ("online", "relay", "pending") or node.get("is_relay"):
            gc = tuple(min(255, int(c * 0.3)) for c in col)
            pygame.draw.rect(self.screen, gc, rect.inflate(4, 4), border_radius=12)

        pygame.draw.rect(self.screen, col, rect, border_radius=8)
        pygame.draw.rect(self.screen, C_BORDER, rect, 1, border_radius=8)

        tc = C_DIM if is_dim else C_TEXT

        # Node ID
        nid_s = self.font_md.render(node["node_id"], True, tc)
        self.screen.blit(nid_s, (rect.centerx - nid_s.get_width()//2, rect.y + 6))

        # Status
        st_label = "YOU" if is_self else status.upper()
        st_s = self.font_sm.render(st_label, True, tc)
        self.screen.blit(st_s, (rect.centerx - st_s.get_width()//2, rect.y + 26))

        # Flame state
        flame = node.get("state", {}).get("flame")

        if flame is not None:
            flame_s = self.font_xs.render(f"🔥 {flame}", True, tc)
            self.screen.blit(
                flame_s,
                (rect.centerx - flame_s.get_width() // 2, rect.bottom - 30)
            )

        # RSSI
        if node.get("rssi", 0) != 0:
            rs = self.font_md.render(f"{node['rssi']}dBm", True, tc)
            self.screen.blit(
                rs,
                (rect.centerx - rs.get_width()//2, rect.bottom - 18)
            )

        # Hops / relay badge
        hops = node.get("hops", 0)
        if node.get("is_relay"):
            hs = self.font_xs.render("RELAY", True, tc)
            self.screen.blit(hs, (rect.x + 3, rect.bottom - 14))
        elif hops > 0:
            hs = self.font_xs.render(f"{hops}hop", True, tc)
            self.screen.blit(hs, (rect.x + 3, rect.bottom - 14))

    def _draw_nodes(self):
        rects = self._node_rects()
        for i, (node, rect) in enumerate(zip(self.nodes, rects)):
            self._draw_node(node, rect, selected=(i == self.selected))

    def _draw_inbox(self):
        pygame.draw.rect(self.screen, C_INBOX, (0, 26, SCREEN_W, SCREEN_H - 26))
        title = self.font_md.render("INBOX", True, C_TEXT)
        self.screen.blit(title, (8, 30))
        pygame.draw.line(self.screen, C_BORDER, (0, 46), (SCREEN_W, 46))

        if not self.inbox:
            empty = self.font_sm.render("No messages", True, C_DIM)
            self.screen.blit(empty, (SCREEN_W//2 - empty.get_width()//2, 100))
            return

        y = 50
        for msg in reversed(self.inbox[-5:]):
            if y > SCREEN_H - 20:
                break
            age = int(time.time() - msg.get("ts", 0))
            age_s = f"{age}s" if age < 60 else f"{age//60}m"
            from_s = self.font_xs.render(f"[{msg['from']}] {age_s}", True, C_MSG_IN)
            self.screen.blit(from_s, (8, y))
            y += 13
            # Word-wrap payload
            payload = msg.get("payload", "")[:60]
            pay_s = self.font_xs.render(payload, True, C_TEXT)
            self.screen.blit(pay_s, (12, y))
            y += 16
            pygame.draw.line(self.screen, C_BORDER, (8, y), (SCREEN_W - 8, y))
            y += 4

    def _draw_compose(self):
        pygame.draw.rect(self.screen, C_INBOX, (0, 26, SCREEN_W, SCREEN_H - 26))
        to_s = self.font_md.render(f"To: {self.compose_to}", True, C_ACCENT)
        self.screen.blit(to_s, (8, 32))
        pygame.draw.line(self.screen, C_BORDER, (0, 50), (SCREEN_W, 50))
        msg_s = self.font_sm.render(self.compose_msg or "...", True, C_TEXT)
        self.screen.blit(msg_s, (8, 58))
        hint = self.font_xs.render("UP=send DN=cancel", True, C_DIM)
        self.screen.blit(hint, (8, SCREEN_H - 16))

    def _draw_state_modal(self):
        dim = pygame.Surface((SCREEN_W, SCREEN_H), pygame.SRCALPHA)
        dim.fill((0, 0, 0, 170))
        self.screen.blit(dim, (0, 0))
        mw, mh = 280, 160
        mx = SCREEN_W//2 - mw//2
        my = SCREEN_H//2 - mh//2
        mr = pygame.Rect(mx, my, mw, mh)
        pygame.draw.rect(self.screen, (20, 22, 30), mr, border_radius=10)
        pygame.draw.rect(self.screen, C_ACCENT, mr, 2, border_radius=10)
        title = self.font_sm.render(f"Action: {self.nodes[self.selected]['node_id'] if self.nodes else ''}", True, C_TEXT)
        self.screen.blit(title, (mx + 8, my + 8))
        bw, bh = 125, 28
        for i, opt in enumerate(self.modal_options):
            bx = mx + 8 + (i % 2) * (bw + 8)
            by = my + 32 + (i // 2) * (bh + 6)
            br = pygame.Rect(bx, by, bw, bh)
            if i == self.modal_sel:
                bg = C_SELECT
            elif opt in ("REVOKE", "CANCEL"):
                bg = (80, 30, 30)
            else:
                bg = C_ACCENT
            pygame.draw.rect(self.screen, bg, br, border_radius=5)
            lbl = self.font_sm.render(opt, True, C_TEXT)
            self.screen.blit(lbl, (br.centerx - lbl.get_width()//2, br.centery - lbl.get_height()//2))

    def _draw(self):
        self.screen.fill(C_BG)
        self._draw_header()

        if self.mode == MODE_NODES:
            self._draw_nodes()
        elif self.mode == MODE_INBOX:
            self._draw_inbox()
        elif self.mode == MODE_COMPOSE:
            self._draw_compose()
        elif self.mode == MODE_STATE:
            self._draw_nodes()
            self._draw_state_modal()

        if TFT_MODE:
            self._tft.write(self.screen)
        else:
            pygame.display.flip()

    # ── Button handling ───────────────────────────────────────────────────────

    def _handle_button(self, idx):
        """
        Buttons:
          0 — UP / prev
          1 — DOWN / next
          2 — SELECT / confirm
          3 — BACK / cancel
        """
        if self.mode == MODE_STATE:
            if idx == 0:
                self.modal_sel = (self.modal_sel - 1) % len(self.modal_options)
            elif idx == 1:
                self.modal_sel = (self.modal_sel + 1) % len(self.modal_options)
            elif idx == 2:
                self._confirm_action()
            elif idx == 3:
                self.mode = MODE_NODES

        elif self.mode == MODE_INBOX:
            if idx == 3:
                self.mode = MODE_NODES
                self._unread = 0

        elif self.mode == MODE_COMPOSE:
            if idx == 0:   # send
                if self.compose_msg:
                    ok = send_msg(self.compose_to, self.compose_msg)
                    self.status_msg  = f"Sent → {self.compose_to}" if ok else "Send failed"
                    self.status_time = time.time()
                self.mode = MODE_NODES
            elif idx == 1 or idx == 3:  # cancel
                self.mode = MODE_NODES

        elif self.mode == MODE_NODES:
            if idx == 0:
                self.selected = max(0, self.selected - 1)
            elif idx == 1:
                self.selected = min(len(self.nodes) - 1, self.selected + 1)
            elif idx == 2:
                self._open_action_menu()
            elif idx == 3:
                self.mode = MODE_INBOX

    def _open_action_menu(self):
        if not self.nodes or self.selected >= len(self.nodes):
            return
        node = self.nodes[self.selected]
        is_self = node["node_id"] == self.local_node_id

        if is_self:
            self.modal_options = ["AVAILABLE", "BUSY", "AWAY", "CANCEL"]
        else:
            self.modal_options = ["MESSAGE", "PING", "REVOKE", "CANCEL"]

        self.modal_sel = 0
        self.mode      = MODE_STATE

    def _confirm_action(self):
        if not self.nodes or self.selected >= len(self.nodes):
            self.mode = MODE_NODES
            return

        node    = self.nodes[self.selected]
        is_self = node["node_id"] == self.local_node_id
        opt     = self.modal_options[self.modal_sel]

        if opt == "CANCEL":
            self.mode = MODE_NODES
            return

        if is_self:
            set_state({"status": opt.lower()})
            self.status_msg  = f"Status → {opt.lower()}"
            self.status_time = time.time()
            self.mode        = MODE_NODES
        else:
            if opt == "MESSAGE":
                self.compose_to  = node["node_id"]
                self.compose_msg = f"Hello from {self.local_node_id}"
                self.mode        = MODE_COMPOSE
            elif opt == "PING":
                self.status_msg  = f"Ping → {node['node_id']}"
                self.status_time = time.time()
                self.mode        = MODE_NODES
            elif opt == "REVOKE":
                self.status_msg  = "Revoke not impl yet"
                self.status_time = time.time()
                self.mode        = MODE_NODES

    # ── Main loop ─────────────────────────────────────────────────────────────

    def run(self):
        running = True
        while running:
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    running = False
                elif event.type == pygame.KEYDOWN:
                    if event.key == pygame.K_ESCAPE:
                        running = False
                    elif event.key == pygame.K_UP:
                        self._handle_button(0)
                    elif event.key == pygame.K_DOWN:
                        self._handle_button(1)
                    elif event.key == pygame.K_RETURN:
                        self._handle_button(2)
                    elif event.key == pygame.K_BACKSPACE:
                        self._handle_button(3)
                    elif event.key == pygame.K_i:
                        self.mode = MODE_INBOX if self.mode != MODE_INBOX else MODE_NODES

            now = time.time()
            if now - self._btn_debounce > 0.2:
                btn = read_buttons()
                if btn is not None and btn != self._last_btn:
                    self._handle_button(btn)
                    self._btn_debounce = now
                self._last_btn = btn

            if now - self._last_refresh > 1.0:
                self.nodes  = sorted(get_nodes(), key=lambda n: n["node_id"])
                self.inbox  = get_inbox()
                self.selected = min(self.selected, max(0, len(self.nodes) - 1))
                # Unread count
                new_count = len(self.inbox)
                if new_count > self._last_inbox_count:
                    self._unread += new_count - self._last_inbox_count
                self._last_inbox_count = new_count
                self._last_refresh = now

            self._draw()
            self._clock.tick(20)

        pygame.quit()
        if GPIO_AVAILABLE:
            GPIO.cleanup()


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--node-id", default="node-01")
    parser.add_argument("--window",  action="store_true")
    parser.add_argument("--mock",    action="store_true")
    args = parser.parse_args()

    if args.mock:
        print("Mock mode")
        fake_nodes = [
                {
                    "node_id": "node-00",
                    "status": "online",
                    "rssi": -72,
                    "snr": 9.5,
                    "hops": 0,
                    "state": {"flame": 6},
                    "is_relay": False
                },
                {
                    "node_id": "node-01",
                    "status": "online",
                    "rssi": 0,
                    "snr": 0.0,
                    "hops": 0,
                    "state": {"flame": 6},
                    "is_relay": False
                },
                {
                    "node_id": "tbeam-1",
                    "status": "relay",
                    "rssi": -88,
                    "snr": 6.0,
                    "hops": 1,
                    "state": {"flame": 6},
                    "is_relay": True
                },
            ]
        
        fake_inbox = [
            {"from": "node-00", "payload": "hello Ryan", "mid": "abc1", "ts": time.time() - 30},
            {"from": "node-00", "payload": "sup Callum",  "mid": "abc2", "ts": time.time() - 10},
        ]

        def mock_server():
            if os.path.exists(DAEMON_SOCKET):
                os.remove(DAEMON_SOCKET)
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(DAEMON_SOCKET)
            srv.listen(5)
            srv.settimeout(1)
            while True:
                try:
                    conn, _ = srv.accept()
                    cmd = conn.recv(512).decode().strip()
                    if cmd == "GET_NODES":
                        conn.sendall(json.dumps(fake_nodes).encode())
                    elif cmd == "GET_INBOX":
                        conn.sendall(json.dumps(fake_inbox).encode())
                    elif cmd.startswith("SET_STATE:"):
                        state = json.loads(cmd[10:])
                        for n in fake_nodes:
                            if n["node_id"] == args.node_id:
                                n["state"] = state; n["status"] = "pending"
                        conn.sendall(b"OK")
                        def ack():
                            time.sleep(2)
                            for n in fake_nodes:
                                if n["node_id"] == args.node_id:
                                    n["status"] = "online"
                        threading.Thread(target=ack, daemon=True).start()
                    elif cmd.startswith("SEND_MSG:"):
                        req = json.loads(cmd[9:])
                        fake_inbox.append({"from": args.node_id, "payload": req["payload"],
                                           "mid": "sent1", "ts": time.time()})
                        conn.sendall(b"OK")
                    conn.close()
                except socket.timeout:
                    continue
        threading.Thread(target=mock_server, daemon=True).start()

    ui = DarkNetUI(local_node_id=args.node_id, fullscreen=not args.window)
    ui.run()
