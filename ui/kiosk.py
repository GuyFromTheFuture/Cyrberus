"""Cyrberus Head - operator screen.

Fullscreen Tkinter kiosk. Polls the daemon's state file and draws one of five
screens. Runs unprivileged: it reads state and nothing else, so a compromise
here yields no filesystem rights.

Design rules carried over from the mockups:
  - no buttons in the main flow; insert, read, remove
  - state is never carried by colour alone - each screen has a distinct
    icon, heading and layout
  - wording is for front-office staff, not technicians

    python3 ui/kiosk.py              fullscreen
    python3 ui/kiosk.py --windowed   800x480 window, for development
"""
import argparse
import os
import sys
import tkinter as tk
import tkinter.font as tkfont
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "head"))
import state  # noqa: E402

DESIGN_W, DESIGN_H = 800, 480
POLL_MS = 250

INK = "#F2F6F8"
MUTED = "#AFC0CE"
FAINT = "#8FA4B5"
NAVY = "#14202B"
PANEL = "#1B2D3C"
TRACK = "#27384A"
BLUE = "#60A5FA"
AMBER = "#FBBF24"
GREEN = "#4ADE80"
RED = "#FF6B6B"
RED_BG = "#2A1416"
RED_PANEL = "#3A1D1F"
RED_INK = "#F7EDED"
RED_MUTED = "#D9AFAF"


def pick_family(root):
    available = set(tkfont.families(root))
    for name in ("Archivo", "DejaVu Sans", "Liberation Sans", "Helvetica", "Arial"):
        if name in available:
            return name
    return "TkDefaultFont"


class Kiosk:
    def __init__(self, root, state_path, windowed=False):
        self.root = root
        self.state_path = state_path
        self.family = pick_family(root)
        self.last_signature = None

        root.title("Cyrberus Head")
        root.configure(bg=NAVY)
        if windowed:
            root.geometry("%dx%d" % (DESIGN_W, DESIGN_H))
        else:
            root.attributes("-fullscreen", True)
            root.configure(cursor="none")
        root.bind("<Escape>", lambda e: root.destroy())

        self.canvas = tk.Canvas(root, highlightthickness=0, bd=0, bg=NAVY)
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<Configure>", lambda e: self.redraw(force=True))

        self.current = state.read(self.state_path)
        self.poll()

    # -- scaling ----------------------------------------------------------
    @property
    def scale(self):
        w = max(self.canvas.winfo_width(), 1)
        h = max(self.canvas.winfo_height(), 1)
        return min(w / DESIGN_W, h / DESIGN_H)

    def sx(self, x):
        """Design x -> canvas x, with the design box centred."""
        w = self.canvas.winfo_width()
        return (w - DESIGN_W * self.scale) / 2 + x * self.scale

    def sy(self, y):
        h = self.canvas.winfo_height()
        return (h - DESIGN_H * self.scale) / 2 + y * self.scale

    def f(self, size, bold=False):
        return (self.family, max(int(size * self.scale), 8),
                "bold" if bold else "normal")

    # -- primitives -------------------------------------------------------
    def box(self, x, y, w, h, fill):
        self.canvas.create_rectangle(self.sx(x), self.sy(y),
                                     self.sx(x + w), self.sy(y + h),
                                     fill=fill, width=0)

    def text(self, x, y, s, size, fill, bold=False, anchor="center"):
        self.canvas.create_text(self.sx(x), self.sy(y), text=s,
                                font=self.f(size, bold), fill=fill,
                                anchor=anchor)

    def line(self, x1, y1, x2, y2, fill, width=3, cap="round"):
        self.canvas.create_line(self.sx(x1), self.sy(y1), self.sx(x2), self.sy(y2),
                                fill=fill, width=max(width * self.scale, 1),
                                capstyle=cap)

    def ring(self, cx, cy, r, fill, width=3):
        self.canvas.create_oval(self.sx(cx - r), self.sy(cy - r),
                                self.sx(cx + r), self.sy(cy + r),
                                outline=fill, width=max(width * self.scale, 1))

    def disc(self, cx, cy, r, fill):
        self.canvas.create_oval(self.sx(cx - r), self.sy(cy - r),
                                self.sx(cx + r), self.sy(cy + r),
                                fill=fill, width=0)

    def bottom_bar(self, fill=PANEL):
        self.box(0, 418, DESIGN_W, 62, fill)

    # -- icons ------------------------------------------------------------
    def icon_usb(self, cx, cy):
        self.line(cx, cy + 62, cx, cy - 62, BLUE, 2.6)
        self.line(cx, cy - 62, cx - 17, cy - 44, BLUE, 2.6)
        self.line(cx, cy - 62, cx + 17, cy - 44, BLUE, 2.6)
        self.line(cx, cy - 8, cx - 34, cy - 36, BLUE, 2.6)
        self.line(cx, cy + 6, cx + 34, cy - 22, BLUE, 2.6)
        self.disc(cx - 34, cy - 36, 10, BLUE)
        self.box(cx + 24, cy - 32, 20, 20, BLUE)

    def icon_magnifier(self, cx, cy):
        self.ring(cx - 7, cy - 8, 38, AMBER, 3)
        self.line(cx + 21, cy + 20, cx + 47, cy + 46, AMBER, 3)
        self.line(cx - 24, cy - 8, cx + 10, cy - 8, AMBER, 3)

    def icon_check(self, cx, cy):
        self.ring(cx, cy, 40, GREEN, 3.4)
        self.line(cx - 18, cy + 2, cx - 5, cy + 15, GREEN, 4)
        self.line(cx - 5, cy + 15, cx + 20, cy - 12, GREEN, 4)

    def icon_warning(self, cx, cy):
        pts = [self.sx(cx), self.sy(cy - 36),
               self.sx(cx + 42), self.sy(cy + 36),
               self.sx(cx - 42), self.sy(cy + 36)]
        self.canvas.create_polygon(pts, outline=RED, fill="",
                                   width=max(3.4 * self.scale, 1), joinstyle="round")
        self.line(cx, cy - 10, cx, cy + 8, RED, 3.4)
        self.disc(cx, cy + 21, 2.8, RED)

    def icon_lock(self, cx, cy):
        self.canvas.create_rectangle(self.sx(cx - 38), self.sy(cy - 6),
                                     self.sx(cx + 38), self.sy(cy + 50),
                                     outline=AMBER, width=max(3.2 * self.scale, 1))
        self.canvas.create_arc(self.sx(cx - 22), self.sy(cy - 50),
                               self.sx(cx + 22), self.sy(cy - 6),
                               start=0, extent=180, style="arc",
                               outline=AMBER, width=max(3.2 * self.scale, 1))
        self.line(cx - 22, cy - 28, cx - 22, cy - 6, AMBER, 3.2)
        self.line(cx + 22, cy - 28, cx + 22, cy - 6, AMBER, 3.2)
        self.disc(cx, cy + 22, 7, AMBER)

    # -- screens ----------------------------------------------------------
    def screen_ready(self, detail):
        self.canvas.configure(bg=NAVY)
        self.icon_usb(400, 150)
        self.text(400, 274, "Insert your USB drive", 44, INK, True)
        self.text(400, 318, "Checking starts on its own.", 22, MUTED)
        self.text(400, 350, "You do not need to press anything.", 22, MUTED)
        self.bottom_bar()
        self.disc(42, 449, 7, GREEN)
        self.text(62, 449, "Ready", 19, INK, True, anchor="w")
        sig = detail.get("signatures_updated")
        self.text(772, 449, "Virus list %s" % ("loaded" if not sig else "set " + str(sig)),
                  17, FAINT, anchor="e")

    def screen_working(self, detail):
        self.canvas.configure(bg=NAVY)
        phase = detail.get("phase", "scanning")
        self.icon_magnifier(400, 140)

        heading = {
            "identifying": "Reading your drive",
            "scanning": "Checking your drive",
            "hashing": "Recording your drive",
            "signing": "Approving your drive",
        }.get(phase, "Checking your drive")
        self.text(400, 240, heading, 42, INK, True)

        done, total = detail.get("done"), detail.get("total")
        self.box(110, 272, 580, 16, TRACK)
        if done is not None and total:
            frac = max(0.0, min(1.0, done / float(total)))
            if frac > 0:
                self.box(110, 272, int(580 * frac), 16, AMBER)
            self.text(110, 314, "%s of %s files" % (f"{done:,}", f"{total:,}"),
                      19, MUTED, anchor="w")
        else:
            # Indeterminate: a fixed band, so nothing implies false precision.
            self.box(110, 272, 170, 16, AMBER)
            self.text(110, 314, "Working", 19, MUTED, anchor="w")

        self.text(400, 368, "Please leave the drive plugged in", 25, AMBER, True)
        self.bottom_bar()
        self.disc(42, 449, 7, AMBER)
        self.text(62, 449, "Working", 19, INK, True, anchor="w")
        label = detail.get("model") or ""
        if detail.get("size"):
            label = ("%s · %s" % (label, detail["size"])).strip(" ·")
        self.text(772, 449, label, 17, FAINT, anchor="e")

    def screen_clean(self, detail):
        self.canvas.configure(bg=NAVY)
        self.box(0, 0, DESIGN_W, 10, GREEN)
        self.icon_check(400, 124)
        self.text(400, 232, "Your drive is clean", 46, GREEN, True)
        self.text(400, 272, "You can now use it on a work computer.", 24, INK)
        self.box(214, 300, 372, 62, PANEL)
        self.ring(256, 331, 14, MUTED, 2.4)
        self.line(256, 322, 256, 331, MUTED, 2.4)
        self.line(256, 331, 262, 335, MUTED, 2.4)
        self.text(286, 331, "Good until %s" % self._friendly_expiry(detail),
                  21, INK, True, anchor="w")
        self.bottom_bar()
        self.text(400, 449, "You may remove your drive", 22, INK, True)

    def screen_threat(self, detail):
        self.canvas.configure(bg=RED_BG)
        self.box(0, 0, DESIGN_W, DESIGN_H, RED_BG)
        self.box(0, 0, DESIGN_W, 10, RED)
        self.icon_warning(400, 122)
        self.text(400, 224, "Do not use this drive", 46, RED, True)
        self.text(400, 262, "Something harmful was found on it.", 24, RED_INK)
        self.box(258, 288, 284, 86, RED_PANEL)
        self.text(400, 316, "Show this code to your IT staff", 17, RED_MUTED)
        self.text(400, 350, detail.get("reference", "—"), 30, RED_INK, True)
        self.box(0, 414, DESIGN_W, 66, RED)
        self.text(400, 447, "Leave the drive here and tell your IT staff",
                  22, RED_BG, True)

    def screen_blocked(self, detail):
        self.canvas.configure(bg=NAVY)
        self.box(0, 0, DESIGN_W, 10, AMBER)
        self.icon_lock(400, 128)
        self.text(400, 232, "We cannot check this drive", 40, AMBER, True)
        reason = detail.get("reason") or "This drive cannot be read."
        for i, chunk in enumerate(self._wrap(reason, 46)[:2]):
            self.text(400, 276 + i * 30, chunk, 23, INK)
        self.box(178, 336, 444, 52, PANEL)
        self.text(400, 362, "A drive we cannot check is never approved.", 20, MUTED)
        self.bottom_bar()
        self.text(400, 449, "Ask your IT staff for help", 21, INK, True)

    def screen_offline(self):
        self.canvas.configure(bg=NAVY)
        self.icon_lock(400, 150)
        self.text(400, 268, "Checking is unavailable", 40, AMBER, True)
        self.text(400, 312, "This station is not running right now.", 23, INK)
        self.bottom_bar()
        self.text(400, 449, "Ask your IT staff for help", 21, INK, True)

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _wrap(s, width):
        words, lines, cur = s.split(), [], ""
        for w in words:
            if len(cur) + len(w) + 1 > width and cur:
                lines.append(cur)
                cur = w
            else:
                cur = (cur + " " + w).strip()
        if cur:
            lines.append(cur)
        return lines

    @staticmethod
    def _friendly_expiry(detail):
        raw = detail.get("expires_at")
        if not raw:
            return "later today"
        try:
            dt = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            local = dt.astimezone()
            hour = local.strftime("%I").lstrip("0") or "12"
            return "%s:%s %s" % (hour, local.strftime("%M"), local.strftime("%p"))
        except ValueError:
            return "later today"

    # -- loop -------------------------------------------------------------
    def signature(self, payload):
        """What must change before a repaint is worth doing."""
        d = payload.get("detail", {})
        return (payload.get("state"), payload.get("stale"), d.get("phase"),
                d.get("done"), d.get("reason"), d.get("reference"),
                d.get("model"), d.get("expires_at"))

    def redraw(self, force=False):
        payload = self.current
        sig = self.signature(payload)
        if not force and sig == self.last_signature:
            return
        self.last_signature = sig

        self.canvas.delete("all")
        detail = payload.get("detail", {})
        name = payload.get("state", state.READY)

        if payload.get("stale"):
            self.screen_offline()
        elif name == state.WORKING:
            self.screen_working(detail)
        elif name == state.CLEAN:
            self.screen_clean(detail)
        elif name == state.THREAT:
            self.screen_threat(detail)
        elif name == state.BLOCKED:
            self.screen_blocked(detail)
        else:
            self.screen_ready(detail)

    def poll(self):
        self.current = state.read(self.state_path)
        self.redraw()
        self.root.after(POLL_MS, self.poll)


def main():
    ap = argparse.ArgumentParser(description="Cyrberus Head operator screen")
    ap.add_argument("--windowed", action="store_true",
                    help="run in a window instead of fullscreen")
    ap.add_argument("--state", default=state.STATE_PATH,
                    help="path to the daemon's state file")
    args = ap.parse_args()

    root = tk.Tk()
    Kiosk(root, args.state, windowed=args.windowed)
    root.mainloop()


if __name__ == "__main__":
    main()
