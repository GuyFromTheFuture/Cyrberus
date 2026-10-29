"""Render tests for the kiosk screens.

Tkinter needs a display, which a CI box and this test host do not have, so a
stub Canvas records draw calls instead of painting. That is enough to catch
the failure that matters: a screen raising an exception and leaving the
operator looking at a frozen window.
"""
import json
import os
import shutil
import sys
import tempfile
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "tests", "tkstub"))   # stub before real tkinter
sys.path.insert(0, os.path.join(_ROOT, "ui"))
sys.path.insert(0, os.path.join(_ROOT, "head"))

import state as st  # noqa: E402

WORK = tempfile.mkdtemp(prefix="uitest-")
st.STATE_PATH = os.path.join(WORK, "state.json")
st.READ_PATH = st.STATE_PATH

from kiosk import Kiosk  # noqa: E402
import tkinter as tk     # noqa: E402

results = []


def check(name, cond, note=""):
    results.append(bool(cond))
    print("%-4s %-46s %s" % ("[ok]" if cond else "[XX]", name, note))


root = tk.Tk()
k = Kiosk(root, st.STATE_PATH, windowed=True)

SCREENS = [
    ("ready", st.READY, {}),
    ("working / scanning", st.WORKING,
     {"phase": "scanning", "model": "SanDisk Ultra", "size": "32 GB"}),
    ("working / hashing", st.WORKING,
     {"phase": "hashing", "model": "SanDisk Ultra", "size": "32 GB",
      "done": 1284, "total": 2061}),
    ("clean", st.CLEAN, {"expires_at": "2026-10-29T21:47:00Z", "file_count": 2061}),
    ("threat", st.THREAT, {"reference": "H4-2291", "detection_count": 2}),
    ("blocked", st.BLOCKED, {"reason": "This drive has more than one section on it."}),
]

for name, s, detail in SCREENS:
    st.publish(s, **detail)
    k.current = st.read()
    k.canvas.calls.clear()
    try:
        k.redraw(force=True)
        drew = [c for c in k.canvas.calls
                if c[0] in ("rect", "text", "line", "oval", "poly", "arc")]
        strings = [c[2].get("text", "") for c in k.canvas.calls if c[0] == "text"]
        offscreen = [c for c in drew if any(
            isinstance(v, (int, float)) and (v != v or abs(v) > 10000) for v in c[1])]
        check("%s renders" % name, len(drew) > 3 and not offscreen,
              "%d shapes, %d strings" % (len(drew), len(strings)))
    except Exception as e:
        check("%s renders" % name, False, "%s: %s" % (type(e).__name__, e))

raw = json.load(open(st.STATE_PATH))
raw["updated_at"] = time.time() - 600
open(st.STATE_PATH, "w").write(json.dumps(raw))
k.current = st.read()
k.canvas.calls.clear()
k.redraw(force=True)
shown = " ".join(c[2].get("text", "") for c in k.canvas.calls if c[0] == "text")
check("stale daemon shows offline screen", "unavailable" in shown, shown[:40])

st.publish(st.READY)
k.current = st.read()
k.redraw(force=True)
k.canvas.calls.clear()
k.current = st.read()
k.redraw()
check("no repaint when nothing changed", len(k.canvas.calls) == 0,
      "%d calls" % len(k.canvas.calls))

st.publish(st.WORKING, phase="hashing", done=99, total=200)
k.current = st.read()
k.canvas.calls.clear()
k.redraw()
check("repaints as progress advances", len(k.canvas.calls) > 3,
      "%d calls" % len(k.canvas.calls))

check("expiry shown as a clock time",
      ":" in Kiosk._friendly_expiry({"expires_at": "2026-10-29T21:47:00Z"}),
      Kiosk._friendly_expiry({"expires_at": "2026-10-29T21:47:00Z"}))
check("missing expiry degrades", Kiosk._friendly_expiry({}) == "later today")
check("malformed expiry degrades",
      Kiosk._friendly_expiry({"expires_at": "nope"}) == "later today")
check("long reason wraps", len(Kiosk._wrap(
    "This drive has more than one section on it and that is a problem", 46)) >= 2)

shutil.rmtree(WORK)
print("\n%d/%d UI checks passed" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
