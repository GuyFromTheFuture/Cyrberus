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

st.publish(st.READY, signatures_updated="")
k.current = st.read()
k.redraw(force=True)
st.publish(st.READY, signatures_updated="27801")
k.current = st.read()
k.canvas.calls.clear()
k.redraw()
shown = " ".join(c[2].get("text", "") for c in k.canvas.calls if c[0] == "text")
check("repaints when the virus list finishes loading", "27801" in shown, shown[-30:])

st.publish(st.BLOCKED, reason="Unplug this drive and plug it in again to check it.")
k.current = st.read()
k.canvas.calls.clear()
k.redraw()
shown = [c[2].get("text", "") for c in k.canvas.calls if c[0] == "text"]
check("re-insert request fits on two lines",
      any("Unplug this drive" in s for s in shown) and
      any("check it." in s for s in shown), " / ".join(shown[1:3]))

# An admin in group cyrberus can READ /run/cyrberus, but a daemon they start
# by hand (--simulate) cannot WRITE there and falls back to their runtime dir;
# a stopped service leaves its last state.json behind. The screen must follow
# the live daemon, not the leftover.
sysdir, xdg = tempfile.mkdtemp(dir=WORK), tempfile.mkdtemp(dir=WORK)
old_sys, old_xdg = st.SYSTEM_STATE_DIR, os.environ.get("XDG_RUNTIME_DIR")
st.SYSTEM_STATE_DIR = sysdir
os.environ["XDG_RUNTIME_DIR"] = xdg
leftover = os.path.join(sysdir, "state.json")
st._write(st.READY, leftover, {})
raw = json.load(open(leftover)); raw["updated_at"] = time.time() - 600
open(leftover, "w").write(json.dumps(raw)); os.utime(leftover, (time.time() - 600,) * 2)
live = os.path.join(xdg, "cyrberus", "state.json")
st._write(st.WORKING, live, {"phase": "scanning"})
check("reader picks the freshest status file", st.resolve_state_path(False) == live)
k2 = Kiosk(tk.Tk(), leftover, windowed=True)      # started while only the leftover existed
k2.poll()
check("screen follows the live daemon, not a leftover",
      k2.state_path == live and k2.current["state"] == st.WORKING,
      os.path.relpath(k2.state_path, WORK))
k3 = Kiosk(tk.Tk(), leftover, windowed=True, explicit_path=True)
k3.poll()
check("an explicit --state path is never second-guessed", k3.state_path == leftover)
# "Checking is unavailable" must say WHY, so a screen/daemon mismatch is
# visible at a glance (the cause of a real demo failure).
gone = os.path.join(xdg, "nothing-here.json")
k4 = Kiosk(tk.Tk(), gone, windowed=True, explicit_path=True)
k4.poll()
shown = " ".join(c[2].get("text", "") for c in k4.canvas.calls if c[0] == "text")
check("unavailable screen names a missing status file",
      "No status at" in shown and "scanner running" in shown, shown[-60:])
_real_access = st.os.access
st.os.access = lambda p, m: False if p == sysdir else _real_access(p, m)
try:
    reason = st.explain(gone)
finally:
    st.os.access = _real_access
check("unavailable screen names an unreadable status folder",
      "cannot open" in reason and sysdir in reason, reason[:60])
k4.canvas.calls.clear(); k4.poll()
check("no repaint while the reason stays the same", len(k4.canvas.calls) == 0,
      "%d calls" % len(k4.canvas.calls))

st.SYSTEM_STATE_DIR = old_sys
if old_xdg is None:
    os.environ.pop("XDG_RUNTIME_DIR", None)
else:
    os.environ["XDG_RUNTIME_DIR"] = old_xdg

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
