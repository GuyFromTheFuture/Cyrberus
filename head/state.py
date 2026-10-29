"""Shared state between the privileged daemon and the unprivileged kiosk UI.

The daemon is the only writer. It publishes its current state to a JSON file
in /run, replaced atomically so a reader never sees a half-written file. The
UI polls it.

A file rather than a socket: the UI needs *current* state, not a stream of
events, so polling is the natural fit. Either process can restart without the
other noticing, and nothing has to manage a connection.
"""
import json
import os
import tempfile
import time

STATE_PATH = "/run/cyrberus/state.json"

# States the UI knows how to draw. The daemon's internal phases collapse
# into these for display.
READY = "ready"        # waiting for a device
WORKING = "working"    # identifying / mounting / scanning / hashing / signing
CLEAN = "clean"        # validated, manifest written
THREAT = "threat"      # malware detected
BLOCKED = "blocked"    # cannot be checked (multi-partition, encrypted, etc.)

# If the UI sees state older than this, the daemon is presumed dead.
STALE_AFTER_SECONDS = 15


def publish(state, path=None, **detail):
    """Atomically replace the state file. Only the daemon calls this."""
    path = path or STATE_PATH
    payload = {
        "state": state,
        "updated_at": time.time(),
        "detail": detail,
    }
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".state-")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)          # atomic on POSIX
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return payload


def read(path=None):
    """Read current state. Never raises - the UI must keep drawing."""
    path = path or STATE_PATH
    try:
        with open(path, "r") as f:
            payload = json.load(f)
    except (OSError, ValueError):
        return {"state": READY, "updated_at": 0.0, "detail": {}, "stale": True}
    payload.setdefault("detail", {})
    payload["stale"] = (time.time() - payload.get("updated_at", 0)) > STALE_AFTER_SECONDS
    return payload
