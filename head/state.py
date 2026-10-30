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
import threading
import time

SYSTEM_STATE_DIR = "/run/cyrberus"


def resolve_state_path(writable):
    """Where the state file lives, for this process.

    Under systemd the unit's RuntimeDirectory= creates /run/cyrberus and both
    the daemon and the kiosk account can reach it. Run by hand for a demo,
    that directory does not exist and an ordinary user cannot create it, so
    fall back to the per-user runtime directory. CYRBERUS_STATE overrides
    everything - set it on both processes if you move the file.
    """
    override = os.environ.get("CYRBERUS_STATE")
    if override:
        return override

    probe = os.W_OK if writable else os.R_OK
    if os.path.isdir(SYSTEM_STATE_DIR) and os.access(SYSTEM_STATE_DIR, probe):
        return os.path.join(SYSTEM_STATE_DIR, "state.json")

    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime and os.path.isdir(runtime):
        return os.path.join(runtime, "cyrberus", "state.json")

    return os.path.join(tempfile.gettempdir(), "cyrberus-state.json")


# Resolved per process: the daemon writes, the UI reads.
STATE_PATH = resolve_state_path(writable=True)
READ_PATH = resolve_state_path(writable=False)

# States the UI knows how to draw. The daemon's internal phases collapse
# into these for display.
READY = "ready"        # waiting for a device
WORKING = "working"    # identifying / mounting / scanning / hashing / signing
CLEAN = "clean"        # validated, manifest written
THREAT = "threat"      # malware detected
BLOCKED = "blocked"    # cannot be checked (multi-partition, encrypted, etc.)

# If the UI sees state older than this, the daemon is presumed dead.
STALE_AFTER_SECONDS = 15


# The last state the daemon published, so the heartbeat can re-stamp it.
_last = {"state": READY, "detail": {}}
_lock = threading.Lock()


def publish(state, path=None, **detail):
    """Atomically replace the state file. Only the daemon calls this."""
    with _lock:
        _last["state"] = state
        _last["detail"] = dict(detail)
    return _write(state, path, detail)


def start_heartbeat(interval=5.0, path=None):
    """Re-stamp the current state periodically so the UI knows we are alive.

    The daemon publishes only on transitions, and sits idle in the udev loop
    between devices - sometimes for hours. Without this the UI would decide
    a healthy, waiting Head was a dead one after STALE_AFTER_SECONDS.
    """
    def beat():
        while True:
            time.sleep(interval)
            with _lock:
                state_name, detail = _last["state"], dict(_last["detail"])
            try:
                _write(state_name, path, detail)
            except OSError:
                pass        # transient; the next beat will try again

    thread = threading.Thread(target=beat, daemon=True, name="cyrberus-heartbeat")
    thread.start()
    return thread


def _write(state, path=None, detail=None):
    path = path or STATE_PATH
    detail = detail or {}
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
    path = path or READ_PATH
    try:
        with open(path, "r") as f:
            payload = json.load(f)
    except (OSError, ValueError):
        return {"state": READY, "updated_at": 0.0, "detail": {}, "stale": True}
    payload.setdefault("detail", {})
    payload["stale"] = (time.time() - payload.get("updated_at", 0)) > STALE_AFTER_SECONDS
    return payload
