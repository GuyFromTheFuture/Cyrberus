"""Cyrberus manifest: shared format logic for the Head (writer) and Sentinel (verifier).

Schema 1. See MANIFEST_FORMAT.md for the normative spec.
"""
import base64, hashlib, json, os
from datetime import datetime, timezone

SCHEMA = 1
MANIFEST_DIR = ".cyrberus"
MANIFEST_NAME = "manifest.json"
SIG_NAME = "manifest.sig"

# Filesystems a Windows Sentinel can mount and verify natively.
SUPPORTED_FS = {"vfat", "fat32", "exfat", "ntfs"}


def key_id(public_key_bytes: bytes) -> str:
    """Short, stable identifier for a Head's public key (PEM bytes)."""
    return hashlib.sha256(public_key_bytes).hexdigest()[:16]


def sha256_file(path, chunk=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def enumerate_files(root):
    """Paths of every regular file under root, excluding the manifest dir.

    Cheap compared to hashing, so the daemon calls this first to learn the
    total for the progress bar.
    """
    out = []
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == MANIFEST_DIR or rel_dir.startswith(MANIFEST_DIR + os.sep):
            dirnames[:] = []
            continue
        if rel_dir == ".":
            dirnames[:] = [d for d in dirnames if d != MANIFEST_DIR]
        for name in filenames:
            out.append(os.path.join(dirpath, name))
    return out


def walk_payload(root, on_progress=None):
    """Every regular file under root, excluding the manifest directory.

    Returns (entries, problems). A non-empty problems list means the device
    must be rejected: the manifest can only describe regular files.

    on_progress(done, total) is called as hashing proceeds, so the operator
    screen can show real progress rather than a spinner.
    """
    entries, problems = [], []
    total = len(enumerate_files(root)) if on_progress else 0
    done = 0
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == MANIFEST_DIR or rel_dir.startswith(MANIFEST_DIR + os.sep):
            dirnames[:] = []
            continue
        if rel_dir == ".":
            dirnames[:] = [d for d in dirnames if d != MANIFEST_DIR]
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if os.path.islink(full):
                problems.append(("symlink", rel))
                continue
            if not os.path.isfile(full):
                problems.append(("not-a-regular-file", rel))
                continue
            try:
                entries.append({
                    "path": rel,
                    "size": os.path.getsize(full),
                    "sha256": sha256_file(full),
                })
            except OSError as e:
                problems.append(("unreadable: %s" % e.strerror, rel))
            if on_progress:
                done += 1
                on_progress(done, total)
    entries.sort(key=lambda e: e["path"])
    return entries, problems


def build_manifest(head_id, kid, issued, expires, device, scan, entries):
    return {
        "schema": SCHEMA,
        "head_id": head_id,
        "key_id": kid,
        "issued_at": issued.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "device": device,
        "scan": scan,
        "files": entries,
    }


def serialize(manifest) -> bytes:
    """The exact bytes written to disk AND the exact bytes signed."""
    return json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")


def parse_iso_z(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def encode_sig(raw: bytes) -> bytes:
    return base64.b64encode(raw) + b"\n"


def decode_sig(blob: bytes) -> bytes:
    return base64.b64decode(blob.strip())
