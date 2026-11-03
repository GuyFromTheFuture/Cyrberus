"""Cyrberus manifest: shared format logic for the Head (writer) and Sentinel (verifier).

Schema 1. See MANIFEST_FORMAT.md for the normative spec.
"""
import base64, hashlib, json, os, stat
from datetime import datetime, timezone

SCHEMA = 1
MANIFEST_DIR = ".cyrberus"
MANIFEST_NAME = "manifest.json"
SIG_NAME = "manifest.sig"

# Filesystems a Windows Sentinel can mount and verify natively.
SUPPORTED_FS = {"vfat", "fat32", "exfat", "ntfs"}


def key_id(public_key_bytes: bytes) -> str:
    """Short, stable identifier for a Head's public key.

    SHA-256 over the EXACT bytes of head_public.pem as the Head wrote it (LF
    line endings, no BOM), first 16 hex characters. Nothing is normalised: a
    copy that gained CRLF endings or a BOM (Notepad, email) has a different
    key_id and every drive from that Head reads as "unknown Head". Copy the
    file in binary (scp, a USB stick) and compute key_id from its content.
    """
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


_REPARSE_POINT = 0x400    # FILE_ATTRIBUTE_REPARSE_POINT; only Windows reports it


def _special(full):
    """Why this entry cannot be described, or None if it is ordinary.

    Symlinks anywhere, and on Windows any reparse point (junctions, mount
    points, cloud placeholders). Checked with lstat so nothing is followed.
    """
    try:
        st = os.lstat(full)
    except OSError as e:
        return "unreadable: %s" % e.strerror
    if stat.S_ISLNK(st.st_mode):
        return "symlink"
    if getattr(st, "st_file_attributes", 0) & _REPARSE_POINT:
        return "reparse point"
    return None


def walk_payload(root, on_progress=None, hash_files=True):
    """Every regular file under root, excluding the manifest directory.

    Returns (entries, problems). A non-empty problems list means the device
    must be rejected: the manifest can only describe regular files, and a
    directory that cannot be read hides files nobody inspected.

    on_progress(done, total) is called as hashing proceeds, so the operator
    screen can show real progress rather than a spinner. hash_files=False
    lists paths and sizes only (the verifier compares file sets first).
    """
    entries, problems = [], []
    total = len(enumerate_files(root)) if on_progress else 0
    done = 0
    root = os.path.abspath(root)

    def rel_of(path):
        return os.path.relpath(path, root).replace(os.sep, "/")

    def unreadable_dir(err):
        # os.walk silently skips directories it cannot list unless told.
        problems.append(("unreadable directory: %s" % err.strerror,
                         rel_of(err.filename or root)))

    for dirpath, dirnames, filenames in os.walk(root, onerror=unreadable_dir):
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == MANIFEST_DIR or rel_dir.startswith(MANIFEST_DIR + os.sep):
            dirnames[:] = []
            continue
        if rel_dir == ".":
            dirnames[:] = [d for d in dirnames if d != MANIFEST_DIR]
        # A symlinked or reparse-point directory is listed here but never
        # descended into - report it rather than silently leaving it out.
        keep = []
        for d in sorted(dirnames):
            why = _special(os.path.join(dirpath, d))
            if why:
                problems.append((why, rel_of(os.path.join(dirpath, d))))
            else:
                keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = rel_of(full)
            why = _special(full)
            if why:
                problems.append((why, rel))
                continue
            if not os.path.isfile(full):
                problems.append(("not-a-regular-file", rel))
                continue
            try:
                entry = {"path": rel, "size": os.path.getsize(full)}
                if hash_files:
                    entry["sha256"] = sha256_file(full)
                entries.append(entry)
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
    """Standard base64 of the 64-byte Ed25519 signature; surrounding
    whitespace (the trailing newline, a stray CR) is ignored, anything else
    outside the base64 alphabet is an error."""
    raw = base64.b64decode(blob.strip(), validate=True)
    if len(raw) != 64:
        raise ValueError("an Ed25519 signature is 64 bytes, got %d" % len(raw))
    return raw
