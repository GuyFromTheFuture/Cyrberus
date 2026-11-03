"""Build, sign and write a manifest onto a drive - library function plus a
LAB tool for making signed test drives without the Pi.

The Head's daemon does not use this file (it signs inside daemon.py, after a
clean scan). Tests and tests/make_sentinel_fixtures.py use sign_device().

    python3 head/sign_manifest.py keygen <dir>
        Create a LAB keypair: <dir>/lab_private.pem and <dir>/lab_public.pem.

    python3 head/sign_manifest.py sign <drive_root> <lab_private.pem> <lab_public.pem>
                                       [--hours 12] [--head-id lab-01]
        Sign whatever is at <drive_root> right now (a mounted USB drive, or a
        folder you will copy onto one).

LAB ONLY. This signs WITHOUT scanning for malware - only the Head's pipeline
scans. It refuses the real Head key, so a test drive can never carry a
production approval. Trust lab_public.pem only on test machines.
"""
import argparse
import os
import sys
from datetime import datetime, timedelta, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "common"))

from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402
from cryptography.hazmat.primitives import serialization       # noqa: E402
import manifest_lib as M                                       # noqa: E402

REAL_KEY_DIR = "/opt/cyrberus/keys"
REAL_KEY_ID_FILE = "/var/lib/cyrberus/key_id.txt"


def sign_device(mount_root, private_key_path, public_key_path, head_id,
                validity_hours=12, device=None, scan=None):
    """Sign the current contents of mount_root and write .cyrberus/ there."""
    with open(private_key_path, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    with open(public_key_path, "rb") as f:
        kid = M.key_id(f.read())

    entries, problems = M.walk_payload(mount_root)
    if problems:
        raise ValueError("device contains entries that cannot be described: %r" % problems[:5])

    now = datetime.now(timezone.utc).replace(microsecond=0)
    manifest = M.build_manifest(
        head_id, kid, now, now + timedelta(hours=validity_hours),
        device or {}, scan or {}, entries)

    blob = M.serialize(manifest)
    sig = priv.sign(blob)

    outdir = os.path.join(mount_root, M.MANIFEST_DIR)
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, M.MANIFEST_NAME), "wb") as f:
        f.write(blob)
    with open(os.path.join(outdir, M.SIG_NAME), "wb") as f:
        f.write(M.encode_sig(sig))
    return manifest


def _refuse_real_key(private_path, public_path):
    real = os.path.realpath(REAL_KEY_DIR)
    for p in (private_path, public_path):
        if os.path.realpath(p).startswith(real + os.sep):
            sys.exit("refusing: %s is the Head's real key. This tool is for lab keys only." % p)
    try:
        with open(REAL_KEY_ID_FILE) as f:
            real_id = f.read().strip()
        with open(public_path, "rb") as f:
            if M.key_id(f.read()) == real_id:
                sys.exit("refusing: that is the Head's real key (key_id %s)." % real_id)
    except OSError:
        pass


def main():
    ap = argparse.ArgumentParser(description="LAB tool: lab keys and signed test drives.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="create lab_private.pem / lab_public.pem")
    k.add_argument("dir")
    s = sub.add_parser("sign", help="sign a drive or folder with a lab key")
    s.add_argument("drive_root")
    s.add_argument("private_pem")
    s.add_argument("public_pem")
    s.add_argument("--hours", type=float, default=12.0)
    s.add_argument("--head-id", default="lab-01")
    args = ap.parse_args()

    if args.cmd == "keygen":
        os.makedirs(args.dir, exist_ok=True)
        priv_path = os.path.join(args.dir, "lab_private.pem")
        pub_path = os.path.join(args.dir, "lab_public.pem")
        if os.path.exists(priv_path) or os.path.exists(pub_path):
            sys.exit("refusing to overwrite an existing key in %s" % args.dir)
        key = ed25519.Ed25519PrivateKey.generate()
        fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
        with open(pub_path, "wb") as f:
            f.write(pub)
        print("lab keypair written to %s (key_id %s) - LAB USE ONLY" % (args.dir, M.key_id(pub)))
        return

    _refuse_real_key(args.private_pem, args.public_pem)
    # Every field the Head writes is present (MANIFEST_FORMAT section 3), so a
    # Sentinel that logs them treats lab drives exactly like real ones.
    device = {"vendor_id": "", "product_id": "", "serial": "", "model": "lab-signed",
              "size_bytes": 0, "filesystem": "", "partition_count": 1}
    scan = {"engine": "none (lab signing - NOT scanned)", "engine_version": "",
            "signature_version": "", "files_scanned": 0, "bytes_scanned": 0,
            "duration_seconds": 0}
    m = sign_device(args.drive_root, args.private_pem, args.public_pem,
                    args.head_id, args.hours, device=device, scan=scan)
    print("signed %d files, valid until %s, key_id %s - NOT malware-scanned (lab only)"
          % (len(m["files"]), m["expires_at"], m["key_id"]))


if __name__ == "__main__":
    main()
