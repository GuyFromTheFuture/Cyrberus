"""Head side: build, sign and write a manifest onto a validated device.

Called only after the malware scan has returned clean. Writes
.cyrberus/manifest.json and .cyrberus/manifest.sig at the partition root.
"""
import os, sys
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import manifest_lib as M


def sign_device(mount_root, private_key_path, public_key_path, head_id,
                validity_hours=12, device=None, scan=None):
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


if __name__ == "__main__":
    if len(sys.argv) < 5:
        sys.exit("usage: sign_manifest.py <mount_root> <priv.pem> <pub.pem> <head_id> [hours]")
    hours = int(sys.argv[5]) if len(sys.argv) > 5 else 12
    m = sign_device(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], hours)
    print("signed %d files, expires %s" % (len(m["files"]), m["expires_at"]))
