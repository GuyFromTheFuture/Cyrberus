"""Sentinel side: reference verifier.

Returns (ok, reason). The Windows Sentinel ports this logic; the ORDER of the
checks is normative - the signature is verified over raw bytes BEFORE the JSON
is parsed, so untrusted media never reaches the parser unauthenticated.
"""
import os, sys
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import manifest_lib as M


def verify_device(mount_root, trusted_pubkeys, now=None):
    """trusted_pubkeys: {key_id: pem_bytes} for every Head this endpoint trusts."""
    now = now or datetime.now(timezone.utc)
    mpath = os.path.join(mount_root, M.MANIFEST_DIR, M.MANIFEST_NAME)
    spath = os.path.join(mount_root, M.MANIFEST_DIR, M.SIG_NAME)

    if not (os.path.isfile(mpath) and os.path.isfile(spath)):
        return False, "no manifest present"

    with open(mpath, "rb") as f:
        blob = f.read()
    with open(spath, "rb") as f:
        try:
            sig = M.decode_sig(f.read())
        except Exception:
            return False, "signature file is malformed"

    # Peek only at key_id to select the public key. Nothing else is trusted yet.
    import json
    try:
        kid = json.loads(blob.decode("utf-8")).get("key_id")
    except Exception:
        return False, "manifest is not valid JSON"
    pem = trusted_pubkeys.get(kid)
    if pem is None:
        return False, "manifest signed by an unknown Head (key_id %s)" % kid

    pub = serialization.load_pem_public_key(pem)
    try:
        pub.verify(sig, blob)
    except InvalidSignature:
        return False, "signature does not match manifest"

    manifest = json.loads(blob.decode("utf-8"))

    if manifest.get("schema") != M.SCHEMA:
        return False, "unsupported manifest schema %r" % manifest.get("schema")
    try:
        expires = M.parse_iso_z(manifest["expires_at"])
    except Exception:
        return False, "manifest has an unreadable expiry"
    if now >= expires:
        return False, "validation expired at %s" % manifest["expires_at"]

    entries, problems = M.walk_payload(mount_root)
    if problems:
        return False, "device contains %s: %s" % (problems[0][0], problems[0][1])

    on_disk = {e["path"]: e for e in entries}
    in_manifest = {e["path"]: e for e in manifest.get("files", [])}

    missing = set(in_manifest) - set(on_disk)
    if missing:
        return False, "file listed in manifest is missing: %s" % sorted(missing)[0]
    extra = set(on_disk) - set(in_manifest)
    if extra:
        return False, "file not covered by manifest: %s" % sorted(extra)[0]
    for path, want in in_manifest.items():
        got = on_disk[path]
        if got["size"] != want["size"] or got["sha256"] != want["sha256"]:
            return False, "file changed since validation: %s" % path

    return True, "valid until %s (%d files)" % (manifest["expires_at"], len(in_manifest))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("usage: verify_manifest.py <mount_root> <trusted_pub.pem> [...]")
    trusted = {}
    for p in sys.argv[2:]:
        with open(p, "rb") as f:
            pem = f.read()
        trusted[M.key_id(pem)] = pem
    ok, reason = verify_device(sys.argv[1], trusted)
    print(("PASS: " if ok else "DENY: ") + reason)
    sys.exit(0 if ok else 1)
