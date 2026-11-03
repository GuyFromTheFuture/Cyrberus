"""Sentinel side: reference verifier for manifest schema 1.

Returns (ok, reason). The Windows Sentinel ports this logic. The ORDER of the
checks is normative (MANIFEST_FORMAT.md section 5): the signature is verified
over the raw bytes BEFORE the JSON is parsed as trusted input, so untrusted
media never reaches the parser as authenticated data.

Behaviour a port must reproduce exactly:
  * key_id = first 16 hex of SHA-256 over the trusted PEM file's exact bytes
  * manifest.sig = standard base64 of 64 bytes; surrounding whitespace ignored
  * expired when now >= expires_at (UTC); exactly at expiry is expired
  * paths compared case-insensitively (MANIFEST_FORMAT.md section 8 - FAT,
    exFAT and NTFS are case-insensitive) using SIMPLE per-character upper-
    casing, as NTFS and .NET StringComparison.OrdinalIgnoreCase do: a
    character whose uppercase is several characters is left as it is, so
    "Straße" and "STRASSE" are different names. Two paths that are equal
    under this folding on either side make the drive ambiguous -> deny
  * any exception anywhere -> deny (fail closed)

    python3 sentinel/verify_manifest.py <drive_root> <trusted_pub.pem> [more.pem ...]
"""
import json
import os
import sys
from datetime import datetime, timezone

# Run as a script, Python only searches sentinel/. The shared format code
# lives in common/.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "common"))

from cryptography.hazmat.primitives import serialization       # noqa: E402
from cryptography.exceptions import InvalidSignature           # noqa: E402
import manifest_lib as M                                       # noqa: E402


def fold(path):
    """Case-insensitive key: simple per-character uppercase (see module doc)."""
    out = []
    for ch in path:
        up = ch.upper()
        out.append(up if len(up) == 1 else ch)
    return "".join(out)


def _by_folded_path(items, side):
    """{folded path: entry}; refuses paths that differ only in case."""
    out = {}
    for e in items:
        k = fold(e["path"])
        if k in out:
            raise ValueError("%s has two paths that differ only in case: %s / %s"
                             % (side, out[k]["path"], e["path"]))
        out[k] = e
    return out


def verify_device(mount_root, trusted_pubkeys, now=None):
    """trusted_pubkeys: {key_id: pem_bytes} for every Head this endpoint trusts."""
    try:
        return _verify(mount_root, trusted_pubkeys, now or datetime.now(timezone.utc))
    except Exception as e:                       # fail closed on anything unforeseen
        return False, "verification error: %s: %s" % (type(e).__name__, e)


def _verify(mount_root, trusted_pubkeys, now):
    mpath = os.path.join(mount_root, M.MANIFEST_DIR, M.MANIFEST_NAME)
    spath = os.path.join(mount_root, M.MANIFEST_DIR, M.SIG_NAME)

    # 1. Both files present.
    if not (os.path.isfile(mpath) and os.path.isfile(spath)):
        return False, "no manifest present"

    # 2. Raw bytes; decode the signature.
    with open(mpath, "rb") as f:
        blob = f.read()
    with open(spath, "rb") as f:
        try:
            sig = M.decode_sig(f.read())
        except Exception:
            return False, "signature file is malformed"

    # 3. key_id only, to choose a public key. Nothing else is trusted yet.
    try:
        kid = json.loads(blob.decode("utf-8")).get("key_id")
    except Exception:
        return False, "manifest is not valid JSON"
    pem = trusted_pubkeys.get(kid)
    if pem is None:
        return False, "manifest signed by an unknown Head (key_id %s)" % kid

    # 4. Signature over the raw bytes.
    try:
        pub = serialization.load_pem_public_key(pem)
    except Exception:
        return False, "trusted key for key_id %s is unreadable" % kid
    try:
        pub.verify(sig, blob)
    except InvalidSignature:
        return False, "signature does not match manifest"

    # 5. Only now is the content trusted.
    manifest = json.loads(blob.decode("utf-8"))

    # 6. Schema.
    if manifest.get("schema") != M.SCHEMA:
        return False, "unsupported manifest schema %r" % manifest.get("schema")

    # 7. Expiry (UTC). Exactly at expires_at counts as expired.
    try:
        expires = M.parse_iso_z(manifest["expires_at"])
    except Exception:
        return False, "manifest has an unreadable expiry"
    if now >= expires:
        return False, "validation expired at %s" % manifest["expires_at"]

    # 8. Walk the drive: anything that is not a plain file denies. No hashing yet.
    entries, problems = M.walk_payload(mount_root, hash_files=False)
    if problems:
        return False, "device contains %s: %s" % (problems[0][0], problems[0][1])

    try:
        on_disk = _by_folded_path(entries, "drive")
        listed = _by_folded_path(manifest.get("files", []), "manifest")
    except ValueError as e:
        return False, str(e)

    # 9. Nothing on the drive that the manifest does not list.
    extra = sorted(set(on_disk) - set(listed))
    if extra:
        return False, "file not covered by manifest: %s" % on_disk[extra[0]]["path"]

    # 10. Nothing listed that is missing from the drive.
    missing = sorted(set(listed) - set(on_disk))
    if missing:
        return False, "file listed in manifest is missing: %s" % listed[missing[0]]["path"]

    # 11. Every file the expected size and hash. (A Sentinel that releases
    # files does this while copying - see HANDOFF.md section 10.4.)
    for k in sorted(listed):
        want, got = listed[k], on_disk[k]
        full = os.path.join(mount_root, *got["path"].split("/"))
        if got["size"] != want["size"] or M.sha256_file(full) != want["sha256"]:
            return False, "file changed since validation: %s" % got["path"]

    # 12. All checks passed.
    return True, "valid until %s (%d files)" % (manifest["expires_at"], len(listed))


def load_trusted(paths):
    """{key_id: pem} from PEM files, key_id computed from content (never filename)."""
    trusted = {}
    for p in paths:
        with open(p, "rb") as f:
            pem = f.read()
        trusted[M.key_id(pem)] = pem
    return trusted


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("usage: verify_manifest.py <drive_root> <trusted_pub.pem> [...]")
    ok, reason = verify_device(sys.argv[1], load_trusted(sys.argv[2:]))
    print(("PASS: " if ok else "DENY: ") + reason)
    sys.exit(0 if ok else 1)
