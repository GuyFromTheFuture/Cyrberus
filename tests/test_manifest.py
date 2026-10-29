import os, sys
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _d in ("common", "head", "sentinel"):
    sys.path.insert(0, os.path.join(_ROOT, _d))

"""Round-trip and tamper tests for the Cyrberus manifest format."""
import json, os, shutil, tempfile
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import manifest_lib as M
from sign_manifest import sign_device
from verify_manifest import verify_device

WORK = tempfile.mkdtemp(prefix="cyrb-")
KEYS = os.path.join(WORK, "keys"); os.makedirs(KEYS)

def make_key(name):
    priv = ed25519.Ed25519PrivateKey.generate()
    pp, bp = os.path.join(KEYS, name + "_priv.pem"), os.path.join(KEYS, name + "_pub.pem")
    open(pp, "wb").write(priv.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    open(bp, "wb").write(priv.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    return pp, bp

HEAD_PRIV, HEAD_PUB = make_key("head")
ROGUE_PRIV, ROGUE_PUB = make_key("rogue")
TRUSTED = {M.key_id(open(HEAD_PUB, "rb").read()): open(HEAD_PUB, "rb").read()}

def fresh_drive(empty=False):
    d = tempfile.mkdtemp(prefix="drive-", dir=WORK)
    if not empty:
        os.makedirs(os.path.join(d, "Documents", "2026"))
        open(os.path.join(d, "readme.txt"), "w").write("hello\n")
        open(os.path.join(d, "Documents", "budget.xlsx"), "wb").write(os.urandom(4096))
        open(os.path.join(d, "Documents", "2026", "notes.md"), "w").write("# notes\n")
        open(os.path.join(d, "Documents", "informe_año.txt"), "w", encoding="utf-8").write("ñ é 日本語\n")
    return d

DEV = {"vendor_id": "0781", "product_id": "5581", "serial": "4C530001", "model": "SanDisk Ultra",
       "size_bytes": 32015679488, "filesystem": "vfat", "partition_count": 1}
SCAN = {"engine": "ClamAV", "engine_version": "1.0.7", "signature_version": "27234",
        "files_scanned": 5, "bytes_scanned": 4203, "duration_seconds": 1.2}

results = []
def check(name, got_ok, want_ok, reason):
    ok = (got_ok == want_ok)
    results.append(ok)
    print("%-4s %-34s -> %s" % ("[ok]" if ok else "[XX]", name, reason))

# 1 happy path
d = fresh_drive()
m = sign_device(d, HEAD_PRIV, HEAD_PUB, "head-01", 12, DEV, SCAN)
ok, r = verify_device(d, TRUSTED); check("clean drive", ok, True, r)

# 2 modified file
d2 = fresh_drive(); sign_device(d2, HEAD_PRIV, HEAD_PUB, "head-01", 12, DEV, SCAN)
open(os.path.join(d2, "readme.txt"), "a").write("tampered")
ok, r = verify_device(d2, TRUSTED); check("file modified after signing", ok, False, r)

# 3 added file
d3 = fresh_drive(); sign_device(d3, HEAD_PRIV, HEAD_PUB, "head-01", 12, DEV, SCAN)
open(os.path.join(d3, "payload.exe"), "wb").write(b"MZ")
ok, r = verify_device(d3, TRUSTED); check("file added after signing", ok, False, r)

# 4 deleted file
d4 = fresh_drive(); sign_device(d4, HEAD_PRIV, HEAD_PUB, "head-01", 12, DEV, SCAN)
os.remove(os.path.join(d4, "Documents", "budget.xlsx"))
ok, r = verify_device(d4, TRUSTED); check("file deleted after signing", ok, False, r)

# 5 expired
d5 = fresh_drive(); sign_device(d5, HEAD_PRIV, HEAD_PUB, "head-01", 12, DEV, SCAN)
later = datetime.now(timezone.utc) + timedelta(hours=13)
ok, r = verify_device(d5, TRUSTED, now=later); check("expired validation", ok, False, r)

# 6 manifest edited to extend expiry
d6 = fresh_drive(); sign_device(d6, HEAD_PRIV, HEAD_PUB, "head-01", 12, DEV, SCAN)
mp = os.path.join(d6, M.MANIFEST_DIR, M.MANIFEST_NAME)
man = json.loads(open(mp, "rb").read().decode()); man["expires_at"] = "2099-01-01T00:00:00Z"
open(mp, "wb").write(M.serialize(man))
ok, r = verify_device(d6, TRUSTED); check("expiry edited in manifest", ok, False, r)

# 7 signed by an untrusted Head
d7 = fresh_drive(); sign_device(d7, ROGUE_PRIV, ROGUE_PUB, "rogue", 12, DEV, SCAN)
ok, r = verify_device(d7, TRUSTED); check("signed by unknown Head", ok, False, r)

# 8 no manifest at all
d8 = fresh_drive()
ok, r = verify_device(d8, TRUSTED); check("unvalidated drive", ok, False, r)

# 9 empty drive
d9 = fresh_drive(empty=True); sign_device(d9, HEAD_PRIV, HEAD_PUB, "head-01", 12, DEV, SCAN)
ok, r = verify_device(d9, TRUSTED); check("empty drive", ok, True, r)

# 10 signature file truncated
d10 = fresh_drive(); sign_device(d10, HEAD_PRIV, HEAD_PUB, "head-01", 12, DEV, SCAN)
open(os.path.join(d10, M.MANIFEST_DIR, M.SIG_NAME), "wb").write(b"AAAA\n")
ok, r = verify_device(d10, TRUSTED); check("corrupt signature file", ok, False, r)

# 11 unicode paths survive the round trip
assert any("año" in e["path"] for e in m["files"]), "unicode path lost"
print("\n[ok]  unicode filenames preserved in manifest")

print("\nmanifest bytes for a 5-file drive: %d" % len(M.serialize(m)))
print("sample entry: %s" % json.dumps(m["files"][0]))
print("\n%d/%d tamper and round-trip cases behaved correctly" % (sum(results), len(results)))
shutil.rmtree(WORK)
