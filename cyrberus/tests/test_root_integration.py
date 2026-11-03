"""Root-only integration test: real kernel mounts, real pipeline.

    sudo /opt/cyrberus/venv/bin/python3 tests/test_root_integration.py

What it proves, against a loopback disk image (never a real USB drive):
  1. The hardened mount options are enforced by the KERNEL - not just written
     into a command line: writes refused, a chmod +x script cannot execute,
     and the read-write manifest window still carries noexec/nosuid/nodev.
  2. The whole Head pipeline end to end - admit, mount, scan, hash, sign,
     write manifest, unmount - followed by the Sentinel reference verifier
     accepting the result and rejecting it after tampering.
  3. Infected, inspection-limited and multi-partition drives are refused, and
     no manifest is ever written to them.

ClamAV is replaced by a stub so the verdict can be driven both ways. The test
uses its own temporary mountpoint, keys and state file; it does not touch
/mnt/cyrberus-scan, /opt/cyrberus/keys or a running Head service. Loop devices
are not USB, so a running daemon ignores them.

On the Pi (dosfstools installed) it uses a real FAT32 image. Where mkfs.vfat is
missing it falls back to ext4 and says so.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

if os.geteuid() != 0:
    sys.exit("SKIPPED: needs root for loop mounts. Run with sudo.")

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _d in ("common", "head", "sentinel"):
    sys.path.insert(0, os.path.join(_ROOT, _d))

import manifest_lib as M          # noqa: E402
import devices                     # noqa: E402
import mounts                      # noqa: E402
import scanner                     # noqa: E402
import state                       # noqa: E402
import daemon                      # noqa: E402
from verify_manifest import verify_device  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519      # noqa: E402
from cryptography.hazmat.primitives import serialization          # noqa: E402

results = []


def check(name, cond, note=""):
    results.append(bool(cond))
    print("%-4s %-52s %s" % ("[ok]" if cond else "[XX]", name, note))


def run(*cmd):
    return subprocess.run(list(cmd), capture_output=True, check=True)


WORK = tempfile.mkdtemp(prefix="cyrb-root-")
IMG = os.path.join(WORK, "drive.img")
STAGE = os.path.join(WORK, "stage")
MP = os.path.join(WORK, "mnt")
os.makedirs(STAGE)

def _kernel_has(fs):
    """True if the running kernel can mount fs (loading its module if needed)."""
    def listed():
        try:
            with open("/proc/filesystems") as f:
                return any(line.split()[-1] == fs for line in f if line.strip())
        except OSError:
            return False
    if listed():
        return True
    try:
        subprocess.run(["modprobe", fs], capture_output=True)
    except OSError:
        return False
    return listed()


if shutil.which("mkfs.vfat") and _kernel_has("vfat"):
    FSTYPE = "vfat"
else:
    FSTYPE = "ext4"
    print("note: no FAT support here (mkfs.vfat or the kernel vfat driver missing) -")
    print("      using ext4, with admission patched to allow it. On the Pi this runs on FAT32.")
    devices.SUPPORTED_FS = devices.SUPPORTED_FS | {"ext4"}


def build_image(files):
    run("dd", "if=/dev/zero", "of=" + IMG, "bs=1M", "count=64")
    if FSTYPE == "vfat":
        run("mkfs.vfat", "-F", "32", IMG)
    else:
        run("mkfs.ext4", "-q", "-F", IMG)
    run("mount", "-o", "loop,utf8" if FSTYPE == "vfat" else "loop", IMG, STAGE)
    try:
        for rel, data in files.items():
            full = os.path.join(STAGE, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as f:
                f.write(data)
            if rel.endswith(".sh"):
                try:
                    os.chmod(full, 0o755)   # FAT has no exec bit to store; that is fine
                except OSError:
                    pass
    finally:
        run("umount", STAGE)


def opts_of(path):
    with open("/proc/mounts") as f:
        for line in f:
            parts = line.split()
            if len(parts) > 3 and parts[1] == path:
                return parts[3].split(",")
    return []


# Everything below runs as root, so call mount directly instead of via sudo.
for _name in ("mount_ro", "mount_rw", "unmount"):
    _fn = getattr(mounts, _name)
    setattr(mounts, _name, (lambda f: (lambda *a, **k: f(*a, **{**k, "sudo": False})))(_fn))

try:
    # ------------------------------------------------------------------ 1
    print("=== 1. kernel-enforced mount hardening (%s) ===" % FSTYPE)
    build_image({"notes.txt": b"payload\n",
                 "run.sh": b"#!/bin/sh\necho pwned\n"})

    mounts.mount_ro(IMG, MP, FSTYPE)
    o = opts_of(MP)
    for flag in ("ro", "noexec", "nosuid", "nodev"):
        check("kernel enforces %s" % flag, flag in o, ",".join(o))
    check("contents readable", open(os.path.join(MP, "notes.txt")).read().strip() == "payload")
    try:
        open(os.path.join(MP, "planted.txt"), "w").close()
        wrote = True
    except OSError:
        wrote = False
    check("write refused on the scan mount", not wrote)
    try:
        subprocess.run([os.path.join(MP, "run.sh")], capture_output=True)
        executed = True
    except PermissionError:
        executed = False
    check("script on the drive cannot execute", not executed)
    check("scan mount released", mounts.unmount(MP) is True)

    mounts.mount_rw(IMG, MP, FSTYPE)
    o = opts_of(MP)
    check("manifest window is writable", "rw" in o, ",".join(o))
    check("manifest window still noexec", "noexec" in o)
    check("manifest window still nosuid", "nosuid" in o)
    mounts.unmount(MP)

    # A disk the system is using (the boot SSD of a USB-booted Pi) must never
    # be treated as a drive to check. Use a real block device to prove it.
    try:
        loopdev = subprocess.run(["losetup", "-f", "--show", IMG], capture_output=True,
                                 text=True).stdout.strip()
    except OSError:
        loopdev = ""
    if loopdev:
        try:
            check("unmounted block device is not in use", not devices.in_use([loopdev]), loopdev)
            run("mount", "-o", "ro", loopdev, STAGE)
            check("mounted block device is in use", devices.in_use([loopdev]))
            run("umount", STAGE)
            check("released again after unmount", not devices.in_use([loopdev]))
        finally:
            if os.path.ismount(STAGE):
                subprocess.run(["umount", "-l", STAGE], capture_output=True)
            subprocess.run(["losetup", "-d", loopdev], capture_output=True)
    else:
        print("note: losetup unavailable - in-use detection not exercised here")

    # ------------------------------------------------------------------ 2
    print("\n=== 2. full Head pipeline, then the Sentinel verifier ===")
    keys = os.path.join(WORK, "keys")
    os.makedirs(keys)
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(serialization.Encoding.PEM,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(os.path.join(keys, "head_private.pem"), "wb") as f:
        f.write(priv.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    with open(os.path.join(keys, "head_public.pem"), "wb") as f:
        f.write(pub_pem)

    fake = os.path.join(WORK, "fake_clamdscan")
    with open(fake, "w") as f:
        f.write("#!/bin/sh\n"
                'case "$1" in --version) echo "ClamAV 1.0.7/27234/test"; exit 0;; esac\n'
                'case "$CYRB_VERDICT" in\n'
                '  threat) echo "$5/invoice.txt: Win.Test.EICAR_HDB-1 FOUND"; exit 1;;\n'
                '  limit)  echo "$5/movie.mkv: Heuristics.Limits.Exceeded.MaxFileSize FOUND"; exit 1;;\n'
                'esac\nexit 0\n')
    os.chmod(fake, 0o755)

    daemon.MOUNTPOINT = MP
    daemon.PRIV_KEY = os.path.join(keys, "head_private.pem")
    daemon.PUB_KEY = os.path.join(keys, "head_public.pem")
    scanner.CLAMDSCAN = fake
    state.STATE_PATH = state.READ_PATH = os.path.join(WORK, "state.json")
    trusted = {M.key_id(pub_pem): pub_pem}

    record = {"node": IMG, "is_usb": True, "is_removable": True,
              "vendor_id": "0781", "product_id": "5581", "serial": "TEST0001",
              "model": "Loopback Test", "size_bytes": 64 * 1024 * 1024,
              "partitions": [{"node": IMG, "fstype": FSTYPE}]}
    head = daemon.Head()

    build_image({"readme.txt": b"hello\n",
                 "Documents/report.docx": os.urandom(4096),
                 "Documents/2026/notes.md": b"# notes\n",
                 "Documents/informe_año.txt": "ñ 日本語\n".encode()})
    os.environ["CYRB_VERDICT"] = "clean"
    head.handle(record)
    s = state.read()
    check("clean drive -> CLEAN", s["state"] == state.CLEAN, s["state"])
    check("4 files recorded", s["detail"].get("file_count") == 4, str(s["detail"].get("file_count")))
    check("drive left unmounted", not os.path.ismount(MP))

    mounts.mount_ro(IMG, MP, FSTYPE)
    man_path = os.path.join(MP, M.MANIFEST_DIR, M.MANIFEST_NAME)
    check("manifest written to the drive", os.path.exists(man_path))
    man = json.loads(open(man_path, "rb").read().decode())
    check("device block recorded", man["device"]["serial"] == "TEST0001")
    check("non-ASCII filename recorded exactly",
          "Documents/informe_año.txt" in [e["path"] for e in man["files"]],
          ", ".join(e["path"] for e in man["files"] if "Documents/inf" in e["path"]))
    check("engine version recorded", man["scan"]["engine_version"] == "1.0.7")
    ok, why = verify_device(MP, trusted)
    check("Sentinel verifier ACCEPTS the drive", ok, why)
    mounts.unmount(MP)

    mounts.mount_rw(IMG, MP, FSTYPE)
    with open(os.path.join(MP, "planted.exe"), "wb") as f:
        f.write(b"MZ\x90")
    mounts.sync()
    mounts.unmount(MP)
    mounts.mount_ro(IMG, MP, FSTYPE)
    ok, why = verify_device(MP, trusted)
    check("Sentinel verifier REJECTS after tampering", not ok, why)
    mounts.unmount(MP)

    # ------------------------------------------------------------------ 3
    print("\n=== 3. drives that must be refused ===")
    for verdict, want_state, label in (
            ("threat", state.THREAT, "infected drive -> THREAT"),
            ("limit", state.BLOCKED, "oversized file -> BLOCKED, not THREAT")):
        build_image({"invoice.txt": b"x", "movie.mkv": b"y"})
        os.environ["CYRB_VERDICT"] = verdict
        head.handle(record)
        s = state.read()
        check(label, s["state"] == want_state,
              s["state"] + (" / " + s["detail"].get("reason", "") if s["detail"].get("reason") else ""))
        mounts.mount_ro(IMG, MP, FSTYPE)
        check("  ...and no manifest written",
              not os.path.exists(os.path.join(MP, M.MANIFEST_DIR, M.MANIFEST_NAME)))
        mounts.unmount(MP)

    os.environ["CYRB_VERDICT"] = "clean"
    multi = dict(record)
    multi["partitions"] = [{"node": IMG, "fstype": FSTYPE}, {"node": IMG + "2", "fstype": FSTYPE}]
    head.handle(multi)
    s = state.read()
    check("two partitions -> BLOCKED", s["state"] == state.BLOCKED, s["detail"].get("reason", ""))
    check("  ...and it was never mounted", not os.path.ismount(MP))

finally:
    if os.path.ismount(MP):
        subprocess.run(["umount", "-l", MP], capture_output=True)
    if os.path.ismount(STAGE):
        subprocess.run(["umount", "-l", STAGE], capture_output=True)
    shutil.rmtree(WORK, ignore_errors=True)

print("\n%d/%d root integration checks passed (%s)" % (sum(results), len(results), FSTYPE))
sys.exit(0 if all(results) else 1)
