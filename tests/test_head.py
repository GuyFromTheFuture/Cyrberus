"""Tests for the Head's decision logic.

The parts that touch hardware (udev, mount, clamd) are thin adapters; the
logic they wrap is pure and tested here without a Pi, a USB drive or ClamAV.
"""
import os
import sys
import tempfile
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _d in ("common", "head"):
    sys.path.insert(0, os.path.join(_ROOT, _d))

import devices
import mounts
import scanner
import state

results = []


def check(name, cond, note=""):
    results.append(bool(cond))
    print("%-4s %-44s %s" % ("[ok]" if cond else "[XX]", name, note))


def dev(partitions, usb=True, removable=True, **kw):
    rec = {"node": "/dev/sda", "is_usb": usb, "is_removable": removable,
           "vendor_id": "0781", "product_id": "5581", "serial": "4C530001",
           "model": "SanDisk Ultra", "size_bytes": 32015679488,
           "partitions": partitions}
    rec.update(kw)
    return rec


print("--- admission policy ---")

ok, why = devices.admit(dev([{"node": "/dev/sda1", "fstype": "vfat"}]))
check("single FAT32 partition is admitted", ok and why is None, "")

ok, why = devices.admit(dev([{"node": "/dev/sda1", "fstype": "exfat"}]))
check("exFAT is admitted", ok, "")

ok, why = devices.admit(dev([{"node": "/dev/sda1", "fstype": "ntfs"}]))
check("NTFS is admitted", ok, "")

# The drive from the verification checklist: vfat + ext4
ok, why = devices.admit(dev([{"node": "/dev/sda1", "fstype": "vfat"},
                             {"node": "/dev/sda2", "fstype": "ext4"}]))
check("two partitions rejected", (not ok) and why == devices.R_MULTI_PARTITION, why or "")

ok, why = devices.admit(dev([]))
check("no partition rejected", (not ok) and why == devices.R_NO_PARTITION, why or "")

ok, why = devices.admit(dev([{"node": "/dev/sda1", "fstype": "ext4"}]))
check("ext4 rejected (Sentinel cannot verify)", (not ok) and why == devices.R_UNSUPPORTED_FS, why or "")

ok, why = devices.admit(dev([{"node": "/dev/sda1", "fstype": "crypto_LUKS"}]))
check("encrypted rejected", (not ok) and why == devices.R_ENCRYPTED, why or "")

ok, why = devices.admit(dev([{"node": "/dev/sda1", "fstype": "vfat", "encrypted": True}]))
check("encrypted flag rejected", (not ok) and why == devices.R_ENCRYPTED, why or "")

ok, why = devices.admit(dev([{"node": "/dev/sda1", "fstype": "vfat"}], usb=False, removable=False))
check("internal disk rejected", (not ok) and why == devices.R_NOT_REMOVABLE, why or "")

print("\n--- manifest device block ---")
blk = devices.device_block(dev([{"node": "/dev/sda1", "fstype": "vfat"}]))
check("device block carries descriptors", blk["vendor_id"] == "0781" and blk["serial"] == "4C530001")
check("device block records partition count", blk["partition_count"] == 1)
check("device block records filesystem", blk["filesystem"] == "vfat")

print("\n--- scan output parsing ---")

r = scanner.parse_output("", 0)
check("clean scan", r.clean and r.usable and not r.detections)

r = scanner.parse_output("/mnt/x/evil.exe: Win.Test.EICAR_HDB-1 FOUND\n", 1)
check("detection parsed", (not r.clean) and r.detections == [("/mnt/x/evil.exe", "Win.Test.EICAR_HDB-1")],
      r.detections and r.detections[0][1] or "")

r = scanner.parse_output("/mnt/x/a: Can't open file ERROR\n", 0)
check("unreadable file makes scan unusable", r.clean and not r.usable,
      r.errors and r.errors[0][1] or "")

r = scanner.parse_output("", 2)
check("engine failure is not clean", (not r.clean) and r.engine_error is not None)

noise = ("----------- SCAN SUMMARY -----------\n"
         "Known viruses: 8700000\nInfected files: 0\nTime: 2.1 sec\n")
r = scanner.parse_output(noise, 0)
check("summary lines ignored", r.clean and not r.detections and not r.errors)

multi = ("/mnt/x/a.exe: Win.Trojan.A FOUND\n"
         "/mnt/x/b.doc: Doc.Dropper.B FOUND\n")
r = scanner.parse_output(multi, 1)
check("multiple detections parsed", len(r.detections) == 2)

print("\n--- mount options ---")
o = mounts._opts_for("vfat", 1001, 1001)
check("FAT mount is ro,noexec,nosuid,nodev",
      all(f in o for f in ("ro", "noexec", "nosuid", "nodev")), o)
check("FAT mount carries ownership", "uid=1001" in o and "gid=1001" in o)
o_rw = mounts._opts_for("vfat", 1001, 1001, writable=True)
check("writable variant drops ro only",
      "rw" in o_rw and "ro," not in o_rw and "noexec" in o_rw, o_rw)
o_ext = mounts._opts_for("ext4", 1001, 1001)
check("ext4 gets no uid/gid (has its own)", "uid=" not in o_ext, o_ext)

print("\n--- state file ---")
tmp = tempfile.mkdtemp()
sp = os.path.join(tmp, "state.json")

state.publish(state.READY, path=sp)
p = state.read(sp)
check("publish/read round trip", p["state"] == state.READY and not p["stale"])

state.publish(state.WORKING, path=sp, phase="hashing", done=12, total=100)
p = state.read(sp)
check("detail survives", p["detail"]["done"] == 12 and p["detail"]["phase"] == "hashing")

p = state.read(os.path.join(tmp, "nope.json"))
check("missing state file is not fatal", p["state"] == state.READY and p["stale"])

with open(sp, "w") as f:
    f.write("{ broken json")
p = state.read(sp)
check("corrupt state file is not fatal", p["state"] == state.READY and p["stale"])

state.publish(state.CLEAN, path=sp)
import json
raw = json.load(open(sp))
raw["updated_at"] = time.time() - (state.STALE_AFTER_SECONDS + 5)
open(sp, "w").write(json.dumps(raw))
p = state.read(sp)
check("old state reported stale", p["stale"])

check("state file is world readable", (os.stat(sp).st_mode & 0o044) != 0)

print("\n%d/%d checks passed" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
