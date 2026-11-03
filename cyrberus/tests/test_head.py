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

ok, why = devices.admit(dev([{"node": "/dev/sda1", "fstype": "vfat"}], in_use=True))
check("disk the system is using rejected", (not ok) and why == devices.R_IN_USE, why or "")
check("root filesystem's device counts as in use",
      os.stat("/").st_dev in devices._in_use_devnums())

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
check("FAT names decoded as UTF-8, 8.3 names as stored",
      "utf8" in o.split(",") and "shortname=mixed" in o.split(","))
o_exf = mounts._opts_for("exfat", 1001, 1001)
check("exFAT not given the FAT-only utf8 flag", "utf8" not in o_exf.split(","), o_exf)

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

print("\n--- clamdscan exit 2 keeps what it reported ---")
r = scanner.parse_output("/m/a.doc: Can't open file ERROR\n", 2)
check("exit 2 with file errors is not an engine failure",
      r.errors and r.engine_error is None and not r.usable)
r = scanner.parse_output("/m/eicar.txt: Win.Test.EICAR_HDB-1 FOUND\n/m/b: Can't open file ERROR\n", 2)
check("exit 2 with a detection still reports the malware", r.malware and r.engine_error is None)
r = scanner.parse_output("", 2)
check("exit 2 with nothing reported is an engine failure", r.engine_error is not None)

print("\n--- inspection limits are not malware ---")
r = scanner.parse_output("/m/movie.mkv: Heuristics.Limits.Exceeded.MaxFileSize FOUND\n", 1)
check("oversized file is a limit, not malware", r.limited and not r.malware,
      r.limited and r.limited[0][1] or "")
r = scanner.parse_output("/m/a.zip: Heuristics.Encrypted.Zip FOUND\n", 1)
check("encrypted archive is a limit, not malware", r.limited and not r.malware)
r = scanner.parse_output("/m/a.zip: Heuristics.Encrypted.Zip FOUND\n"
                         "/m/b.exe: Win.Trojan.Agent-1 FOUND\n", 1)
check("real malware still wins alongside a limit", len(r.malware) == 1 and len(r.limited) == 1)
r = scanner.parse_output("/m/eicar.txt: Win.Test.EICAR_HDB-1 FOUND\n", 1)
check("EICAR is malware", r.malware and not r.limited)
check("prefix match is exact", not scanner.is_inspection_limit("Heuristics.Phishing.Email"))

print("\n--- heartbeat keeps an idle daemon alive ---")
import shutil as _sh
hb_dir = tempfile.mkdtemp()
hb_path = os.path.join(hb_dir, "hb.json")
_old_stale = state.STALE_AFTER_SECONDS
state.STALE_AFTER_SECONDS = 2
state.publish(state.READY, path=hb_path, signatures_updated="27234")
state.start_heartbeat(interval=0.5, path=hb_path)
went_stale = False
for _ in range(8):                      # 4 s idle, twice the stale window
    time.sleep(0.5)
    if state.read(hb_path)["stale"]:
        went_stale = True
check("idle state never goes stale", not went_stale)
check("heartbeat keeps the detail", state.read(hb_path)["detail"].get("signatures_updated") == "27234")
dead = os.path.join(hb_dir, "dead.json")
state._write(state.CLEAN, dead, {})
time.sleep(2.5)
check("a file nothing re-stamps still goes stale", state.read(dead)["stale"])
state.STALE_AFTER_SECONDS = _old_stale
_sh.rmtree(hb_dir)

print("\n--- unattended boot behaviour ---")
import daemon                                    # noqa: E402

lk_dir = tempfile.mkdtemp()
lk = os.path.join(lk_dir, "head.lock")
first = daemon.single_instance(lk)
try:
    daemon.single_instance(lk)
    second_refused = False
except daemon.AlreadyRunning:
    second_refused = True
check("a second daemon is refused", second_refused)
os.close(first)
again = daemon.single_instance(lk)
check("lock is free once the first daemon exits", again is not None)
os.close(again)

# Drive the run loop with fake hardware and record every screen published.
run_dir = tempfile.mkdtemp()
state.STATE_PATH = state.READ_PATH = os.path.join(run_dir, "state.json")
published = []
_real_publish = state.publish


def _recording_publish(name, path=None, **detail):
    published.append((name, detail))
    return _real_publish(name, path=path, **detail)


versions = iter(["", "", "27801", "27801"])     # clamd still loading, then ready
_saved = (state.publish, scanner.engine_info, devices.current_usb_disks,
          devices.monitor, daemon.MOUNTPOINT)
state.publish = _recording_publish
scanner.engine_info = lambda *a, **k: {"engine": "ClamAV", "engine_version": "1.0.7",
                                       "signature_version": next(versions, "27801")}
devices.current_usb_disks = lambda: [{"node": "/dev/sdz", "model": "Left In"}]
devices.monitor = lambda idle_every=None: iter([
    ("idle", None),                  # still BLOCKED: must not be overwritten
    ("add", {"node": "/dev/sdy", "in_use": True}),   # boot SSD re-announced: ignored
    ("remove", {"node": "/dev/sdz"}),
    ("idle", None),                  # READY, clamd now answers
    ("idle", None),                  # nothing changed: no republish
])
daemon.MOUNTPOINT = os.path.join(run_dir, "not-mounted")
try:
    daemon.Head().run()
finally:
    (state.publish, scanner.engine_info, devices.current_usb_disks,
     devices.monitor, daemon.MOUNTPOINT) = _saved

names = [n for n, _ in published]


check("drive present at boot -> asked to re-insert",
      published[1][0] == state.BLOCKED
      and published[1][1].get("reason") == devices.R_PRESENT_AT_START,
      published[1][1].get("reason", ""))
check("idle tick never overwrites a result screen", names[2] == state.READY,
      " -> ".join(names))
check("virus list version appears once clamd answers",
      published[-1][0] == state.READY
      and published[-1][1].get("signatures_updated") == "27801")
check("no republish when nothing changed", len(published) == 4, "%d publishes" % len(published))

# Verdict order inside the daemon: malware beats a scan error; file errors get
# their own message.
_saved_scan = scanner.scan_tree
verdicts = []
for label, res in (
        ("malware + engine error", scanner.ScanResult(False, [("/m/x", "Win.Test.EICAR_HDB-1")], [],
                                                       engine_error="exit 2")),
        ("file errors only", scanner.parse_output("/m/a: Can't open file ERROR\n", 2))):
    scanner.scan_tree = lambda *a, **k: res
    published.clear()
    state.publish = _recording_publish
    try:
        daemon.Head()._inspect({}, {}, "vfat", "Test", "1 GB")
    finally:
        state.publish = _real_publish
    verdicts.append((label, published[-1]))
scanner.scan_tree = _saved_scan
check("malware wins over a scan error", verdicts[0][1][0] == state.THREAT, verdicts[0][1][0])
check("unreadable files: 'could not be checked'",
      verdicts[1][1][0] == state.BLOCKED
      and verdicts[1][1][1].get("reason", "").startswith("Some files on this drive could not"),
      verdicts[1][1][1].get("reason", ""))
_sh.rmtree(run_dir, ignore_errors=True)
_sh.rmtree(lk_dir, ignore_errors=True)

print("\n%d/%d checks passed" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
