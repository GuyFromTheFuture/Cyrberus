"""Cyrberus Head - scanner daemon.

Watches for USB storage, admits or rejects it, scans it, and on a clean
result writes a signed manifest. Publishes its state for the kiosk UI.

Runs unprivileged as the `cyrberus` account. The only privileged operations
are mount and umount, granted narrowly through sudoers.

    python3 head/daemon.py                 run against real hardware
    python3 head/daemon.py --simulate      walk the states with no hardware
"""
import argparse
import logging
import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _d in ("common", "head"):
    sys.path.insert(0, os.path.join(_ROOT, _d))

import manifest_lib as M          # noqa: E402
import devices                     # noqa: E402
import mounts                      # noqa: E402
import scanner                     # noqa: E402
import state                       # noqa: E402

HEAD_ID = os.environ.get("CYRBERUS_HEAD_ID", "head-01")
KEY_DIR = os.environ.get("CYRBERUS_KEY_DIR", "/opt/cyrberus/keys")
PRIV_KEY = os.path.join(KEY_DIR, "head_private.pem")
PUB_KEY = os.path.join(KEY_DIR, "head_public.pem")
MOUNTPOINT = os.environ.get("CYRBERUS_MOUNT", "/mnt/cyrberus-scan")
VALIDITY_HOURS = int(os.environ.get("CYRBERUS_VALIDITY_HOURS", "12"))
LOG_PATH = os.environ.get("CYRBERUS_LOG", "/var/log/cyrberus/head.log")

log = logging.getLogger("cyrberus.head")


def setup_logging(verbose=False):
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(sh)
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        fh = logging.FileHandler(LOG_PATH)
        fh.setFormatter(fmt)
        log.addHandler(fh)
    except OSError as e:
        log.warning("file logging unavailable (%s); console only", e)


def reference_code():
    """Short code shown on the threat screen.

    The operator reads this to IT, who finds the full detection detail in the
    log. The malware family name would mean nothing to a front-office user.
    """
    return "H%d-%04d" % (random.randint(1, 9), random.randint(1000, 9999))


class Head:
    def __init__(self, simulate=False):
        self.simulate = simulate
        self.busy = False

    # -- state publishing -------------------------------------------------
    def ready(self):
        state.publish(state.READY, signatures_updated=self._sig_date())
        log.info("ready")

    def working(self, phase, **kw):
        state.publish(state.WORKING, phase=phase, **kw)

    def blocked(self, reason, **kw):
        state.publish(state.BLOCKED, reason=reason, **kw)
        log.warning("blocked: %s", reason)

    def threat(self, code, detections, **kw):
        state.publish(state.THREAT, reference=code,
                      detection_count=len(detections), **kw)
        for path, sig in detections:
            log.error("DETECTION ref=%s sig=%s path=%s", code, sig, path)

    def clean(self, manifest, **kw):
        state.publish(state.CLEAN,
                      expires_at=manifest["expires_at"],
                      file_count=len(manifest["files"]), **kw)
        log.info("validated: %d files, expires %s",
                 len(manifest["files"]), manifest["expires_at"])

    def _sig_date(self):
        info = scanner.engine_info()
        return info.get("signature_version", "")

    # -- the pipeline -----------------------------------------------------
    def handle(self, record):
        label = record.get("model") or record.get("node", "device")
        size = devices.human_size(record.get("size_bytes", 0))
        log.info("device attached: %s (%s) %s", label, size, record.get("node"))

        self.working("identifying", model=label, size=size)

        ok, reason = devices.admit(record)
        if not ok:
            self.blocked(reason, model=label)
            return

        part = record["partitions"][0]
        fstype = (part.get("fstype") or "").lower()

        try:
            mounts.mount_ro(part["node"], MOUNTPOINT, fstype)
        except mounts.MountError as e:
            log.error("mount failed: %s", e)
            self.blocked("This drive could not be opened for checking.", model=label)
            return

        try:
            self._inspect(record, part, fstype, label, size)
        finally:
            mounts.sync()
            try:
                mounts.unmount(MOUNTPOINT)
            except mounts.MountError as e:
                log.error("unmount failed: %s", e)

    def _inspect(self, record, part, fstype, label, size):
        self.working("scanning", model=label, size=size)
        t0 = time.time()
        result = scanner.scan_tree(MOUNTPOINT)
        scan_seconds = round(time.time() - t0, 1)
        log.info("scan finished in %ss: %r", scan_seconds, result)

        if result.engine_error:
            log.error("scanner unavailable: %s", result.engine_error)
            self.blocked("The checking service is not available right now.",
                         model=label)
            return

        if not result.clean:
            self.threat(reference_code(), result.detections, model=label)
            return

        if not result.usable:
            # Files the engine could not inspect are not evidence of safety.
            for path, msg in result.errors[:10]:
                log.warning("unscannable: %s (%s)", path, msg)
            self.blocked("Some files on this drive could not be checked.",
                         model=label)
            return

        # Clean. Hash everything for the manifest, reporting progress.
        total_hint = len(M.enumerate_files(MOUNTPOINT))
        self.working("hashing", model=label, size=size, done=0, total=total_hint)

        last = [0.0]

        def progress(done, total):
            now = time.time()
            if now - last[0] > 0.2 or done == total:
                last[0] = now
                self.working("hashing", model=label, size=size,
                             done=done, total=total)

        entries, problems = M.walk_payload(MOUNTPOINT, on_progress=progress)
        if problems:
            kind, where = problems[0]
            log.warning("undescribable entry (%s): %s", kind, where)
            self.blocked("This drive contains something we cannot record.",
                         model=label)
            return

        self.working("signing", model=label, size=size)
        manifest = self._sign(record, entries, scan_seconds, fstype, part["node"])
        if manifest is None:
            self.blocked("The approval could not be written to this drive.",
                         model=label)
            return
        self.clean(manifest, model=label)

    def _sign(self, record, entries, scan_seconds, fstype, part_node):
        from cryptography.hazmat.primitives import serialization

        try:
            with open(PRIV_KEY, "rb") as f:
                priv = serialization.load_pem_private_key(f.read(), password=None)
            with open(PUB_KEY, "rb") as f:
                kid = M.key_id(f.read())
        except OSError as e:
            log.error("cannot load signing key: %s", e)
            return None

        info = scanner.engine_info()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        manifest = M.build_manifest(
            HEAD_ID, kid, now, now + timedelta(hours=VALIDITY_HOURS),
            devices.device_block(record),
            {
                "engine": info["engine"],
                "engine_version": info["engine_version"],
                "signature_version": info["signature_version"],
                "files_scanned": len(entries),
                "bytes_scanned": sum(e["size"] for e in entries),
                "duration_seconds": scan_seconds,
            },
            entries)

        blob = M.serialize(manifest)
        sig = priv.sign(blob)
        outdir = os.path.join(MOUNTPOINT, M.MANIFEST_DIR)

        try:
            # Unmount the read-only scan mount, then mount fresh read-write
            # for exactly as long as the manifest write takes.
            mounts.unmount(MOUNTPOINT)
            mounts.mount_rw(part_node, MOUNTPOINT, fstype)
            os.makedirs(outdir, exist_ok=True)
            with open(os.path.join(outdir, M.MANIFEST_NAME), "wb") as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
            with open(os.path.join(outdir, M.SIG_NAME), "wb") as f:
                f.write(M.encode_sig(sig))
                f.flush()
                os.fsync(f.fileno())
            mounts.sync()
        except (OSError, mounts.MountError) as e:
            log.error("writing manifest failed: %s", e)
            return None
        finally:
            # Drop the writable mount immediately, whatever happened above.
            try:
                mounts.unmount(MOUNTPOINT)
            except mounts.MountError as e:
                log.error("could not release writable mount: %s", e)
        return manifest

    # -- loops ------------------------------------------------------------
    def run(self):
        log.info("Cyrberus Head starting (head_id=%s, validity=%dh)",
                 HEAD_ID, VALIDITY_HOURS)
        try:
            mounts.unmount(MOUNTPOINT)      # clear anything left by a crash
        except mounts.MountError:
            pass
        self.ready()

        for action, record in devices.monitor():
            if action == "add":
                if self.busy:
                    log.warning("device attached while busy; ignoring")
                    continue
                self.busy = True
                try:
                    self.handle(record)
                except Exception:
                    log.exception("unhandled error while processing device")
                    self.blocked("Something went wrong while checking this drive.")
                finally:
                    self.busy = False
            elif action == "remove":
                log.info("device removed: %s", record.get("node"))
                try:
                    mounts.unmount(MOUNTPOINT)
                except mounts.MountError:
                    pass
                self.ready()

    def run_simulation(self):
        """Walk every screen with no hardware. For UI work and demos."""
        log.info("simulation mode - no hardware will be touched")
        demo = [
            (state.READY, 3, {}),
            (state.WORKING, 2, {"phase": "identifying", "model": "SanDisk Ultra", "size": "32 GB"}),
            (state.WORKING, 4, {"phase": "scanning", "model": "SanDisk Ultra", "size": "32 GB"}),
            ("_hashing", 4, {}),
            (state.WORKING, 1.5, {"phase": "signing", "model": "SanDisk Ultra", "size": "32 GB"}),
            (state.CLEAN, 6, {"expires_at": (datetime.now(timezone.utc) + timedelta(hours=12))
                              .strftime("%Y-%m-%dT%H:%M:%SZ"), "file_count": 2061}),
            (state.READY, 3, {}),
            (state.WORKING, 3, {"phase": "scanning", "model": "Kingston DT", "size": "16 GB"}),
            (state.THREAT, 7, {"reference": reference_code(), "detection_count": 2}),
            (state.READY, 3, {}),
            (state.BLOCKED, 6, {"reason": devices.R_MULTI_PARTITION, "model": "Generic USB"}),
            (state.READY, 3, {}),
            (state.BLOCKED, 6, {"reason": devices.R_ENCRYPTED, "model": "IronKey"}),
        ]
        while True:
            for name, hold, kw in demo:
                if name == "_hashing":
                    total, steps = 2061, 28
                    for i in range(steps + 1):
                        state.publish(state.WORKING, phase="hashing",
                                      model="SanDisk Ultra", size="32 GB",
                                      done=int(total * i / steps), total=total)
                        time.sleep(hold / steps)
                    continue
                state.publish(name, **kw)
                log.info("simulate: %s %s", name, kw.get("phase", ""))
                time.sleep(hold)


def main():
    ap = argparse.ArgumentParser(description="Cyrberus Head scanner daemon")
    ap.add_argument("--simulate", action="store_true",
                    help="cycle through the operator screens with no hardware")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    setup_logging(args.verbose)
    head = Head(simulate=args.simulate)
    try:
        if args.simulate:
            head.run_simulation()
        else:
            head.run()
    except KeyboardInterrupt:
        log.info("stopping")
        try:
            mounts.unmount(MOUNTPOINT)
        except mounts.MountError:
            pass


if __name__ == "__main__":
    main()
