"""ClamAV integration.

Shells out to clamdscan so the resident daemon does the work - it already
holds the signature database in memory, which is why the Head can scan a
drive in seconds rather than reloading ~1 GB of signatures each time.

Output parsing is a pure function so it can be tested without ClamAV present.
"""
import os
import re
import subprocess

CLAMDSCAN = "/usr/bin/clamdscan"

# clamdscan exit codes
EXIT_CLEAN = 0
EXIT_FOUND = 1
EXIT_ERROR = 2

_FOUND = re.compile(r"^(?P<path>.+?):\s+(?P<sig>\S+)\s+FOUND\s*$")
_ERROR = re.compile(r"^(?P<path>.+?):\s+(?P<msg>.+?)\s+ERROR\s*$")


class ScanResult:
    def __init__(self, clean, detections=None, errors=None, raw="", engine_error=None):
        self.clean = clean
        self.detections = detections or []     # [(path, signature)]
        self.errors = errors or []             # [(path, message)]
        self.raw = raw
        self.engine_error = engine_error       # scanner itself failed

    @property
    def usable(self):
        """A scan is usable only if nothing was skipped or unreadable.

        Fail-closed: a file the engine could not inspect is not evidence of
        safety. This is the policy behind AlertExceedsMax in clamd.conf.
        """
        return self.engine_error is None and not self.errors

    def __repr__(self):
        return "<ScanResult clean=%s detections=%d errors=%d>" % (
            self.clean, len(self.detections), len(self.errors))


def parse_output(stdout, returncode):
    """Turn clamdscan output into a ScanResult. Pure - safe to unit test."""
    detections, errors = [], []
    for line in (stdout or "").splitlines():
        line = line.rstrip()
        if not line or line.startswith("-") or ":" not in line:
            continue
        if line.startswith(("Infected files", "Scanned files", "Known viruses",
                            "Engine version", "Scanned directories", "Data scanned",
                            "Data read", "Time", "Start Date", "End Date")):
            continue
        m = _FOUND.match(line)
        if m:
            detections.append((m.group("path"), m.group("sig")))
            continue
        m = _ERROR.match(line)
        if m:
            errors.append((m.group("path"), m.group("msg")))

    if returncode == EXIT_CLEAN:
        return ScanResult(True, detections, errors, stdout)
    if returncode == EXIT_FOUND:
        return ScanResult(False, detections, errors, stdout)
    return ScanResult(False, detections, errors, stdout,
                      engine_error="clamdscan exited with status %d" % returncode)


def scan_tree(path, clamdscan=None, timeout=1800):
    """Scan a mounted filesystem. Returns ScanResult."""
    clamdscan = clamdscan or CLAMDSCAN
    if not os.path.exists(clamdscan):
        return ScanResult(False, engine_error="clamdscan not found at %s" % clamdscan)

    cmd = [clamdscan, "--fdpass", "--multiscan", "--infected", "--no-summary", path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ScanResult(False, engine_error="scan exceeded %d seconds" % timeout)
    except OSError as e:
        return ScanResult(False, engine_error="could not run clamdscan: %s" % e)

    # --no-summary means clean scans print nothing at all.
    return parse_output(proc.stdout, proc.returncode)


def engine_info(clamdscan=None):
    """Engine and signature versions, recorded in the manifest's scan block."""
    clamdscan = clamdscan or CLAMDSCAN
    info = {"engine": "ClamAV", "engine_version": "", "signature_version": ""}
    try:
        proc = subprocess.run([clamdscan, "--version"], capture_output=True,
                              text=True, timeout=15)
        # e.g. "ClamAV 1.0.7/27234/Tue Oct 28 08:12:03 2026"
        parts = (proc.stdout or "").strip().split("/")
        if parts:
            info["engine_version"] = parts[0].replace("ClamAV", "").strip()
        if len(parts) > 1:
            info["signature_version"] = parts[1].strip()
    except Exception:
        pass
    return info
