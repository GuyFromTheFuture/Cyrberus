"""Golden test vectors for building and testing the Sentinel.

    python3 tests/make_sentinel_fixtures.py [OUTDIR] [--hours N]

Writes OUTDIR (default ./sentinel-fixtures) containing:

    drives/<case>/...           one folder per case, laid out exactly as a
                                validated USB drive's root would be
    trusted/fixture_head_public.pem
                                the ONLY key the cases are signed with (a
                                throwaway fixture key - never a real Head's)
    expected.json               {"<case>": {"verdict": "PASS" | "DENY",
                                            "why": "<spec step / reason>"}, ...}
    README.txt                  how to use them on Windows

OUTDIR is replaced on each run, but only if it is empty or was made by this
script (it carries a .cyrberus-fixtures marker) - it never deletes anything
else.

Then it runs the reference verifier (sentinel/verify_manifest.py) over every
case and refuses to finish unless each verdict matches expected.json. A
Sentinel implementation is conformant with schema 1 when it reaches the same
verdict on every case.

Copy the folder to the Windows machine (zip it, or put it on a drive) and
point the Sentinel's verifier at each drives/<case> folder, trusting only
trusted/fixture_head_public.pem.

--hours sets the validity of the "valid" cases (default 8760 = one year, so
the fixtures stay usable for the rest of the project). Real Heads issue 12 h.
If the Sentinel enforces a maximum validity (open decision D6 in
docs/HANDOFF.md), regenerate with --hours 12 just before testing.
"""
import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timedelta, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _d in ("common", "sentinel"):
    sys.path.insert(0, os.path.join(_ROOT, _d))

import manifest_lib as M                               # noqa: E402
from verify_manifest import verify_device              # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519   # noqa: E402
from cryptography.hazmat.primitives import serialization       # noqa: E402

DEVICE = {"vendor_id": "0781", "product_id": "5581", "serial": "FIXTURE0001",
          "model": "Fixture Drive", "size_bytes": 32015679488,
          "filesystem": "vfat", "partition_count": 1}
SCAN = {"engine": "ClamAV", "engine_version": "1.0.7", "signature_version": "27234",
        "files_scanned": 0, "bytes_scanned": 0, "duration_seconds": 0.1}


def pem_pair():
    k = ed25519.Ed25519PrivateKey.generate()
    pub = k.public_key().public_bytes(serialization.Encoding.PEM,
                                      serialization.PublicFormat.SubjectPublicKeyInfo)
    return k, pub


def write_files(root, files):
    for rel, data in files.items():
        p = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)


def sign_into(root, key, pub, issued, expires, schema=M.SCHEMA, edit=None, rename=None):
    """Sign whatever is in root now, exactly as the Head does."""
    entries, problems = M.walk_payload(root)
    assert not problems, problems
    if rename:                    # record paths differently from how they sit on disk
        for e in entries:
            e["path"] = rename(e["path"])
        entries.sort(key=lambda e: e["path"])
    scan = dict(SCAN, files_scanned=len(entries), bytes_scanned=sum(e["size"] for e in entries))
    manifest = M.build_manifest("head-fixture", M.key_id(pub), issued, expires,
                                DEVICE, scan, entries)
    manifest["schema"] = schema
    blob = M.serialize(manifest)
    sig = key.sign(blob)
    if edit:                      # change the bytes AFTER signing
        blob = edit(blob)
    out = os.path.join(root, M.MANIFEST_DIR)
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, M.MANIFEST_NAME), "wb") as f:
        f.write(blob)
    with open(os.path.join(out, M.SIG_NAME), "wb") as f:
        f.write(M.encode_sig(sig))


BASE = {
    "readme.txt": b"Quarterly figures attached.\r\n",
    "Documents/budget.xlsx": bytes(range(256)) * 16,
    "Documents/2026/notes.md": b"# notes\n",
}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("outdir", nargs="?", default="sentinel-fixtures")
    ap.add_argument("--hours", type=float, default=8760.0)
    args = ap.parse_args()

    out = os.path.abspath(args.outdir)
    marker = os.path.join(out, ".cyrberus-fixtures")
    if os.path.exists(out):
        if not os.path.isdir(out):
            sys.exit("refusing: %s exists and is not a directory" % out)
        if os.listdir(out) and not os.path.exists(marker):
            sys.exit("refusing to replace %s: it is not empty and was not made by this "
                     "script. Choose a new folder name." % out)
        shutil.rmtree(out)
    drives = os.path.join(out, "drives")
    os.makedirs(os.path.join(out, "trusted"))
    open(marker, "w").close()

    key, pub = pem_pair()
    rogue, rogue_pub = pem_pair()
    with open(os.path.join(out, "trusted", "fixture_head_public.pem"), "wb") as f:
        f.write(pub)

    now = datetime.now(timezone.utc).replace(microsecond=0)
    good = (now - timedelta(minutes=5), now + timedelta(hours=args.hours))
    expected = {}

    def case(name, verdict, why, files=BASE, signer=(key, pub), times=good,
             after=None, **kw):
        root = os.path.join(drives, name)
        os.makedirs(root)
        write_files(root, files)
        sign_into(root, signer[0], signer[1], times[0], times[1], **kw)
        if after:
            after(root)
        expected[name] = {"verdict": verdict, "why": why}

    case("valid", "PASS", "untouched since signing")
    case("valid_empty_drive", "PASS", "an empty drive is valid: files: []", files={})
    case("valid_unicode_names", "PASS", "UTF-8 paths, case preserved",
         files={"Informe_Año.txt": "ñ é 日本語\n".encode(), "MixedCase/ReadMe.TXT": b"x"})
    # MANIFEST_FORMAT section 8: FAT/exFAT/NTFS are case-insensitive, so a
    # Sentinel compares paths case-insensitively. Manifest says "docs/readme.txt",
    # the drive holds "Docs/ReadMe.TXT" - same file on these filesystems.
    case("valid_path_case_differs", "PASS",
         "MANIFEST_FORMAT s8: paths compare case-insensitively",
         files={"Docs/ReadMe.TXT": b"case test\r\n", "Docs/Budget.xlsx": b"\x00" * 64},
         rename=lambda p: p.lower())
    # ...but folding is SIMPLE per-character uppercase, as on NTFS and .NET
    # OrdinalIgnoreCase: "Straße" is not "STRASSE". A port using full Unicode
    # case folding (Python str.casefold) would wrongly pass this one.
    case("deny_case_fold_is_simple", "DENY",
         "steps 9-10: 'ß' does not fold to 'SS' (simple uppercase, like NTFS)",
         files={"Straße.txt": b"x\r\n"},
         rename=lambda p: p.replace("Straße", "STRASSE"))
    case("deny_file_added", "DENY", "spec step 9: file on disk not in manifest",
         after=lambda r: write_files(r, {"Documents/invoice.exe": b"MZ\x90\x00"}))
    case("deny_file_modified", "DENY", "spec step 11: hash mismatch",
         after=lambda r: write_files(r, {"readme.txt": b"Quarterly figures attached!\r\n"}))
    case("deny_file_deleted", "DENY", "spec step 10: manifest entry missing on disk",
         after=lambda r: os.remove(os.path.join(r, "Documents", "2026", "notes.md")))
    case("deny_expired", "DENY", "spec step 7: expires_at in the past",
         times=(now - timedelta(hours=13), now - timedelta(hours=1)))
    case("deny_unknown_head", "DENY", "spec step 3: key_id not in the trust store",
         signer=(rogue, rogue_pub))
    case("deny_manifest_edited", "DENY", "spec step 4: bytes changed after signing",
         edit=lambda b: b.replace(b'"head-fixture"', b'"head-fixturX"'))
    case("deny_wrong_schema", "DENY", "spec step 6: schema 2 is not implemented", schema=2)

    # Proposal section 7, objective O3: a valid manifest copied onto a
    # different drive must not make that drive trusted.
    def clone_onto_other_drive(r):
        for name in os.listdir(r):
            if name != M.MANIFEST_DIR:
                p = os.path.join(r, name)
                shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
        write_files(r, {"payroll_update.exe": b"MZ\x90\x00", "readme.txt": b"hi\r\n"})
    case("deny_manifest_copied_to_other_drive", "DENY",
         "proposal O3: manifest binds to content - step 9 (payroll_update.exe not listed)",
         after=clone_onto_other_drive)

    def no_manifest(r):
        shutil.rmtree(os.path.join(r, M.MANIFEST_DIR))
    case("deny_no_manifest", "DENY", "spec step 1: nothing to verify", after=no_manifest)

    def corrupt_sig(r):
        with open(os.path.join(r, M.MANIFEST_DIR, M.SIG_NAME), "wb") as f:
            f.write(b"not base64 at all!!\n")
    case("deny_corrupt_signature", "DENY", "spec step 2: signature file malformed",
         after=corrupt_sig)

    # What Windows itself writes to a drive it mounts read-write. Under schema
    # 1 this is an added file and MUST deny - which is why the workstation
    # must not let Windows write to the drive before the Sentinel verifies it.
    # See open decision D4 in docs/HANDOFF.md.
    case("deny_windows_wrote_system_volume_information", "DENY",
         "spec step 9: Windows added System Volume Information files (see HANDOFF D4)",
         after=lambda r: write_files(r, {
             "System Volume Information/WPSettings.dat": b"\x0c\x00\x00\x00" * 3,
             "System Volume Information/IndexerVolumeGuid": "{2F5C4D1E-0000-0000-0000-000000000000}".encode("utf-16-le")}))

    with open(os.path.join(out, "expected.json"), "w") as f:
        json.dump(expected, f, indent=2, sort_keys=True)

    with open(os.path.join(out, "README.txt"), "w", newline="\r\n") as f:
        f.write(
            "Cyrberus Sentinel fixtures - schema 1\n"
            "======================================\n\n"
            "Each folder in drives\\ is laid out like the root of a validated USB drive.\n"
            "Trust ONLY trusted\\fixture_head_public.pem (a throwaway fixture key).\n"
            "expected.json gives the verdict a conformant Sentinel must reach.\n\n"
            "Reference check on Windows (from the repository root):\n"
            "  py sentinel\\verify_manifest.py <path>\\drives\\valid <path>\\trusted\\fixture_head_public.pem\n"
            "  -> PASS: valid until ...\n\n"
            "A REAL TEST DRIVE without the Pi: format a USB stick FAT32 (one partition),\n"
            "copy EVERYTHING inside drives\\valid\\ (including the .cyrberus folder) to the\n"
            "stick's root, eject. It now carries a valid manifest from the fixture key.\n"
            "If Windows later writes System Volume Information files to it, verification\n"
            "fails - that is HANDOFF decision D4 / spike T3, working as designed.\n\n"
            "Copy the .pem in binary (never open and re-save it in an editor): key_id is\n"
            "the SHA-256 of its exact bytes.\n\n"
            "Valid cases expire %s UTC. Regenerate on any machine with Python and\n"
            "the 'cryptography' package:  python tests/make_sentinel_fixtures.py <new folder>\n"
            % good[1].strftime("%Y-%m-%d %H:%M"))

    # Self-check with the reference verifier.
    trusted = {M.key_id(pub): pub}
    bad = 0
    print("%-48s %-6s %s" % ("case", "want", "reference verifier"))
    for name in sorted(expected):
        ok, why = verify_device(os.path.join(drives, name), trusted)
        got = "PASS" if ok else "DENY"
        mark = "ok" if got == expected[name]["verdict"] else "XX"
        bad += mark == "XX"
        print("[%s] %-44s %-6s %s: %s" % (mark, name, expected[name]["verdict"], got, why))
    print("\n%d cases written to %s" % (len(expected), out))
    if bad:
        sys.exit("%d case(s) disagree with the reference verifier" % bad)


if __name__ == "__main__":
    main()
