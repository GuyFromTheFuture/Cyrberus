#!/usr/bin/env bash
# Run every test suite.
#
#   bash tests/run_all.sh          the three suites that need no hardware, plus a
#                                  self-check of the Sentinel golden vectors
#   sudo bash tests/run_all.sh     ...plus the root integration test, which
#                                  makes real (loopback) mounts - on the Pi it
#                                  proves the hardening on a genuine FAT32 image
#
# Every suite exits non-zero on any failure, so this script's exit status is
# trustworthy in automation.
set -u
cd "$(dirname "$0")/.." || exit 1
# Under sudo, compiled .pyc files would be written as root into your checkout.
export PYTHONDONTWRITEBYTECODE=1

# Prefer the project venv (has cryptography and pyudev), fall back to python3.
PY=python3
[ -x /opt/cyrberus/venv/bin/python3 ] && PY=/opt/cyrberus/venv/bin/python3

fail=0
suites=(tests/test_manifest.py tests/test_head.py tests/test_ui.py)
[ "$(id -u)" = 0 ] && suites+=(tests/test_root_integration.py)

for t in "${suites[@]}"; do
    echo "=============================================================="
    echo "  $t"
    echo "=============================================================="
    "$PY" "$t" || fail=1
    echo
done

echo "=============================================================="
echo "  tests/make_sentinel_fixtures.py (self-check, temporary folder)"
echo "=============================================================="
fx="$(mktemp -d)/fixtures"
# Capture first: piping straight into tail would report tail's exit status
# and hide a fixture that disagrees with the reference verifier.
if fx_out="$("$PY" tests/make_sentinel_fixtures.py "$fx" 2>&1)"; then
    printf '%s\n' "$fx_out" | tail -1
else
    printf '%s\n' "$fx_out" | grep -E '^\[XX\]|disagree|Error' ; fail=1
fi
rm -rf "$(dirname "$fx")"
echo

if [ "$(id -u)" != 0 ]; then
    echo "(skipped tests/test_root_integration.py - run with sudo to include real mounts)"
fi
if [ $fail -eq 0 ]; then echo "ALL SUITES PASSED"; else echo "SOME SUITES FAILED"; fi
exit $fail
