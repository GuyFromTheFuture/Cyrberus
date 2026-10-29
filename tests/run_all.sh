#!/usr/bin/env bash
# Every suite that runs without hardware.
set -u
cd "$(dirname "$0")/.."
fail=0
for t in tests/test_manifest.py tests/test_head.py tests/test_ui.py; do
    echo "=============================================================="
    echo "  $t"
    echo "=============================================================="
    python3 "$t" || fail=1
    echo
done
if [ $fail -eq 0 ]; then echo "ALL SUITES PASSED"; else echo "SOME SUITES FAILED"; fi
exit $fail
