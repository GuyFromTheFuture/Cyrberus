#!/usr/bin/env bash
# Cyrberus Head - live-mode preflight.
#
#   bash deploy/preflight.sh          check only, change nothing
#   sudo bash deploy/preflight.sh --fix   create and chown what is missing
#
# Safe to run repeatedly. --fix only creates directories and sets ownership;
# it never formats anything, never touches a USB device, and never writes keys.

set -uo pipefail

FIX=0
[ "${1:-}" = "--fix" ] && FIX=1

SVC_USER="${CYRBERUS_USER:-cyrberus}"
APP_DIR="${CYRBERUS_APP:-/opt/cyrberus}"
KEY_DIR="$APP_DIR/keys"
MOUNTPOINT="${CYRBERUS_MOUNT:-/mnt/cyrberus-scan}"
RUN_DIR="/run/cyrberus"
LOG_DIR="/var/log/cyrberus"
VENV_PY="$APP_DIR/venv/bin/python3"

pass=0; fail=0; fixed=0
ok()   { printf '  \033[32m[ok]\033[0m   %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31m[XX]\033[0m   %s\n' "$1"; fail=$((fail+1)); }
note() { printf '         %s\n' "$1"; }
did()  { printf '  \033[33m[fix]\033[0m  %s\n' "$1"; fixed=$((fixed+1)); }

need_root_to_fix() {
    if [ "$FIX" = 1 ] && [ "$(id -u)" != 0 ]; then
        echo "--fix needs root. Re-run with: sudo bash deploy/preflight.sh --fix"
        exit 2
    fi
}
need_root_to_fix

echo
echo "Cyrberus Head preflight"
echo "======================="
echo

# ---------------------------------------------------------------- account
echo "Service account"
if id "$SVC_USER" >/dev/null 2>&1; then
    ok "user '$SVC_USER' exists (uid $(id -u "$SVC_USER"))"
else
    bad "user '$SVC_USER' does not exist"
    note "sudo useradd -r -s /usr/sbin/nologin -d $APP_DIR $SVC_USER"
fi

# ------------------------------------------------------------------- keys
echo
echo "Signing keys"
# The key directory is mode 700 owned by the service account, so an ordinary
# login cannot stat anything inside it. Probe as root when we can, and say
# "cannot check" rather than "missing" when we cannot.
if [ "$(id -u)" = 0 ]; then
    key_probe() { test -f "$1"; }
    key_stat()  { stat -c "$2" "$1" 2>/dev/null; }
    can_probe=1
elif sudo -n true 2>/dev/null; then
    key_probe() { sudo -n test -f "$1"; }
    key_stat()  { sudo -n stat -c "$2" "$1" 2>/dev/null; }
    can_probe=1
else
    can_probe=0
fi

if [ "$can_probe" = 0 ]; then
    note "[--]   cannot read $KEY_DIR as $(id -un) - it is mode 700 owned by $SVC_USER."
    note "       Re-run with sudo to check the keys."
elif key_probe "$KEY_DIR/head_private.pem"; then
    mode=$(key_stat "$KEY_DIR/head_private.pem" '%a')
    owner=$(key_stat "$KEY_DIR/head_private.pem" '%U')
    [ "$mode" = "600" ] && ok "private key is mode 600" \
                        || bad "private key is mode $mode, expected 600"
    [ "$owner" = "$SVC_USER" ] && ok "private key owned by $SVC_USER" \
                               || bad "private key owned by $owner, expected $SVC_USER"
    key_probe "$KEY_DIR/head_public.pem" && ok "public key present" \
                                         || bad "no public key at $KEY_DIR/head_public.pem"
else
    bad "no private key at $KEY_DIR/head_private.pem"
    note "sudo -u $SVC_USER $VENV_PY $APP_DIR/head/keygen.py"
fi

# ------------------------------------------------------------ directories
echo
echo "Directories"
check_dir() {
    local path="$1" mode="$2" label="$3"
    if [ ! -d "$path" ]; then
        if [ "$FIX" = 1 ]; then
            mkdir -p "$path" && chown "$SVC_USER:$SVC_USER" "$path" \
                && chmod "$mode" "$path" && did "created $path ($mode, $SVC_USER)"
        else
            bad "$label missing: $path"
            note "sudo mkdir -p $path && sudo chown $SVC_USER:$SVC_USER $path && sudo chmod $mode $path"
        fi
        return
    fi
    local owner; owner=$(stat -c '%U' "$path")
    # Files left inside by an earlier run under a different account block
    # writes even when the directory itself is correct - the log file in
    # particular. Check the contents, not just the directory.
    local strays
    strays=$(find "$path" -mindepth 1 -maxdepth 1 ! -user "$SVC_USER" 2>/dev/null | head -5)
    if [ -n "$strays" ]; then
        if [ "$FIX" = 1 ]; then
            chown -R "$SVC_USER:$SVC_USER" "$path" \
                && did "re-owned contents of $path to $SVC_USER"
        else
            bad "$label $path contains files not owned by $SVC_USER"
            note "sudo chown -R $SVC_USER:$SVC_USER $path"
        fi
    fi
    if [ "$owner" != "$SVC_USER" ]; then
        if [ "$FIX" = 1 ]; then
            chown "$SVC_USER:$SVC_USER" "$path" && chmod "$mode" "$path" \
                && did "re-owned $path to $SVC_USER"
        else
            bad "$label $path owned by $owner, expected $SVC_USER"
            note "sudo chown $SVC_USER:$SVC_USER $path"
        fi
    else
        ok "$label $path ($(stat -c '%a' "$path"), $owner)"
    fi
}
check_dir "$MOUNTPOINT" 0755 "scan mountpoint"
check_dir "$RUN_DIR"    0755 "runtime dir"
check_dir "$LOG_DIR"    0755 "log dir"

if [ -d "$RUN_DIR" ] && [ "$(stat -c '%a' "$RUN_DIR")" != "0755" ] \
   && [ "$(stat -c '%a' "$RUN_DIR")" != "755" ]; then
    note "note: $RUN_DIR is not world-readable; the UI runs as a different"
    note "      user and must be able to read the state file."
fi

# ---------------------------------------------------------------- sudoers
echo
echo "Mount privileges"
if sudo -u "$SVC_USER" sudo -n /usr/bin/mount --version >/dev/null 2>&1; then
    ok "$SVC_USER may run mount without a password"
else
    bad "$SVC_USER cannot run mount via sudo"
    note "sudo EDITOR=nano visudo -f /etc/sudoers.d/cyrberus"
    note "then add:  $SVC_USER ALL=(root) NOPASSWD: /usr/bin/mount, /usr/bin/umount"
fi

# ----------------------------------------------------------------- clamav
echo
echo "Scanner"
if systemctl is-active --quiet clamav-daemon 2>/dev/null; then
    ok "clamav-daemon is running"
else
    bad "clamav-daemon is not running"
    note "sudo systemctl start clamav-daemon"
fi
if command -v clamdscan >/dev/null 2>&1; then
    ok "clamdscan found at $(command -v clamdscan)"
    # Capture first: clamconf can exit non-zero over unrelated config, and
    # with `set -o pipefail` that would sink the whole pipeline.
    clam_cfg=$(clamconf 2>/dev/null || true)
    if [ -z "$clam_cfg" ]; then
        clam_cfg=$(grep -h . /etc/clamav/clamd.conf 2>/dev/null || true)
    fi
    if printf '%s\n' "$clam_cfg" | grep -qiE '^[[:space:]]*AlertExceedsMax[[:space:]="]*yes'; then
        ok "AlertExceedsMax is on (oversized files are flagged, not skipped)"
    else
        bad "AlertExceedsMax is NOT enabled - large files would pass unchecked"
        note "check with:  sudo clamconf | grep AlertExceedsMax"
        note "settings are in deploy/clamd.conf.d/cyrberus.conf"
    fi
else
    bad "clamdscan not installed"
fi

# ------------------------------------------------------------ automounting
echo
echo "Automounting"
if systemctl is-active --quiet udisks2 2>/dev/null; then
    bad "udisks2 is running - it will mount drives before the Head sees them"
    note "sudo systemctl disable --now udisks2   (or apt purge udisks2)"
else
    ok "no udisks2 automounter running"
fi

# ------------------------------------------------------------ python deps
echo
echo "Python"
if [ -x "$VENV_PY" ]; then
    ok "venv interpreter at $VENV_PY"
    if sudo -u "$SVC_USER" "$VENV_PY" -c 'import pyudev, cryptography' 2>/dev/null; then
        ok "$SVC_USER can import pyudev and cryptography"
    else
        bad "$SVC_USER cannot import pyudev/cryptography from the venv"
        note "$VENV_PY -m pip install -r $APP_DIR/head/requirements.txt"
    fi
else
    bad "no venv interpreter at $VENV_PY"
fi
if python3 -c 'import tkinter' 2>/dev/null; then
    ok "tkinter available for the UI"
else
    bad "tkinter missing - the kiosk UI will not start"
    note "sudo apt install -y python3-tk"
fi

# ----------------------------------------------------------- attached media
echo
echo "Attached removable media"
found=0
while read -r disk tran size model; do
    [ "$tran" = "usb" ] || continue
    found=1
    parts=$(lsblk -nr -o NAME,TYPE "/dev/$disk" 2>/dev/null | awk '$2=="part"' | wc -l)
    fstypes=$(lsblk -nr -o FSTYPE,TYPE "/dev/$disk" 2>/dev/null | awk '$2=="part"{print $1}' | tr '\n' ' ')
    [ "$parts" = "0" ] && fstypes=$(lsblk -nro FSTYPE "/dev/$disk" 2>/dev/null | head -1)
    verdict="would be ADMITTED"
    if [ "$parts" -gt 1 ]; then
        verdict="would be REJECTED - $parts partitions"
    elif ! printf '%s' "$fstypes" | grep -qiE 'vfat|exfat|ntfs'; then
        verdict="would be REJECTED - filesystem '$(echo $fstypes)' not supported"
    fi
    printf '  /dev/%-6s %-8s %-18s %s\n' "$disk" "$size" "${model:-unknown}" "$verdict"
done < <(lsblk -dn -o NAME,TRAN,SIZE,MODEL 2>/dev/null)
[ "$found" = 0 ] && note "no USB disks attached right now"

# ------------------------------------------------------------------ verdict
echo
echo "======================="
if [ "$fixed" -gt 0 ]; then
    echo "$fixed item(s) fixed. Re-run without --fix to confirm."
fi
if [ "$fail" -eq 0 ]; then
    echo "READY  -  $pass checks passed."
    echo
    echo "Start the daemon:"
    echo "  sudo -u $SVC_USER $VENV_PY $APP_DIR/head/daemon.py -v"
    exit 0
else
    echo "NOT READY  -  $fail problem(s), $pass ok."
    [ "$FIX" = 0 ] && echo "Many of these are fixed by: sudo bash deploy/preflight.sh --fix"
    exit 1
fi
