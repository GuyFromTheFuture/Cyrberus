#!/usr/bin/env bash
# Cyrberus Head - preflight check.
#
#   bash deploy/preflight.sh              check only, change nothing
#   sudo bash deploy/preflight.sh         same, but can also inspect the keys
#   sudo bash deploy/preflight.sh --fix   create and re-own missing directories
#
# Safe to run any time, as often as you like. --fix only creates directories
# and sets ownership; it never formats anything, never touches a USB device,
# and never writes keys. deploy/install-head.sh does the full setup.
#
# [ok] fine   [XX] will break the Head - fix before a demo   [!!] worth knowing
set -uo pipefail

FIX=0
[ "${1:-}" = "--fix" ] && FIX=1

SVC_USER="${CYRBERUS_USER:-cyrberus}"
KIOSK_USER="${CYRBERUS_KIOSK_USER:-kiosk}"
APP_DIR="${CYRBERUS_APP:-/opt/cyrberus}"
KEY_DIR="$APP_DIR/keys"
MOUNTPOINT="${CYRBERUS_MOUNT:-/mnt/cyrberus-scan}"
RUN_DIR="/run/cyrberus"
LOG_DIR="/var/log/cyrberus"
VENV_PY="$APP_DIR/venv/bin/python3"
SERVICE=cyrberus-scanner

pass=0; fail=0; warns=0; fixed=0
ok()   { printf '  \033[32m[ok]\033[0m   %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31m[XX]\033[0m   %s\n' "$1"; fail=$((fail+1)); }
warn() { printf '  \033[33m[!!]\033[0m   %s\n' "$1"; warns=$((warns+1)); }
note() { printf '         %s\n' "$1"; }
did()  { printf '  \033[36m[fix]\033[0m  %s\n' "$1"; fixed=$((fixed+1)); }

IS_ROOT=0; [ "$(id -u)" = 0 ] && IS_ROOT=1
if [ "$FIX" = 1 ] && [ "$IS_ROOT" = 0 ]; then
    echo "--fix needs root. Re-run with: sudo bash deploy/preflight.sh --fix"
    exit 2
fi
# Run a command as another account (only possible as root).
as_user() { local u="$1"; shift; sudo -n -u "$u" "$@"; }

echo
echo "Cyrberus Head preflight"
echo "======================="
echo

# ---------------------------------------------------------------- accounts
echo "Accounts"
if id "$SVC_USER" >/dev/null 2>&1; then
    ok "service account '$SVC_USER' exists (uid $(id -u "$SVC_USER"))"
else
    bad "service account '$SVC_USER' does not exist"
    note "sudo bash $APP_DIR/deploy/install-head.sh"
fi
KIOSK_EXISTS=0
if id "$KIOSK_USER" >/dev/null 2>&1; then
    KIOSK_EXISTS=1
    ok "screen account '$KIOSK_USER' exists"
    if id -nG "$KIOSK_USER" | tr ' ' '\n' | grep -qx sudo; then
        bad "'$KIOSK_USER' is in the sudo group - the screen account must have no admin rights"
        note "sudo deluser $KIOSK_USER sudo"
    fi
else
    note "no '$KIOSK_USER' account (fine for hand-run demos; needed for boot mode)"
fi
ME="${SUDO_USER:-$(id -un)}"
if [ "$ME" != root ] && [ "$ME" != "$SVC_USER" ]; then
    if id -nG "$ME" 2>/dev/null | tr ' ' '\n' | grep -qx "$SVC_USER"; then
        ok "you ($ME) are in group $SVC_USER (can read the logs without sudo)"
    else
        note "you ($ME) are not in group $SVC_USER - read logs with sudo, or: sudo usermod -aG $SVC_USER $ME"
    fi
fi

# ------------------------------------------------------------------- keys
echo
echo "Signing keys"
# The key directory is mode 700 owned by the service account, so an ordinary
# login cannot stat anything inside it. Probe as root when we can, and say
# "cannot check" rather than "missing" when we cannot.
if [ "$IS_ROOT" = 1 ]; then
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
    dmode=$(key_stat "$KEY_DIR" '%a')
    [ "$dmode" = "700" ] && ok "key directory is mode 700" \
                         || bad "key directory is mode $dmode, expected 700"
    if key_probe "$KEY_DIR/head_public.pem"; then
        if [ -r /var/lib/cyrberus/key_id.txt ]; then
            ok "public key present (key_id $(cat /var/lib/cyrberus/key_id.txt))"
        else
            ok "public key present"
        fi
    else
        bad "no public key at $KEY_DIR/head_public.pem"
    fi
else
    bad "no private key at $KEY_DIR/head_private.pem"
    note "sudo bash $APP_DIR/deploy/install-head.sh   (generates one; never overwrites)"
fi

# ------------------------------------------------------------ directories
echo
echo "Directories"
check_dir() {
    local path="$1" mode="$2" label="$3"
    if [ ! -d "$path" ]; then
        if [ "$FIX" = 1 ]; then
            install -d -m "$mode" -o "$SVC_USER" -g "$SVC_USER" "$path" \
                && did "created $path ($mode, $SVC_USER)"
        else
            bad "$label missing: $path"
            note "sudo bash deploy/preflight.sh --fix"
        fi
        return
    fi
    local owner cur
    owner=$(stat -c '%U' "$path")
    cur=$(stat -c '%a' "$path")
    # Files left inside by an earlier run under a different account block
    # writes even when the directory itself is correct - the log file in
    # particular. Check the contents, not just the directory.
    local strays
    strays=$(find "$path" -mindepth 1 -maxdepth 1 ! -user "$SVC_USER" 2>/dev/null | head -5)
    if [ -n "$strays" ]; then
        if [ "$FIX" = 1 ]; then
            chown -R "$SVC_USER:$SVC_USER" "$path" && did "re-owned contents of $path to $SVC_USER"
        else
            bad "$label $path contains files not owned by $SVC_USER"
            note "sudo chown -R $SVC_USER:$SVC_USER $path"
        fi
    fi
    if [ "$owner" != "$SVC_USER" ]; then
        if [ "$FIX" = 1 ]; then
            chown "$SVC_USER:$SVC_USER" "$path" && chmod "$mode" "$path" \
                && did "re-owned $path to $SVC_USER ($mode)"
        else
            bad "$label $path owned by $owner, expected $SVC_USER"
            note "sudo bash deploy/preflight.sh --fix"
        fi
    elif [ "$cur" != "${mode#0}" ] && ! mountpoint -q "$path" 2>/dev/null; then
        if [ "$FIX" = 1 ]; then
            chmod "$mode" "$path" && did "set $path to $mode"
        else
            warn "$label $path is mode $cur, expected ${mode#0}"
            note "sudo bash deploy/preflight.sh --fix"
        fi
    else
        ok "$label $path ($cur, $owner)"
    fi
}
check_dir "$MOUNTPOINT" 0750 "scan mountpoint"
check_dir "$RUN_DIR"    0755 "runtime dir"
check_dir "$LOG_DIR"    0750 "log dir"
if [ -f /etc/tmpfiles.d/cyrberus.conf ]; then
    ok "tmpfiles rule installed (recreates $RUN_DIR at every boot)"
else
    bad "no /etc/tmpfiles.d/cyrberus.conf - $RUN_DIR vanishes at every reboot"
    note "sudo bash $APP_DIR/deploy/install-head.sh"
fi
if [ "$KIOSK_EXISTS" = 1 ] && [ "$IS_ROOT" = 1 ] && [ -d "$RUN_DIR" ]; then
    if as_user "$KIOSK_USER" test -r "$RUN_DIR" -a -x "$RUN_DIR" 2>/dev/null; then
        ok "screen account can open $RUN_DIR"
    else
        bad "screen account cannot open $RUN_DIR - the screen will say 'unavailable'"
    fi
fi
if mountpoint -q "$MOUNTPOINT" 2>/dev/null; then
    warn "something is mounted on $MOUNTPOINT right now (left over from a crash?)"
    note "sudo umount $MOUNTPOINT"
fi

# ---------------------------------------------------------------- sudoers
echo
echo "Mount privileges"
if [ "$IS_ROOT" = 1 ] || sudo -n true 2>/dev/null; then
    if sudo -n -u "$SVC_USER" sudo -n /usr/bin/mount --version >/dev/null 2>&1; then
        ok "$SVC_USER may run mount without a password"
    else
        bad "$SVC_USER cannot run mount via sudo"
        note "sudo bash $APP_DIR/deploy/install-head.sh   (installs /etc/sudoers.d/cyrberus)"
    fi
else
    note "[--]   re-run with sudo to check $SVC_USER's mount rule"
fi

# ----------------------------------------------------------------- clamav
echo
echo "Scanner"
if systemctl is-active --quiet clamav-daemon 2>/dev/null; then
    ok "clamav-daemon is running"
    v="$(timeout 10 clamdscan --version 2>/dev/null | cut -s -d/ -f2)"
    if [ -n "$v" ]; then ok "virus list loaded (version $v)"
    else warn "clamd is up but not answering yet - it loads signatures for ~1 minute after boot"; fi
else
    bad "clamav-daemon is not running - every drive will be refused"
    note "sudo systemctl start clamav-daemon   (no virus database yet? sudo systemctl status clamav-freshclam)"
fi
if command -v clamdscan >/dev/null 2>&1; then
    ok "clamdscan found at $(command -v clamdscan)"
    # Capture first: clamconf can exit non-zero over unrelated config, and
    # with `set -o pipefail` that would sink the whole pipeline.
    clam_cfg=$(clamconf 2>/dev/null || true)
    if [ -z "$clam_cfg" ]; then
        clam_cfg=$(grep -h . /etc/clamav/clamd.conf 2>/dev/null || true)
    fi
    if printf '%s\n' "$clam_cfg" | grep -qiE '^[[:space:]]*AlertExceedsMax[[:space:]="]*(yes|true)'; then
        ok "AlertExceedsMax is on (oversized files are flagged, not skipped)"
    else
        bad "AlertExceedsMax is NOT enabled - large files would pass unchecked"
        note "sudo bash $APP_DIR/deploy/install-head.sh   (merges deploy/clamd.conf.d/cyrberus.conf)"
    fi
else
    bad "clamdscan not installed"
fi

# ------------------------------------------------------------ automounting
echo
echo "Filesystems and automounting"
if systemctl is-active --quiet udisks2 2>/dev/null; then
    bad "udisks2 is running - it will mount drives before the Head sees them"
    note "sudo systemctl mask --now udisks2"
else
    ok "no udisks2 automounter running"
fi
if [ -x /sbin/mount.ntfs ] || [ -x /usr/sbin/mount.ntfs ] || [ -x /sbin/mount.ntfs-3g ] \
   || [ -x /usr/bin/ntfs-3g ]; then
    ok "NTFS support (ntfs-3g) installed"
else
    warn "ntfs-3g not installed - NTFS drives will show 'could not be opened'"
    note "sudo apt install -y ntfs-3g"
fi

# ------------------------------------------------------------ python deps
echo
echo "Python"
if [ -x "$VENV_PY" ]; then
    ok "venv interpreter at $VENV_PY"
    if [ "$IS_ROOT" = 1 ] || sudo -n true 2>/dev/null; then
        if sudo -n -u "$SVC_USER" "$VENV_PY" -c 'import pyudev, cryptography' 2>/dev/null; then
            ok "$SVC_USER can import pyudev and cryptography"
        else
            bad "$SVC_USER cannot import pyudev/cryptography from the venv"
            note "$VENV_PY -m pip install -r $APP_DIR/head/requirements.txt"
        fi
    elif "$VENV_PY" -c 'import pyudev, cryptography' 2>/dev/null; then
        ok "venv has pyudev and cryptography"
    else
        bad "venv cannot import pyudev/cryptography"
        note "$VENV_PY -m pip install -r $APP_DIR/head/requirements.txt"
    fi
else
    bad "no venv interpreter at $VENV_PY"
fi
if python3 -c 'import tkinter' 2>/dev/null; then
    ok "tkinter available for the screen"
else
    bad "tkinter missing - the screen will not start"
    note "sudo apt install -y python3-tk"
fi

# ------------------------------------------------------------------ clock
echo
echo "Clock"
# Manifests carry issued/expires times. The Pi 4 has no battery-backed clock:
# without network time it boots with the time it last shut down at.
if command -v timedatectl >/dev/null 2>&1; then
    synced="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)"
    tz="$(timedatectl show -p Timezone --value 2>/dev/null || echo unknown)"
    if [ "$synced" = yes ]; then
        ok "clock synchronised: $(date '+%a %d %b %Y %H:%M %Z') ($tz)"
    else
        warn "clock NOT synchronised: $(date '+%a %d %b %Y %H:%M %Z') ($tz)"
        note "manifests would carry wrong times. Connect to a network, or fit an RTC module."
        note "check: timedatectl status   enable: sudo timedatectl set-ntp true"
    fi
else
    warn "timedatectl not available - cannot check the clock"
fi

# ------------------------------------------------------------- what runs
echo
echo "Service and screen"
svc_enabled="$(systemctl is-enabled "$SERVICE" 2>/dev/null || true)"
svc_active="$(systemctl is-active "$SERVICE" 2>/dev/null || true)"
svc_pid="$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || echo 0)"
if [ -z "$svc_enabled" ] || [ "$svc_enabled" = "not-found" ]; then
    note "service not installed (hand-run mode)"
else
    note "service: ${svc_enabled} at boot, ${svc_active} now"
fi
hand=()
while read -r pid; do
    [ -z "$pid" ] && continue
    [ "$pid" = "$svc_pid" ] && continue
    # Count only Python processes: not the `sudo` wrapper of a hand-run, and
    # not an editor or `tail` that merely has daemon.py on its command line.
    case "$(ps -o comm= -p "$pid" 2>/dev/null)" in python*) hand+=("$pid") ;; esac
done < <(pgrep -f 'head/daemon\.py' 2>/dev/null)
svc_running=0; [ "$svc_active" = active ] && svc_running=1
running=$(( ${#hand[@]} + svc_running ))
if [ "$running" -gt 1 ]; then
    bad "$running Head daemons are running at once (hand-run pid ${hand[*]}) - they will fight over every drive"
    note "stop the hand-run one (Ctrl+C), or:  sudo systemctl stop $SERVICE"
elif [ "$running" = 1 ]; then
    ok "exactly one Head daemon running"
else
    note "no Head daemon running"
fi
if [ "$KIOSK_EXISTS" = 1 ]; then
    khome="$(getent passwd "$KIOSK_USER" | cut -d: -f6)"
    if [ -f "$khome/.xinitrc" ] && [ -f "$khome/.bash_profile" ]; then
        ok "screen files installed for '$KIOSK_USER'"
    elif [ "$IS_ROOT" = 1 ]; then
        bad "screen files missing in $khome (.xinitrc / .bash_profile)"
        note "sudo bash $APP_DIR/deploy/install-head.sh"
    fi
fi
if grep -qs -- "--autologin $KIOSK_USER" /etc/systemd/system/getty@tty1.service.d/autologin.conf; then
    note "boot mode: ON (console autologin for '$KIOSK_USER')"
else
    note "boot mode: OFF   (turn on: sudo bash $APP_DIR/deploy/boot-mode.sh on)"
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
[ "$found" = 1 ] && note "(a drive attached before the daemon started must be re-plugged to be checked)"

# ------------------------------------------------------------------ verdict
echo
echo "======================="
if [ "$fixed" -gt 0 ]; then
    echo "$fixed item(s) fixed. Re-run without --fix to confirm."
fi
if [ "$fail" -eq 0 ]; then
    echo "READY  -  $pass checks passed$([ "$warns" -gt 0 ] && echo ", $warns note(s) marked [!!]")."
    echo
    if [ "$svc_active" = active ]; then
        echo "The scanner service is running: the Head is in standby."
        echo "  watch it:  journalctl -u $SERVICE -f"
    else
        echo "Start the daemon by hand (development):"
        echo "  sudo -u $SVC_USER $VENV_PY $APP_DIR/head/daemon.py -v"
        echo "or as the service:  sudo systemctl start $SERVICE"
    fi
    exit 0
else
    echo "NOT READY  -  $fail problem(s) marked [XX], $warns note(s), $pass ok."
    [ "$FIX" = 0 ] && echo "Directory problems: sudo bash deploy/preflight.sh --fix.  Everything else: sudo bash deploy/install-head.sh"
    exit 1
fi
