#!/usr/bin/env bash
# Cyrberus Head - installer for a Raspberry Pi running Raspberry Pi OS Lite.
#
#   sudo bash /opt/cyrberus/deploy/install-head.sh [options]
#
#   --dry-run       show what would change; change nothing
#   --no-packages   skip apt entirely (offline re-run on a Pi already set up)
#   --no-kiosk      scanner only: no kiosk account and no screen files
#   --boot          also switch boot-to-standby on (deploy/boot-mode.sh on)
#
# Safe to re-run: every step checks before it acts, so a second run on a
# finished Pi reports "unchanged" for everything. It never overwrites the
# signing key, never formats or mounts anything, and never touches a USB drive.
#
# What it sets up (docs/SETUP_HEAD.md explains each one):
#   1 packages         ClamAV, Python venv support, filesystem tools, X for the screen
#   2 accounts         cyrberus (runs the daemon), kiosk (shows the screen),
#                      and your admin account added to the cyrberus group
#   3 python venv      /opt/cyrberus/venv with head/requirements.txt
#   4 directories      keys, scan mountpoint, logs, /run/cyrberus (tmpfiles)
#   5 signing key      generated once; public key exported for Sentinels
#   6 mount privilege  /etc/sudoers.d/cyrberus, syntax-checked by visudo first
#   7 ClamAV           fail-closed scan limits merged into clamd.conf
#   8 automounting     udisks2 masked so nothing mounts a drive behind our back
#   9 clock            network time sync switched on
#  10 service          cyrberus-scanner.service installed (not enabled)
#  11 screen           kiosk ~/.xinitrc, ~/.bash_profile, X console-only
#  12 checks           deploy/preflight.sh
set -euo pipefail

APP_DIR=/opt/cyrberus
DEPLOY="$APP_DIR/deploy"
SVC_USER=cyrberus
KIOSK_USER=kiosk
KEY_DIR="$APP_DIR/keys"
MOUNTPOINT=/mnt/cyrberus-scan
LOG_DIR=/var/log/cyrberus
RUN_DIR=/run/cyrberus
EXPORT_DIR=/var/lib/cyrberus
VENV_PY="$APP_DIR/venv/bin/python3"
CLAMD_CONF=/etc/clamav/clamd.conf
UNIT=/etc/systemd/system/cyrberus-scanner.service

DRY=0; PACKAGES=1; KIOSK=1; BOOT=0
for arg in "$@"; do
    case "$arg" in
        --dry-run)     DRY=1 ;;
        --no-packages) PACKAGES=0 ;;
        --no-kiosk)    KIOSK=0 ;;
        --boot)        BOOT=1 ;;
        -h|--help)     sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg  (try --help)"; exit 2 ;;
    esac
done

CHANGES=0
WARNINGS=()
step()   { printf '\n\033[1m[%s] %s\033[0m\n' "$1" "$2"; }
same()   { printf '   \033[32m=\033[0m %s\n' "$*"; }
change() { printf '   \033[33m+\033[0m %s%s\n' "$*" "$([ "$DRY" = 1 ] && echo '   (dry run)')"; CHANGES=$((CHANGES+1)); }
warn()   { printf '   \033[31m!\033[0m %s\n' "$*"; WARNINGS+=("$*"); }
info()   { printf '     %s\n' "$*"; }
run()    { if [ "$DRY" = 1 ]; then printf '       would run: %s\n' "$*"; else "$@"; fi; }

# install_file SRC DEST MODE OWNER GROUP - copy only if missing or different.
install_file() {
    local src="$1" dest="$2" mode="$3" owner="$4" group="$5"
    if [ -f "$dest" ] && cmp -s "$src" "$dest"; then
        same "$dest"
        return 1
    fi
    change "install $dest"
    run install -D -m "$mode" -o "$owner" -g "$group" "$src" "$dest"
    return 0
}

# ensure_dir PATH MODE OWNER GROUP
ensure_dir() {
    local path="$1" mode="$2" owner="$3" group="$4"
    if [ ! -d "$path" ]; then
        change "create $path ($mode $owner:$group)"
        run install -d -m "$mode" -o "$owner" -g "$group" "$path"
        return
    fi
    if mountpoint -q "$path"; then
        warn "$path has a drive mounted on it - left alone. Unmount it and re-run."
        return
    fi
    local cur; cur="$(stat -c '%a %U:%G' "$path")"
    if [ "$cur" != "${mode#0} $owner:$group" ]; then
        change "fix $path ($cur -> ${mode#0} $owner:$group)"
        run chown "$owner:$group" "$path"
        run chmod "$mode" "$path"
    else
        same "$path ($cur)"
    fi
    # Files left by an earlier hand-run under another account block writes.
    local strays
    strays="$(find "$path" -mindepth 1 -maxdepth 2 ! -user "$owner" 2>/dev/null | head -3)"
    if [ -n "$strays" ]; then
        change "re-own stray files in $path"
        run chown -R "$owner:$group" "$path"
    fi
}

pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }
user_exists()   { id "$1" >/dev/null 2>&1; }
group_exists()  { getent group "$1" >/dev/null 2>&1; }
in_group()      { id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qx "$2"; }
has_unit()      { systemctl list-unit-files "$1" --no-legend 2>/dev/null | grep -q "^$1"; }

# --------------------------------------------------------------- preconditions
if [ "$(id -u)" != 0 ]; then
    echo "Run as root:  sudo bash $APP_DIR/deploy/install-head.sh $*"
    exit 2
fi
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
if [ "$HERE" != "$DEPLOY" ]; then
    echo "This repository must live at $APP_DIR (found it at ${HERE%/deploy})."
    echo "The service, the screen and the sudoers rule all use that path. Move it:"
    echo "  sudo mv ${HERE%/deploy} $APP_DIR"
    exit 2
fi
for f in cyrberus-scanner.service tmpfiles.d-cyrberus.conf sudoers.d/cyrberus \
         clamd.conf.d/cyrberus.conf cyrberus-kiosk.xinitrc \
         cyrberus-kiosk.bash_profile getty-autologin.conf cyrberus.default preflight.sh; do
    [ -f "$DEPLOY/$f" ] || { echo "missing $DEPLOY/$f - is the checkout complete? (git pull)"; exit 2; }
done
ADMIN_USER="${SUDO_USER:-}"
[ "$ADMIN_USER" = root ] && ADMIN_USER=""

echo "Cyrberus Head installer$([ "$DRY" = 1 ] && echo '  -  DRY RUN, nothing will change')"
echo "  repository : $APP_DIR (owner $(stat -c %U "$APP_DIR"))"
echo "  system     : $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}") / $(uname -m)"
echo "  admin user : ${ADMIN_USER:-none detected (run with sudo from your own login)}"
[ "$(uname -m)" = aarch64 ] || info "note: expected aarch64 (64-bit Pi OS); continuing anyway"

# ------------------------------------------------------------------ 1 packages
step 1 "Packages"
CORE_PKGS=(clamav clamav-daemon clamav-freshclam python3-venv git
           ntfs-3g exfatprogs dosfstools)
SCREEN_PKGS=(python3-tk xserver-xorg xinit x11-xserver-utils matchbox-window-manager)
# Best effort: each is tried on its own and a failure only warns. Package
# names drift between Debian releases (Bookworm 12 -> Trixie 13), and none of
# these is required for the screen to work. "a|b" = try a, then b.
#   xserver-xorg-legacy  Xorg.wrap + Xwrapper.config (console-only rule)
#   unclutter            hides the pointer (the screen also hides it itself)
NICE_PKGS=(xserver-xorg-legacy "unclutter|unclutter-xfixes" fonts-dejavu-core fontconfig)
# --no-install-recommends keeps the screen layer to ~45 MB (no desktop, no
# file manager, no automounter) - the footprint the progress report states.
APT_INSTALL=(env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends)
wanted=("${CORE_PKGS[@]}")
[ "$KIOSK" = 1 ] && wanted+=("${SCREEN_PKGS[@]}")
missing=()
for p in "${wanted[@]}"; do pkg_installed "$p" || missing+=("$p"); done
nice_missing=()
if [ "$KIOSK" = 1 ]; then
    for alts in "${NICE_PKGS[@]}"; do
        have=0
        for p in ${alts//|/ }; do pkg_installed "$p" && have=1; done
        [ "$have" = 1 ] || nice_missing+=("$alts")
    done
fi

if [ "$PACKAGES" = 0 ]; then
    same "skipped (--no-packages)"
    [ ${#missing[@]} -gt 0 ] && warn "not installed: ${missing[*]}"
elif [ ${#missing[@]} -eq 0 ] && [ ${#nice_missing[@]} -eq 0 ]; then
    same "all ${#wanted[@]} packages already installed"
else
    change "apt install ${missing[*]} ${nice_missing[*]//|/ or }"
    run apt-get update
    if [ ${#missing[@]} -gt 0 ]; then
        run "${APT_INSTALL[@]}" "${missing[@]}"
    fi
    for alts in "${nice_missing[@]}"; do
        done_one=0
        for p in ${alts//|/ }; do
            if run "${APT_INSTALL[@]}" "$p"; then done_one=1; break; fi
        done
        [ "$done_one" = 1 ] || warn "optional package ${alts//|/ or } not installed (not required)"
    done
fi
if ! compgen -G "/var/lib/clamav/daily.c[vl]d" >/dev/null && \
   ! compgen -G "/var/lib/clamav/daily.inc" >/dev/null; then
    warn "no virus database yet - every drive is refused until freshclam downloads one (needs internet)"
    info "check:  sudo systemctl status clamav-freshclam"
fi

# ------------------------------------------------------------------ 2 accounts
step 2 "Accounts"
if user_exists "$SVC_USER"; then
    same "service account $SVC_USER"
else
    change "create service account $SVC_USER (no login, no home)"
    if group_exists "$SVC_USER"; then grp=(-g "$SVC_USER"); else grp=(--user-group); fi
    run useradd --system "${grp[@]}" --home-dir "$APP_DIR" --no-create-home \
        --shell /usr/sbin/nologin "$SVC_USER"
fi

if [ "$KIOSK" = 1 ]; then
    if user_exists "$KIOSK_USER"; then
        same "screen account $KIOSK_USER"
    else
        change "create screen account $KIOSK_USER (no password, no sudo)"
        run useradd --create-home --user-group --shell /bin/bash "$KIOSK_USER"
        run usermod --lock "$KIOSK_USER"
    fi
    # cyrberus: read the state file. video/input/render: drive the display.
    for g in "$SVC_USER" video input render; do
        group_exists "$g" || continue
        if user_exists "$KIOSK_USER" && in_group "$KIOSK_USER" "$g"; then
            same "$KIOSK_USER in group $g"
        else
            change "add $KIOSK_USER to group $g"
            run usermod -aG "$g" "$KIOSK_USER"
        fi
    done
    if user_exists "$KIOSK_USER" && id -nG "$KIOSK_USER" | tr ' ' '\n' | grep -qx sudo; then
        warn "$KIOSK_USER is in the sudo group - remove it: sudo deluser $KIOSK_USER sudo"
    fi
fi

ADMIN_ADDED=0
if [ -n "$ADMIN_USER" ]; then
    if in_group "$ADMIN_USER" "$SVC_USER"; then
        same "$ADMIN_USER in group $SVC_USER (can read state and logs)"
    else
        change "add $ADMIN_USER to group $SVC_USER (log out and back in for it to apply)"
        run usermod -aG "$SVC_USER" "$ADMIN_USER"
        [ "$DRY" = 0 ] && ADMIN_ADDED=1
    fi
fi

# --------------------------------------------------------------- 3 python venv
step 3 "Python environment"
APP_OWNER="$(stat -c %U "$APP_DIR")"
if [ -x "$VENV_PY" ]; then
    same "venv at $APP_DIR/venv"
else
    change "create venv at $APP_DIR/venv (as $APP_OWNER, who owns the checkout)"
    run sudo -u "$APP_OWNER" python3 -m venv "$APP_DIR/venv"
fi
if [ "$DRY" = 0 ] && user_exists "$SVC_USER" && \
   sudo -u "$SVC_USER" "$VENV_PY" -c 'import pyudev, cryptography, psutil' 2>/dev/null; then
    same "pyudev, cryptography, psutil importable by $SVC_USER"
else
    change "pip install -r head/requirements.txt"
    run sudo -u "$APP_OWNER" "$VENV_PY" -m pip install --quiet -r "$APP_DIR/head/requirements.txt"
fi
if [ "$DRY" = 0 ] && user_exists "$SVC_USER" && \
   ! sudo -u "$SVC_USER" test -r "$APP_DIR/head/daemon.py"; then
    warn "$SVC_USER cannot read $APP_DIR/head/daemon.py - the checkout is not world-readable."
    info "fix:  sudo chmod -R o+rX $APP_DIR   (then re-run; keys/ is reset to 700 below)"
fi

# --------------------------------------------------------------- 4 directories
step 4 "Directories"
if [ "$DRY" = 1 ] && ! user_exists "$SVC_USER"; then
    info "(account $SVC_USER does not exist yet - showing the plan only)"
    change "create $KEY_DIR, $MOUNTPOINT, $LOG_DIR (owned by $SVC_USER)"
else
    ensure_dir "$KEY_DIR"    0700 "$SVC_USER" "$SVC_USER"
    ensure_dir "$MOUNTPOINT" 0750 "$SVC_USER" "$SVC_USER"
    ensure_dir "$LOG_DIR"    0750 "$SVC_USER" "$SVC_USER"
fi
if install_file "$DEPLOY/tmpfiles.d-cyrberus.conf" /etc/tmpfiles.d/cyrberus.conf 0644 root root \
   || [ ! -d "$RUN_DIR" ]; then
    change "apply tmpfiles rule now (creates $RUN_DIR without a reboot)"
    run systemd-tmpfiles --create /etc/tmpfiles.d/cyrberus.conf
fi
if [ -d "$RUN_DIR" ]; then
    strays="$(find "$RUN_DIR" -mindepth 1 ! -user "$SVC_USER" 2>/dev/null | head -3)"
    if [ -n "$strays" ]; then
        change "re-own files in $RUN_DIR left by a hand-run"
        run chown -R "$SVC_USER:$SVC_USER" "$RUN_DIR"
    fi
fi

# --------------------------------------------------------------- 5 signing key
step 5 "Signing key"
PRIV="$KEY_DIR/head_private.pem"
PUB="$KEY_DIR/head_public.pem"
if [ -f "$PRIV" ]; then
    same "private key present - never overwritten by this script"
elif [ "$DRY" = 1 ]; then
    change "generate the Head's Ed25519 keypair in $KEY_DIR"
else
    change "generate the Head's Ed25519 keypair in $KEY_DIR"
    if [ -f "$APP_DIR/head/keygen.py" ]; then
        sudo -u "$SVC_USER" "$VENV_PY" "$APP_DIR/head/keygen.py"
    else
        # Same behaviour as head/keygen.py: refuse to overwrite, private 600.
        sudo -u "$SVC_USER" "$VENV_PY" - "$KEY_DIR" <<'PY'
import os, sys
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
d = sys.argv[1]
os.umask(0o077)
priv = ed25519.Ed25519PrivateKey.generate()
pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                         serialization.NoEncryption())
pub = priv.public_key().public_bytes(serialization.Encoding.PEM,
                                     serialization.PublicFormat.SubjectPublicKeyInfo)
fd = os.open(os.path.join(d, "head_private.pem"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as f:
    f.write(pem)
fd = os.open(os.path.join(d, "head_public.pem"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
with os.fdopen(fd, "wb") as f:
    f.write(pub)
os.chmod(os.path.join(d, "head_public.pem"), 0o644)
print("keypair written")
PY
    fi
fi
if [ -f "$PRIV" ]; then
    m="$(stat -c '%a %U' "$PRIV")"
    if [ "$m" != "600 $SVC_USER" ]; then
        change "fix private key permissions ($m -> 600 $SVC_USER)"
        run chown "$SVC_USER:$SVC_USER" "$PRIV"
        run chmod 600 "$PRIV"
    fi
fi
KEY_ID=""
if [ -f "$PUB" ]; then
    KEY_ID="$(sha256sum "$PUB" | cut -c1-16)"
    info "key_id: $KEY_ID   (every manifest from this Head carries it)"
    # Export the PUBLIC key where an ordinary login can copy it for Sentinels.
    if [ "$DRY" = 0 ]; then
        install -d -m 0755 "$EXPORT_DIR"
        if ! cmp -s "$PUB" "$EXPORT_DIR/head_public.pem"; then
            change "export public key to $EXPORT_DIR/head_public.pem"
            install -m 0644 "$PUB" "$EXPORT_DIR/head_public.pem"
        fi
        echo "$KEY_ID" > "$EXPORT_DIR/key_id.txt"
        chmod 0644 "$EXPORT_DIR/key_id.txt"
    fi
    info "copy for the Sentinel trust store:  $EXPORT_DIR/head_public.pem"
fi

# ----------------------------------------------------------- 6 mount privilege
step 6 "Mount privilege (sudoers)"
tmp="$(mktemp)"
cp "$DEPLOY/sudoers.d/cyrberus" "$tmp"
if ! visudo -cqf "$tmp"; then
    rm -f "$tmp"
    echo "deploy/sudoers.d/cyrberus failed visudo's syntax check - not installed."
    echo "A broken sudoers file can lock every account out of sudo. Fix the file first."
    exit 1
fi
if [ -f /etc/sudoers.d/cyrberus ] && cmp -s "$tmp" /etc/sudoers.d/cyrberus; then
    same "/etc/sudoers.d/cyrberus (validated)"
else
    change "install /etc/sudoers.d/cyrberus (validated by visudo)"
    run install -m 0440 -o root -g root "$tmp" /etc/sudoers.d/cyrberus
fi
rm -f "$tmp"

# -------------------------------------------------------------------- 7 ClamAV
step 7 "ClamAV settings"
clam_changed=0
if [ ! -f "$CLAMD_CONF" ]; then
    warn "$CLAMD_CONF not found - is clamav-daemon installed?"
else
    while read -r key value; do
        case "$key" in ''|'#'*) continue ;; esac
        if grep -qE "^[[:space:]]*${key}[[:space:]]+${value}[[:space:]]*$" "$CLAMD_CONF" \
           && [ "$(grep -cE "^[[:space:]]*${key}[[:space:]]" "$CLAMD_CONF")" = 1 ]; then
            same "$key $value"
            continue
        fi
        if [ "$clam_changed" = 0 ] && [ "$DRY" = 0 ] && [ ! -f "$CLAMD_CONF.pre-cyrberus" ]; then
            cp -p "$CLAMD_CONF" "$CLAMD_CONF.pre-cyrberus"
            info "backup: $CLAMD_CONF.pre-cyrberus"
        fi
        clam_changed=1
        if grep -qE "^[[:space:]]*${key}[[:space:]]" "$CLAMD_CONF"; then
            change "set $key $value"
            if [ "$DRY" = 0 ]; then
                # Replace the first occurrence, delete any duplicates.
                awk -v k="$key" -v v="$value" '
                    $1 == k { if (!done) { print k " " v; done = 1 } ; next }
                    { print }' "$CLAMD_CONF" > "$CLAMD_CONF.tmp" \
                  && cat "$CLAMD_CONF.tmp" > "$CLAMD_CONF" && rm -f "$CLAMD_CONF.tmp"
            fi
        else
            change "add $key $value"
            [ "$DRY" = 0 ] && printf '%s %s\n' "$key" "$value" >> "$CLAMD_CONF"
        fi
    done < "$DEPLOY/clamd.conf.d/cyrberus.conf"
fi
if [ "$clam_changed" = 1 ] && has_unit clamav-daemon.service; then
    change "restart clamav-daemon to load the new settings"
    run systemctl restart clamav-daemon || true
    if [ "$DRY" = 0 ]; then
        sleep 3
        st="$(systemctl is-active clamav-daemon 2>/dev/null || true)"
        case "$st" in
            active|activating) info "clamav-daemon is $st (loading signatures takes ~1 minute on a Pi)" ;;
            *) warn "clamav-daemon is '$st' after the change. See: sudo journalctl -u clamav-daemon -n 30"
               info "the original is at $CLAMD_CONF.pre-cyrberus" ;;
        esac
    fi
fi
if has_unit clamav-freshclam.service; then
    if systemctl is-enabled --quiet clamav-freshclam 2>/dev/null; then
        same "clamav-freshclam enabled (signature updates)"
    else
        change "enable clamav-freshclam (signature updates)"
        run systemctl enable --now clamav-freshclam
    fi
fi

# -------------------------------------------------------------- 8 automounting
step 8 "Automounting"
if has_unit udisks2.service; then
    if [ "$(systemctl is-enabled udisks2 2>/dev/null || true)" = masked ]; then
        same "udisks2 masked"
    else
        change "mask udisks2 - nothing but the Head may mount a drive"
        run systemctl mask --now udisks2
    fi
else
    same "udisks2 not installed"
fi

# ---------------------------------------------------------------------- 9 clock
step 9 "Clock"
if command -v timedatectl >/dev/null 2>&1; then
    if [ "$(timedatectl show -p NTP --value 2>/dev/null || true)" = yes ]; then
        same "network time sync on"
    else
        change "switch network time sync on"
        run timedatectl set-ntp true || warn "could not enable NTP - see SETUP_HEAD.md, Clock"
    fi
    info "timezone: $(timedatectl show -p Timezone --value 2>/dev/null || echo unknown)"
    info "(the screen shows expiry in local time - set it with: sudo timedatectl set-timezone America/Chicago)"
else
    warn "timedatectl not found - cannot check the clock"
fi

# -------------------------------------------------------------------- 10 service
step 10 "Scanner service"
unit_changed=0
install_file "$DEPLOY/cyrberus-scanner.service" "$UNIT" 0644 root root && unit_changed=1
if [ -f /etc/default/cyrberus ]; then
    same "/etc/default/cyrberus (site settings, never overwritten)"
else
    change "install /etc/default/cyrberus (site settings template)"
    run install -m 0644 -o root -g root "$DEPLOY/cyrberus.default" /etc/default/cyrberus
fi
if [ "$unit_changed" = 1 ]; then
    run systemctl daemon-reload
fi
if systemctl is-active --quiet cyrberus-scanner 2>/dev/null; then
    # Restart only if the unit or the daemon's code changed since it started
    # (typically: git pull, then re-run this script).
    stale=$unit_changed
    since="$(systemctl show -p ExecMainStartTimestamp --value cyrberus-scanner 2>/dev/null || true)"
    epoch="$(date -d "$since" +%s 2>/dev/null || echo 0)"
    if [ "$epoch" = 0 ] || [ -n "$(find "$APP_DIR/head" "$APP_DIR/common" -name '*.py' \
                                   -newermt "@$epoch" 2>/dev/null | head -1)" ]; then
        stale=1
    fi
    if [ "$stale" = 1 ]; then
        change "restart cyrberus-scanner so it runs the current code"
        run systemctl restart cyrberus-scanner
    else
        same "cyrberus-scanner is running the current code"
    fi
fi
if systemctl is-enabled --quiet cyrberus-scanner 2>/dev/null; then
    info "starts at boot: yes (boot mode on)"
else
    info "starts at boot: no  (turn on with: sudo bash $DEPLOY/boot-mode.sh on)"
fi

# --------------------------------------------------------------------- 11 screen
step 11 "Operator screen"
if [ "$KIOSK" = 0 ]; then
    same "skipped (--no-kiosk)"
elif ! user_exists "$KIOSK_USER"; then
    info "(account $KIOSK_USER does not exist yet - showing the plan only)"
    change "install ~$KIOSK_USER/.xinitrc and ~$KIOSK_USER/.bash_profile"
else
    KHOME="$(getent passwd "$KIOSK_USER" | cut -d: -f6)"
    install_file "$DEPLOY/cyrberus-kiosk.xinitrc"      "$KHOME/.xinitrc"      0644 "$KIOSK_USER" "$KIOSK_USER" || true
    install_file "$DEPLOY/cyrberus-kiosk.bash_profile" "$KHOME/.bash_profile" 0644 "$KIOSK_USER" "$KIOSK_USER" || true
    if [ ! -f "$KHOME/.hushlogin" ]; then
        change "silence the login banner on the screen"
        run install -m 0644 -o "$KIOSK_USER" -g "$KIOSK_USER" /dev/null "$KHOME/.hushlogin"
    fi
fi
if [ "$KIOSK" = 1 ]; then
    XW=/etc/X11/Xwrapper.config
    if [ -f "$XW" ] && grep -qE '^[[:space:]]*allowed_users[[:space:]]*=[[:space:]]*console' "$XW"; then
        same "X may only be started from the physical console"
    elif [ -f "$XW" ] && grep -qE '^[[:space:]]*allowed_users' "$XW"; then
        change "X back to console-only (allowed_users=console); X over SSH stops working"
        [ "$DRY" = 0 ] && sed -i -E 's/^[[:space:]]*allowed_users[[:space:]]*=.*/allowed_users=console/' "$XW"
    else
        change "set allowed_users=console in $XW"
        [ "$DRY" = 0 ] && { install -d /etc/X11; echo "allowed_users=console" >> "$XW"; }
    fi
fi

# ------------------------------------------------------------------ boot mode
if [ "$BOOT" = 1 ]; then
    step "+" "Boot-to-standby"
    if [ "$DRY" = 1 ]; then
        change "bash $DEPLOY/boot-mode.sh on"
    else
        bash "$DEPLOY/boot-mode.sh" on
    fi
fi

# --------------------------------------------------------------------- 12 checks
step 12 "Preflight"
if [ "$DRY" = 1 ]; then
    info "skipped in a dry run"
else
    bash "$DEPLOY/preflight.sh" || true
fi

# -------------------------------------------------------------------- summary
echo
echo "=================================================================="
if [ "$DRY" = 1 ]; then
    echo "DRY RUN: $CHANGES change(s) would be made. Nothing was changed."
else
    echo "Install finished: $CHANGES change(s) made."
fi
if [ ${#WARNINGS[@]} -gt 0 ]; then
    echo "Read these before a demo:"
    for w in "${WARNINGS[@]}"; do echo "  ! $w"; done
fi
[ -n "$KEY_ID" ] && echo "Head key_id: $KEY_ID"
echo
if systemctl is-enabled --quiet cyrberus-scanner 2>/dev/null; then
    echo "Boot-to-standby is ON. Reboot to see it:  sudo reboot"
else
    echo "Next:"
    echo "  Try it by hand ..... see docs/DEMO.md"
    echo "  Standby at boot .... sudo bash $DEPLOY/boot-mode.sh on   then   sudo reboot"
fi
if [ "$ADMIN_ADDED" = 1 ]; then
    echo
    echo "You were added to the '$SVC_USER' group. Log out and back in (or reboot)"
    echo "before running the screen by hand, or it cannot read the state file."
fi
