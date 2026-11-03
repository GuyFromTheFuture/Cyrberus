#!/usr/bin/env bash
# Cyrberus Head - boot-to-standby switch.
#
#   sudo bash deploy/boot-mode.sh on        at power-on the Head goes straight
#                                           to "Insert your USB drive"
#   sudo bash deploy/boot-mode.sh on --now  ...and switch to it right now
#   sudo bash deploy/boot-mode.sh off       development mode: nothing starts by
#                                           itself; run things by hand (DEMO.md)
#   sudo bash deploy/boot-mode.sh restart   restart scanner + screen (after git pull)
#        bash deploy/boot-mode.sh status    what happens at boot, what runs now
#
# This only decides what starts by itself. It changes nothing about how the
# Head scans or signs. Run deploy/install-head.sh once before using it.
#
# What "on" means, piece by piece:
#   cyrberus-scanner.service enabled  -> the daemon starts at boot as `cyrberus`
#   console autologin on tty1         -> the `kiosk` account logs in on the
#                                        physical screen, its ~/.bash_profile
#                                        runs startx, ~/.xinitrc runs the UI
#   default target multi-user         -> no desktop competing for the screen
set -uo pipefail

APP_DIR=/opt/cyrberus
DEPLOY="$APP_DIR/deploy"
SERVICE=cyrberus-scanner
KIOSK_USER=kiosk
DROPIN_DIR=/etc/systemd/system/getty@tty1.service.d
DROPIN="$DROPIN_DIR/autologin.conf"
UNIT=/etc/systemd/system/$SERVICE.service

ok()   { printf '  \033[32m[ok]\033[0m   %s\n' "$*"; }
bad()  { printf '  \033[31m[XX]\033[0m   %s\n' "$*"; }
did()  { printf '  \033[33m[set]\033[0m  %s\n' "$*"; }
note() { printf '         %s\n' "$*"; }

need_root() {
    if [ "$(id -u)" != 0 ]; then
        echo "Needs root:  sudo bash $DEPLOY/boot-mode.sh $*"
        exit 2
    fi
}

ours() { [ -f "$DROPIN" ] && grep -q -- "--autologin $KIOSK_USER" "$DROPIN"; }

# Daemons started by hand (not by systemd) - the classic double-daemon mistake.
# Only Python processes count: an editor open on daemon.py, or the `sudo`
# wrapper around a hand-run, must not be reported as a second daemon.
hand_run_daemons() {
    local svc_pid; svc_pid="$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || echo 0)"
    pgrep -f 'head/daemon\.py' 2>/dev/null | while read -r pid; do
        [ "$pid" = "$svc_pid" ] && continue
        case "$(ps -o comm= -p "$pid" 2>/dev/null)" in python*) echo "$pid" ;; esac
    done
}

cmd_on() {
    need_root on
    local now=0; [ "${1:-}" = "--now" ] && now=1
    echo "Boot-to-standby: ON"
    local missing=0
    [ -f "$UNIT" ] || { bad "service not installed ($UNIT)"; missing=1; }
    id "$KIOSK_USER" >/dev/null 2>&1 || { bad "no '$KIOSK_USER' account"; missing=1; }
    local khome; khome="$(getent passwd "$KIOSK_USER" | cut -d: -f6)"
    [ -n "$khome" ] && [ -f "$khome/.xinitrc" ] && [ -f "$khome/.bash_profile" ] \
        || { bad "kiosk screen files missing (~$KIOSK_USER/.xinitrc, .bash_profile)"; missing=1; }
    if [ "$missing" = 1 ]; then
        note "Run the installer first:  sudo bash $DEPLOY/install-head.sh"
        exit 1
    fi
    if [ ! -f "$APP_DIR/keys/head_private.pem" ]; then
        bad "no signing key - the Head would refuse to approve anything"
        note "Run the installer first:  sudo bash $DEPLOY/install-head.sh"
        exit 1
    fi

    if [ -f "$DROPIN" ] && ! ours; then
        note "replacing an existing console autologin (probably set by raspi-config):"
        note "  $(grep -m1 -- '--autologin' "$DROPIN" | sed 's/^ExecStart=-//')"
    fi
    if install -d -m 0755 "$DROPIN_DIR" && install -m 0644 "$DEPLOY/getty-autologin.conf" "$DROPIN"; then
        did "console autologin on tty1 for '$KIOSK_USER'"
    else
        bad "could not write $DROPIN"; exit 1
    fi

    systemctl daemon-reload
    if systemctl enable "$SERVICE" >/dev/null 2>&1; then
        did "$SERVICE starts at boot"
    else
        bad "could not enable $SERVICE:"; systemctl enable "$SERVICE"; exit 1
    fi

    if [ "$(systemctl get-default)" != multi-user.target ]; then
        systemctl set-default multi-user.target >/dev/null 2>&1
        did "default target multi-user (no desktop session competing for the screen)"
    fi

    local strays; strays="$(hand_run_daemons | tr '\n' ' ')"
    if [ -n "$strays" ]; then
        bad "a Head daemon started by hand is running (pid $strays)"
        note "Stop it (Ctrl+C in its terminal). The service waits for it - two"
        note "daemons never run at once - but the screen stays on that one until then."
    fi

    if [ "$now" = 1 ]; then
        systemctl restart "$SERVICE" && did "$SERVICE started"
        systemctl restart getty@tty1 && did "screen restarted on tty1"
        echo
        echo "Done. The screen should show 'Insert your USB drive' within ~15 seconds."
    else
        echo
        echo "Done. Test it the way it will really be used:  sudo reboot"
        echo "(or switch over without rebooting:  sudo bash $DEPLOY/boot-mode.sh on --now)"
    fi
}

cmd_off() {
    need_root off
    local now=0; [ "${1:-}" = "--now" ] && now=1
    echo "Boot-to-standby: OFF (development mode)"
    if ours; then
        rm -f "$DROPIN"
        rmdir "$DROPIN_DIR" 2>/dev/null || true
        did "console autologin removed - tty1 shows a normal login prompt after reboot"
    elif [ -f "$DROPIN" ]; then
        note "left $DROPIN alone - it is not Cyrberus's (autologin for another account)"
    else
        ok "no console autologin"
    fi
    systemctl daemon-reload
    systemctl disable "$SERVICE" >/dev/null 2>&1 && did "$SERVICE no longer starts at boot"
    if systemctl is-active --quiet "$SERVICE"; then
        systemctl stop "$SERVICE" && did "$SERVICE stopped - you can run the daemon by hand now"
    fi
    if [ "$now" = 1 ]; then
        systemctl restart getty@tty1 && did "screen session on tty1 closed"
    else
        note "The kiosk screen keeps running until reboot, or:  sudo systemctl restart getty@tty1"
    fi
}

cmd_restart() {
    need_root restart
    systemctl restart "$SERVICE" && did "$SERVICE restarted"
    if ours; then
        systemctl restart getty@tty1 && did "screen restarted (picks up ui/ changes)"
    else
        note "boot mode is off - restart your hand-run screen yourself"
    fi
}

cmd_status() {
    echo "Cyrberus Head - boot mode status"
    echo "--------------------------------"
    local enabled active
    enabled="$(systemctl is-enabled "$SERVICE" 2>/dev/null || true)"
    active="$(systemctl is-active "$SERVICE" 2>/dev/null || true)"
    if [ "$enabled" = enabled ] && ours; then
        ok "boot mode ON - power on and it goes straight to standby"
    elif [ "$enabled" != enabled ] && ! ours; then
        ok "boot mode OFF - development mode, nothing starts by itself"
    else
        bad "boot mode PARTIAL - service ${enabled:-not installed}, autologin $(ours && echo on || echo off)"
        note "fix with:  sudo bash $DEPLOY/boot-mode.sh on    (or off)"
    fi

    echo
    echo "Right now"
    if [ "$active" = active ]; then
        local since; since="$(systemctl show -p ActiveEnterTimestamp --value "$SERVICE" 2>/dev/null)"
        ok "scanner service running (since ${since:-?})"
    else
        note "scanner service: ${active:-not installed}"
    fi
    local strays; strays="$(hand_run_daemons | tr '\n' ' ')"
    [ -n "$strays" ] && note "hand-run daemon(s): pid $strays"
    if pgrep -u "$KIOSK_USER" -f 'ui/kiosk\.py' >/dev/null 2>&1; then
        ok "screen running (kiosk account)"
    elif pgrep -f 'ui/kiosk\.py' >/dev/null 2>&1; then
        note "screen running under another account (hand-run)"
    else
        note "screen not running"
    fi

    local sf=/run/cyrberus/state.json
    if [ -r "$sf" ]; then
        python3 - "$sf" <<'PY'
import json, sys, time
try:
    p = json.load(open(sys.argv[1]))
except Exception as e:
    print("         state file unreadable: %s" % e); sys.exit()
age = time.time() - p.get("updated_at", 0)
d = p.get("detail", {})
extra = d.get("reason") or d.get("phase") or d.get("signatures_updated") or ""
mark = "  STALE - daemon not updating it" if age > 15 else ""
print("         screen state: %s %s (updated %ds ago)%s" % (p.get("state"), extra, age, mark))
PY
    elif [ -e "$sf" ]; then
        note "state file exists but $(id -un) cannot read it (not in group cyrberus?)"
    else
        note "no state file yet"
    fi

    if systemctl is-active --quiet clamav-daemon 2>/dev/null; then
        local v; v="$(timeout 10 clamdscan --version 2>/dev/null | cut -d/ -f2)"
        ok "clamd running, virus list ${v:-still loading}"
    else
        bad "clamd not running - every drive will be refused"
    fi
    local sync; sync="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)"
    if [ "$sync" = yes ]; then ok "clock synchronised ($(date '+%a %d %b %H:%M %Z'))"
    else bad "clock NOT synchronised ($(date '+%a %d %b %H:%M %Z')) - expiry times will be wrong"; fi
    [ -r /var/lib/cyrberus/key_id.txt ] && note "key_id: $(cat /var/lib/cyrberus/key_id.txt)"

    echo
    echo "Recent log (journalctl -u $SERVICE):"
    journalctl -u "$SERVICE" -n 6 --no-pager -o cat 2>/dev/null | sed 's/^/    /' \
        || note "(no permission - run with sudo to see the log)"
}

case "${1:-status}" in
    on)      shift; cmd_on "$@" ;;
    off)     shift; cmd_off "$@" ;;
    restart) cmd_restart ;;
    status)  cmd_status ;;
    *) sed -n '2,12p' "$0"; exit 2 ;;
esac
