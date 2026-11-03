# shellcheck shell=bash
# ~/.bash_profile for the Cyrberus `kiosk` account.
# Installed by deploy/install-head.sh. Do not give this account a password.
#
# On the physical console (tty1) this starts the operator screen and never
# offers a shell: if the screen closes or crashes, the session ends and the
# console autologin (deploy/boot-mode.sh on) starts it again a few seconds
# later. Reached any other way, it is an ordinary login.

if [ -z "${DISPLAY:-}" ] && [ "$(tty)" = "/dev/tty1" ]; then
    # Ctrl+C / Ctrl+Z on the console keyboard must not drop to a prompt.
    trap '' INT QUIT TSTP
    # The X server and the kiosk write their errors here - first stop when
    # the screen stays black: cat /home/kiosk/kiosk-session.log
    startx -- -nocursor >"$HOME/kiosk-session.log" 2>&1
    # Throttle a crash loop, then end the session; getty logs in again.
    sleep 3
    exit 0
fi

[ -f "$HOME/.bashrc" ] && . "$HOME/.bashrc"
