#!/bin/sh
# ~/.xinitrc for the unprivileged `kiosk` account (installed by
# deploy/install-head.sh; started by ~/.bash_profile on tty1).
#
# Starts one fullscreen program and nothing else: no desktop, no file
# manager, and therefore no automounting.

xset s off          # no screen blanking - a dark screen reads as "broken"
xset -dpms
xset s noblank
command -v unclutter >/dev/null 2>&1 && unclutter -idle 0 &
matchbox-window-manager -use_titlebar no -use_cursor no &

# exec so that X exits when the UI exits; ~/.bash_profile then ends the
# session and the console autologin brings the screen back.
exec /opt/cyrberus/venv/bin/python3 /opt/cyrberus/ui/kiosk.py
