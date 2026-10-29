#!/bin/sh
# Installed as ~/.xinitrc for the unprivileged `kiosk` account.
# Starts one fullscreen program and nothing else: no desktop, no file
# manager, and therefore no automounting.

xset s off          # no screen blanking - a dark screen reads as "broken"
xset -dpms
xset s noblank
unclutter -idle 0 &
matchbox-window-manager -use_titlebar no -use_cursor no &

# exec so that X exits when the UI exits, rather than dropping to a bare root window
exec /opt/cyrberus/venv/bin/python3 /opt/cyrberus/ui/kiosk.py
