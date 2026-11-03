# Running the Head demo

Setup is in [`SETUP_HEAD.md`](SETUP_HEAD.md); this page is about showing the
Head working. Steps marked **PARAMOUNT** are crucial: skip one and the demo
fails or misleads.

| Mode | Use it for | Needs |
|---|---|---|
| **1. Simulation** | Showing the screens; working on the UI | Nothing but a screen — no drive, no scanning |
| **2. Live, by hand** | Development: watching the daemon's log as you insert drives | Installed Head, development mode |
| **3. Standby at boot** | The real demo: power on, insert drives, no keyboard | Installed Head, `boot-mode.sh on` |

> **PARAMOUNT — one mode at a time.** Modes 1–2 start a daemon by hand; mode 3
> runs one as a service. Two daemons would fight over every drive, so a
> second one now refuses to start (*"another Head daemon is already running"*).
> Switch with `sudo bash deploy/boot-mode.sh off` / `on`.

---

## Before any audience — 5-minute checklist (PARAMOUNT)

1. `sudo bash /opt/cyrberus/deploy/preflight.sh` → **READY**.
2. `bash /opt/cyrberus/deploy/boot-mode.sh status` → clock **synchronised**, clamd running with a virus list version.
3. The screen's bottom-right says **"Virus list version 27xxx"** — not "not ready yet".
4. Test drives prepared, **labelled**, and *not* plugged in (a drive present at boot must be re-inserted anyway).
5. EICAR only. **Never real malware** — not on a drive, not in the repo.
6. Know your fallback: if anything misbehaves live, switch to mode 1 (simulation) and narrate.

---

## 1. Simulation

On the Pi's console (X needs the physical screen), with boot mode **off**:

```bash
cd /opt/cyrberus
python3 head/daemon.py --simulate &        # cycles every screen, touches no hardware
cp deploy/cyrberus-kiosk.xinitrc ~/.xinitrc
startx
```

The daemon walks ready → scanning → hashing with a live progress bar →
clean → threat → blocked (two kinds) and loops. Escape closes the screen;
`kill %1` stops the simulated daemon.

On a laptop instead (any OS with Python and Tk), for UI work:
```bash
python3 head/daemon.py --simulate          # terminal 1
python3 ui/kiosk.py --windowed             # terminal 2 - an 800x480 window
```
If the two disagree about where the status file is, set the same
`CYRBERUS_STATE=/tmp/cyrberus-state.json` in both terminals.

---

## 2. Live, by hand

Boot mode **off** (`sudo bash deploy/boot-mode.sh off`). Two places:

```bash
# SSH session - the daemon, with its log on screen
sudo -u cyrberus /opt/cyrberus/venv/bin/python3 /opt/cyrberus/head/daemon.py -v

# Pi console - the screen
cp /opt/cyrberus/deploy/cyrberus-kiosk.xinitrc ~/.xinitrc && startx
```

The daemon must run as `cyrberus` — the sudoers rule that lets it mount names
that account. After `ready` it **waits silently; that is normal.** Insert a
drive: it is identified, scanned, hashed with real progress, and approved;
`.cyrberus/manifest.json` and `manifest.sig` appear on the drive.

---

## 3. Standby at boot

```bash
sudo bash /opt/cyrberus/deploy/boot-mode.sh on
sudo reboot
```

Wait for **"Virus list version …"** in the bottom-right (1–2 minutes after
power-on). Then the Pi needs nothing but drives. Watch the log from a laptop
if you like: `ssh <admin>@<pi-ip> journalctl -u cyrberus-scanner -f`.

---

## Test media

**No formatting required** — most USB sticks are already single-partition
FAT32 or exFAT, which is what the Head admits. Check with
`lsblk -o NAME,FSTYPE,SIZE,LABEL,MOUNTPOINT`: one partition line under the
disk, `vfat` or `exfat`.

**Clean drive.** A handful of ordinary documents. Include a file with an
accented name (e.g. `informe_año.txt`) to show Unicode names survive.

**EICAR drive (PARAMOUNT: the only "malware" you ever use).** EICAR is the
industry-standard test string every scanner detects; it is not malware and
does nothing. Create it **on the Pi** (Windows Defender would quarantine it
on the laptop). Stop any daemon first (boot mode off), then:

```bash
lsblk                                   # confirm the stick is sda1 - the Pi boots from mmcblk0
sudo mkdir -p /mnt/prep
sudo mount /dev/sda1 /mnt/prep
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
  | sudo tee /mnt/prep/invoice.txt > /dev/null
wc -c /mnt/prep/invoice.txt             # must be exactly 68
clamdscan /mnt/prep/invoice.txt         # ... FOUND
sync && sudo umount /mnt/prep
```

**Two-partition drive.** Any stick with two partitions (an old Linux
installer stick often has two). The Head refuses it: a hidden second
partition is an evasion technique.

**Tampered drive.** Made live during the demo — see below.

---

## Demo script

Four drives, in this order. The last two make the point.

| # | Drive | Head shows | Proves | Requirement |
|---|---|---|---|---|
| 1 | Clean drive | **"Your drive is clean"** + "Good until …" | The happy path, real progress bar, plain-language result | FR1, FR2, O4 |
| 2 | Same drive with a file added afterwards | verifier says **DENY** | Validation binds to *contents*, not to the drive | FR4, O3 |
| 3 | EICAR drive | **"Do not use this drive"** + reference code | Detection; no manifest is written | FR1, SR2 |
| 4 | Two-partition drive | **"We cannot check this drive"** | A hidden partition cannot slip past | SR2 |

**Showing #2 without a Sentinel.** The Windows Sentinel is not built yet;
`sentinel/verify_manifest.py` is the reference implementation of exactly the
check it will make. After drive 1 is approved, leave it plugged in and, over
SSH:

```bash
VERIFY="/opt/cyrberus/venv/bin/python3 /opt/cyrberus/sentinel/verify_manifest.py"
KEY=/var/lib/cyrberus/head_public.pem
sudo mkdir -p /mnt/check

sudo mount -o ro /dev/sda1 /mnt/check
sudo $VERIFY /mnt/check $KEY           # PASS: valid until ... (N files)
sudo umount /mnt/check

sudo mount /dev/sda1 /mnt/check        # "an attacker" adds a file after validation
echo "added later" | sudo tee /mnt/check/payload.txt > /dev/null
sudo umount /mnt/check

sudo mount -o ro /dev/sda1 /mnt/check
sudo $VERIFY /mnt/check $KEY           # DENY: file not covered by manifest: payload.txt
sudo umount /mnt/check                 # PARAMOUNT: unmount before pulling the drive
```

Talking points: the manifest is signed (Ed25519) so it cannot be edited; it
lists a SHA-256 hash of every file, so adding, changing or deleting any file
breaks it; and nothing about the drive's identity is trusted — a cloned or
spoofed drive gains nothing.

---

## When something goes wrong live

| You see | Say / do |
|---|---|
| "Virus list not ready yet" | The engine is still loading — wait a minute. This is the fail-closed design visible. |
| "Unplug this drive and plug it in again" | It was plugged in before the station started — re-insert. |
| "Checking is unavailable" | `bash deploy/boot-mode.sh status`; fall back to simulation. |
| Anything else | [`SETUP_HEAD.md` §11 Troubleshooting](SETUP_HEAD.md#11-troubleshooting) |

Logs: `journalctl -u cyrberus-scanner -f`, or `/var/log/cyrberus/head.log`.
