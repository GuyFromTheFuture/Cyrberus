# Cyrberus Head — Setup Guide

From a blank microSD card to a Raspberry Pi that powers on straight into
**"Insert your USB drive"**. This supersedes the earlier hand-built setup
notes. Almost everything is now done by one idempotent installer,
`deploy/install-head.sh`; this guide explains what it does, the few steps it
cannot do for you, and how to operate and troubleshoot the result.

| | |
|---|---|
| **Hardware** | Raspberry Pi 4 Model B (4 GB minimum, 8 GB used in development) |
| **OS** | Raspberry Pi OS **Lite**, **64-bit** (Bookworm/Debian 12 or Trixie/Debian 13) |
| **Time** | ~45 min, most of it waiting on downloads |
| **You need** | the Pi + official power supply, microSD, a screen, a USB keyboard (first boot only), a laptop on the same network |

> **How to read this guide.** Steps marked **PARAMOUNT** are crucial for
> operation or security: skip one and the Head either stops working or stops
> being trustworthy. Everything else is recommended or optional.
> Placeholders: `<admin>` = the login you create on the Pi, `<pi-ip>` = its IP
> address, `<owner>/<repo>` = your GitHub repository.

---

## PARAMOUNT index

| ID | Rule | Where |
|---|---|---|
| **P1** | Flash Raspberry Pi OS **Lite 64-bit** — no desktop (a desktop brings an automounter), 64-bit (ClamAV needs the memory) | [§2](#2-flash-the-os) |
| **P2** | The repository lives at **`/opt/cyrberus`** — the service, screen and permissions all assume that path | [§4](#4-get-the-code) |
| **P3** | **Nothing but the Head may mount a drive.** After setup, plug in a drive: `lsblk` must show no mountpoint | [§5](#5-run-the-installer), [§6](#6-verify) |
| **P4** | ClamAV must **fail closed**: `AlertExceedsMax yes` (the installer sets it; preflight checks it) | [§5](#5-run-the-installer) |
| **P5** | The **private key never leaves the Pi** — never copied, never emailed, never committed. Mode 600, owner `cyrberus`. Exposed = rotate | [§9.5](#95-the-signing-key-export-rotate-never-copy) |
| **P6** | **One Head daemon at a time.** Boot mode on → stop the service before running one by hand (the daemon now refuses a second copy) | [§8](#8-boot-to-standby-the-hands-off-mode) |
| **P7** | **The clock must be right** — manifests carry issue and expiry times. Network time or an RTC module, and the correct timezone | [§9.3](#93-the-clock) |
| **P8** | Before accepting drives, the screen must show **"Virus list version N"** — until then every drive is refused | [§8](#8-boot-to-standby-the-hands-off-mode) |
| **P9** | Run **preflight** and get **READY** before every demo | [§6](#6-verify) |
| **P10** | The `kiosk` screen account has **no password and no sudo**; X starts only from the physical console | [§5](#5-run-the-installer) |
| **P11** | Test with **EICAR only** — never real malware, never commit samples | [DEMO.md](DEMO.md) |
| **P12** | Shut down with `sudo poweroff`; never pull the power while it is writing | [§9.6](#96-power-and-the-sd-card) |

---

## 1. Hardware

| Item | Notes |
|---|---|
| Raspberry Pi 4 Model B | 4 GB is the design target (it is what a school would buy); 8 GB gives headroom. ClamAV alone holds 1.3–1.8 GB of RAM. |
| **Official 5.1 V / 3 A USB-C supply** | Undervoltage corrupts SD cards and drops USB devices mid-scan. Phone chargers are a false economy. |
| microSD, 32 GB+, A1/A2 rated | Or boot from a USB SSD for endurance. The Head recognises its own boot disk and never treats it as a drive to check. |
| Screen | The UI is designed for 800×480 (official 7" touchscreen) and scales to any HDMI monitor. **The Pi 4 has micro-HDMI ports** — bring the right cable. Touch is not needed: the workflow has no buttons. |
| USB keyboard | First boot and console troubleshooting only. |
| Case with cooling | Scanning keeps the CPU busy for minutes at a time. |
| *Optional:* DS3231 RTC module | The Pi 4 has no battery-backed clock. Without network time it boots with the time it last shut down at (see P7). |

---

## 2. Flash the OS

**PARAMOUNT (P1).** In **Raspberry Pi Imager** choose
*Raspberry Pi OS (other) → Raspberry Pi OS Lite (64-bit)*.

Before writing, open Imager's **customisation** settings and set:

- hostname `cyrberus`
- a username and strong password — this is `<admin>`, your administrator login
- Wi-Fi (or plan on Ethernet) — needed for packages, virus-signature updates and time
- locale, keyboard and **timezone** (South Texas is `America/Chicago`)
- **enable SSH**

> Why Lite: the Desktop image ships a file manager that mounts every drive the
> moment it is inserted — before the Head can decide how to mount it read-only.
> Why 64-bit: ClamAV's signature database needs more address space than a
> 32-bit process gets.

Raspberry Pi OS moved from Debian 12 (Bookworm) to Debian 13 (Trixie) in late
2025; the Head was built on Bookworm and the installer is written for both.

---

## 3. First boot and SSH

Boot the Pi with the screen and keyboard attached. Log in, then:

```bash
uname -m                      # must print aarch64 (64-bit). armv7l = wrong image
cat /etc/os-release | head -2 # which Debian release you are on
hostname -I                   # the Pi's IP address: <pi-ip>
```

From your laptop (Windows PowerShell has `ssh` built in):

```powershell
ssh <admin>@<pi-ip>
```

> `ssh <admin>@cyrberus.local` also works on some networks, but Windows often
> cannot resolve `.local` names. Use the IP address.

Update everything once:

```bash
sudo apt update && sudo apt full-upgrade -y
sudo reboot
```

---

## 4. Get the code

**PARAMOUNT (P2).** The repository must be at `/opt/cyrberus`, owned by your
admin login.

```bash
sudo apt install -y git
sudo git clone https://github.com/<owner>/<repo>.git /opt/cyrberus
sudo chown -R "$USER":"$USER" /opt/cyrberus
cd /opt/cyrberus
git config pull.rebase true
```

- **Private repository:** GitHub does not accept your account password for
  git. When prompted for a password, paste a *personal access token*
  (fine-grained, read-only, this repository only).
- **Never commit from the Pi.** Changes are made on a laptop and pushed; the
  Pi only pulls. This avoids the "divergent branches" problem entirely.

**Already have a working Head?** Skip the clone:
`cd /opt/cyrberus && git pull`, then continue with §5. The installer adopts
an existing setup — your key, accounts and venv are kept.

---

## 5. Run the installer

See what it would change first, then run it for real:

```bash
sudo bash /opt/cyrberus/deploy/install-head.sh --dry-run
sudo bash /opt/cyrberus/deploy/install-head.sh
```

It is **safe to re-run** at any time: each step checks before it acts, and a
second run on a finished Pi reports `0 change(s)`. It never overwrites the
signing key, never formats or mounts anything, and never touches a USB drive.

| # | Step | What it does | Why (security rationale) |
|---|---|---|---|
| 1 | Packages | ClamAV, Python venv, `ntfs-3g`, `exfatprogs`, `dosfstools`; for the screen a bare X server, `matchbox` and `python3-tk` — `--no-install-recommends`, ~45 MB | Least functionality (CM-7): no desktop, no file manager, no automounter. `ntfs-3g` parses untrusted NTFS in user space, not the kernel |
| 2 | Accounts | `cyrberus` (runs the daemon, no login), `kiosk` (shows the screen, no password, no sudo), adds `<admin>` to group `cyrberus` | Privilege separation: the scanner can mount, the screen can only read status |
| 3 | Python venv | `/opt/cyrberus/venv` with `head/requirements.txt` | Reproducible dependencies; Debian forbids `pip` into system Python |
| 4 | Directories | `keys/` 700; `/mnt/cyrberus-scan`, `/var/log/cyrberus`, `/run/cyrberus` 750; tmpfiles rule recreates `/run/cyrberus` every boot | Only `cyrberus` writes; group members read |
| 5 | **Signing key** | Generates the Ed25519 keypair **once**; exports the *public* key to `/var/lib/cyrberus/head_public.pem` and prints its `key_id` | Root of trust (P5). Public key is what Sentinels need |
| 6 | Mount privilege | `/etc/sudoers.d/cyrberus`, **syntax-checked by `visudo` before install** | A broken sudoers file locks everyone out of sudo |
| 7 | **ClamAV** | Merges `deploy/clamd.conf.d/cyrberus.conf` into `clamd.conf` (backup kept as `clamd.conf.pre-cyrberus`), restarts clamd | **P4** fail closed: oversized or encrypted content is flagged, never silently skipped |
| 8 | **Automounting** | Masks `udisks2` | **P3** |
| 9 | Clock | Turns on network time sync | **P7** |
| 10 | Service | Installs `cyrberus-scanner.service` and `/etc/default/cyrberus` (site settings). **Does not enable it** | Boot behaviour is a separate, explicit switch (§8) |
| 11 | Screen | `~kiosk/.xinitrc`, `~kiosk/.bash_profile`, X restricted to the console | **P10** |
| 12 | Checks | Runs `deploy/preflight.sh` | |

Options: `--no-packages` (offline re-run), `--no-kiosk` (scanner only),
`--boot` (also switch boot-to-standby on).

> If the installer added you to the `cyrberus` group, **log out and back in**
> (or reboot) before running the screen by hand.

**Time zone** — the screen shows "Good until 4:47 PM" in local time:
```bash
sudo timedatectl set-timezone America/Chicago
```

---

## 6. Verify

**PARAMOUNT (P9).** Before every demo:

```bash
sudo bash /opt/cyrberus/deploy/preflight.sh
```

It must end with `READY`. `[XX]` lines will break the Head and say how to fix
them; `[!!]` lines are worth knowing (unsynchronised clock, clamd still
loading). Then:

```bash
sudo bash /opt/cyrberus/tests/run_all.sh
```

must end with `ALL SUITES PASSED`. Run with `sudo`, it includes the
integration test that makes real mounts: on the Pi it builds a genuine FAT32
image and its last line must say **`(vfat)`**. It proves, against the real
kernel, that scan mounts are read-only/noexec/nosuid/nodev, that a validated
drive passes the Sentinel verifier, that tampering fails it, and that a
non-ASCII filename is recorded exactly.

**P3 check, by hand:** plug in any USB drive and run `lsblk -o NAME,FSTYPE,MOUNTPOINT`.
The drive's partition must show **no** mountpoint (unless the Head is
scanning it at that moment). Remove the drive.

**Engine check:**
```bash
clamdscan --version     # ClamAV 1.x.x/27xxx/<date>  - the middle number is the virus list version
```
No middle number = clamd is still loading signatures (about a minute after
boot) or has no database yet (`sudo systemctl status clamav-freshclam`).

---

## 7. Try it by hand (development mode)

Development mode is the default after installation: nothing starts by itself.
The full demo procedures — simulation, live scanning, test media — are in
[`DEMO.md`](DEMO.md). The short version, on the Pi's own console (keyboard
and screen, not SSH — X needs the physical console):

```bash
# SSH session: the daemon
sudo -u cyrberus /opt/cyrberus/venv/bin/python3 /opt/cyrberus/head/daemon.py -v

# Pi console (logged in as <admin>): the screen, with its window manager
cp /opt/cyrberus/deploy/cyrberus-kiosk.xinitrc ~/.xinitrc
startx
```

Escape closes the screen and returns to the console.

> The daemon printing `ready` and then **sitting there is normal** — it is
> waiting for a USB insertion. Insert a drive and watch it work.

---

## 8. Boot-to-standby (the hands-off mode)

For the final demonstrations and deployment: power on, and within a minute
the screen says **"Insert your USB drive"** with nobody touching anything.

```bash
sudo bash /opt/cyrberus/deploy/boot-mode.sh on
sudo reboot
```

What you will see after power-on:

| Time | Screen | Meaning |
|---|---|---|
| 0–30 s | boot text | Pi starting |
| ~30 s | "Checking is unavailable" (briefly) | screen started before the scanner published its first status |
| ~35 s | **"Insert your USB drive"** · *Virus list not ready yet* | scanner running; ClamAV loading signatures |
| 1–2 min | **"Insert your USB drive"** · *Virus list version 27xxx* | **ready to check drives** |

**PARAMOUNT (P8).** Wait for the version number. A drive inserted before it
appears is refused with "The checking service is not available right now" —
correct, fail-closed, but not what you want in front of an audience.

A drive that was **already plugged in during boot** is not checked silently;
the screen asks to *"Unplug this drive and plug it in again to check it."*

**The switch:**

```bash
sudo bash deploy/boot-mode.sh on          # standby at every boot
sudo bash deploy/boot-mode.sh on --now    # ...and switch to it right now, no reboot
sudo bash deploy/boot-mode.sh off         # back to development mode
sudo bash deploy/boot-mode.sh restart     # restart scanner + screen (after a git pull)
bash deploy/boot-mode.sh status           # what happens at boot, what runs now
```

**PARAMOUNT (P6).** With boot mode on, the scanner service owns the USB
ports. To run the daemon by hand, `sudo bash deploy/boot-mode.sh off` first
(or `sudo systemctl stop cyrberus-scanner`). A second daemon now refuses to
start with *"another Head daemon is already running"* — that message is the
safeguard working, not a fault.

**How it works under the hood** (useful when something does not appear):

```
power on
 ├─ systemd-tmpfiles ─► /run/cyrberus (0750 cyrberus:cyrberus)
 ├─ clamav-daemon ────► loads signatures (~1 min)
 ├─ cyrberus-scanner.service (User=cyrberus)
 │     daemon.py ─► waits for USB; writes /run/cyrberus/state.json every ≤5 s
 └─ getty@tty1 + autologin drop-in ─► logs in `kiosk` on the physical console
       ~kiosk/.bash_profile ─► startx            (tty1 only; never a shell)
       ~kiosk/.xinitrc ─────► matchbox + ui/kiosk.py (fullscreen, reads state.json)
```

If the screen process crashes or someone presses Escape, the session ends and
the autologin brings the screen back within a few seconds. Ctrl+C on the
console keyboard does not drop to a prompt.

---

## 9. Operating the Head

### 9.1 Logs and the threat reference code

```bash
journalctl -u cyrberus-scanner -f          # live, when running as the service
tail -f /var/log/cyrberus/head.log         # same events, as a file (group cyrberus can read)
grep H4-2291 /var/log/cyrberus/head.log    # what a threat screen's code refers to
```

The threat screen shows a short code (e.g. `H4-2291`) instead of a malware
name; the log line `DETECTION ref=H4-2291 sig=<signature> path=<file>` holds
the detail for IT.

### 9.2 Updating the code

On the laptop: commit and push. On the Pi:

```bash
cd /opt/cyrberus && git pull
sudo bash deploy/install-head.sh     # applies deploy/ changes; restarts the scanner only if its code changed
sudo bash deploy/boot-mode.sh restart  # if boot mode is on: also restarts the screen
```

### 9.3 The clock

**PARAMOUNT (P7).** Every manifest records when it was issued and when it
expires, and the Sentinel compares that expiry with the workstation's clock.

```bash
timedatectl status       # want: System clock synchronized: yes, and the right Time zone
```

- **Network time** is switched on by the installer and is enough whenever
  the Pi has network access.
- **No network at the demo venue?** The Pi boots with the time it last shut
  down at, so manifests would carry stale times. Either give it network
  briefly at startup, or fit a DS3231 RTC module (enable it with
  `dtoverlay=i2c-rtc,ds3231` in `/boot/firmware/config.txt`; follow the
  module's guide for your OS release).
- Preflight and `boot-mode.sh status` both warn when the clock is not
  synchronised.

### 9.4 Virus signature updates

`clamav-freshclam` downloads new signatures automatically whenever the Pi is
online, and the screen's "Virus list version" updates within a minute. Check:
`sudo journalctl -u clamav-freshclam -n 20`.

The production design keeps the Head off the internal network (requirement
SR3); how updates reach an isolated Head — cellular link, offline bundles, or
a data diode — is open decision **D5** in [HANDOFF.md](HANDOFF.md).

### 9.5 The signing key: export, rotate, never copy

**PARAMOUNT (P5).** `keys/head_private.pem` is the root of trust: anyone
holding it can approve any drive. It is plaintext protected by permissions
(mode 600, owner `cyrberus`, directory 700) — acceptable for a lab prototype,
documented as a limitation.

**Export the public key for Sentinels** (from Windows PowerShell):

```powershell
scp <admin>@<pi-ip>:/var/lib/cyrberus/head_public.pem .
scp <admin>@<pi-ip>:/var/lib/cyrberus/key_id.txt .
```

**Rotate** (after any suspected exposure, or before the final demo if the
key was ever handled carelessly):

```bash
sudo systemctl stop cyrberus-scanner                       # if running
sudo mv /opt/cyrberus/keys/head_private.pem /root/head_private.retired.pem
sudo mv /opt/cyrberus/keys/head_public.pem  /root/head_public.retired.pem
sudo bash /opt/cyrberus/deploy/install-head.sh             # generates a new pair, prints the new key_id
```

Then replace the public key in every Sentinel trust store and remove the old
one. Manifests signed by the old key stop verifying immediately; any still in
circulation expire within 12 hours anyway. Delete the retired files once
you are sure. If a private key was ever committed to git, rotating is the fix —
deleting the commit is not (history is recoverable).

### 9.6 Power and the SD card

**PARAMOUNT (P12).** `sudo poweroff`, wait for the green LED to stop, then
remove power. Pulling power mid-write is the most common way to corrupt a
Pi's SD card. Never pull a USB drive while the screen says *"Please leave the
drive plugged in."*

### 9.7 Site settings

`/etc/default/cyrberus` (created once, never overwritten):

```bash
CYRBERUS_HEAD_ID=head-01         # name written into manifests; one per Head; audit only
CYRBERUS_VALIDITY_HOURS=12       # the proposal commits to 12 h - change only as a team decision
```
Apply with `sudo systemctl restart cyrberus-scanner`.

---

## 10. Hardening checklist

| Item | Status | Notes |
|---|---|---|
| No desktop, no automounter (`udisks2` masked) | installer | P1, P3 |
| Scan mounts `ro,noexec,nosuid,nodev`; manifest write window still `noexec,nosuid,nodev` | built in | proved by the root integration test |
| Daemon unprivileged; only `mount`/`umount` via sudo | installer | |
| Screen account unprivileged, no password, console-only X | installer | P10 |
| systemd sandboxing: `ProtectSystem=full`, `ProtectHome`, `PrivateTmp`, code read-only | unit file | `NoNewPrivileges` must stay off (sudo) |
| ClamAV fail-closed settings | installer | P4 |
| Single-instance lock | built in | P6 |
| Admin login uses SSH keys, password login disabled | **manual** | from PowerShell: `ssh-keygen -t ed25519`, then `type $env:USERPROFILE\.ssh\id_ed25519.pub \| ssh <admin>@<pi-ip> "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"`; confirm key login works, then set `PasswordAuthentication no` in `/etc/ssh/sshd_config` |
| Firewall: allow SSH from the admin network only | **manual / future** | e.g. `ufw` |
| Narrow the mount privilege to a fixed-argument wrapper | **future (H1)** | today `cyrberus` may run *any* `mount`; see HANDOFF §8.12 |
| Private key in hardware (TPM / secure element) | **future (H2)** | today: plaintext + file permissions |
| Network isolation of the Head (SR3) | **open (D5)** | lab Head uses Wi-Fi for updates and SSH |

---

## 11. Troubleshooting

| Symptom | Cause → fix |
|---|---|
| Daemon prints `ready` and then nothing | **Normal.** It waits for a USB insertion. |
| Screen: "Checking is unavailable" | Daemon not running or not updating its status. `bash deploy/boot-mode.sh status`. If you run the screen by hand: are you in group `cyrberus` (log out/in after the installer added you)? |
| Screen: "Virus list not ready yet" for more than ~3 min | clamd down or no database: `systemctl status clamav-daemon clamav-freshclam` |
| "The checking service is not available right now" | clamd not answering — still loading after boot, or stopped (P8) |
| "Unplug this drive and plug it in again to check it." | The drive was attached before the daemon started. Re-insert it. |
| "This drive has more than one section on it." | Multi-partition drive — refused by design (hidden partitions are an evasion technique) |
| "This drive uses a format we cannot read." | Not FAT32/exFAT/NTFS (e.g. ext4, HFS+) — refused by design: a Windows Sentinel could not verify it |
| "Some files on this drive are too large or locked to be checked." | ClamAV could not see inside something (over size limits, encrypted archive/document). Fail-closed by design |
| "This drive could not be opened for checking." | Mount failed: `journalctl -u cyrberus-scanner -n 30`. NTFS: is `ntfs-3g` installed? An NTFS drive from a hibernated Windows PC ("Fast Startup") may refuse to mount — shut Windows down fully |
| "The approval could not be written to this drive." | Drive is write-protected (switch on SD adapters) or full |
| `another Head daemon is already running` | P6 — the boot service is on. `sudo bash deploy/boot-mode.sh off`, or stop the other terminal's daemon |
| Boot mode on, screen stays black | `cat /home/kiosk/kiosk-session.log` (X and screen errors); `bash deploy/boot-mode.sh status` |
| `Only console users are allowed to run the X server` | You started X from SSH. X runs on the Pi's own console (or use boot mode) — intentional (P10) |
| `PermissionError: '/run/cyrberus'` | Run the installer (installs the tmpfiles rule); or an old checkout — `git pull` |
| `findmnt` shows nothing while a drive is being scanned | Expected under the service: it has a private mount namespace. To look: `sudo nsenter -t $(systemctl show -p MainPID --value cyrberus-scanner) -m findmnt /mnt/cyrberus-scan` |
| Service fails to start | `systemctl status cyrberus-scanner`, `journalctl -u cyrberus-scanner -b`. To rule out the sandboxing, temporarily: `sudo systemctl edit cyrberus-scanner` → `[Service]` `ProtectSystem=no` `ProtectHome=no` `PrivateTmp=no` `ReadOnlyPaths=` — and report what fixed it |
| Clean drive, but expiry time on the screen is wrong | Clock or timezone (P7) |
| `/bin/bash^M: bad interpreter` | Windows line endings got in. `.gitattributes` prevents this; re-clone, or `sed -i 's/\r$//' <file>` |
| `git pull`: divergent branches | Something was committed on the Pi. `git pull --rebase`; then stop committing on the Pi |
| `git`: refusing to merge unrelated histories | Wrong folder / repo initialised twice. Fresh clone (§4) |
| `scp …cyrberus.local…` cannot resolve | Use the IP address from `hostname -I` |
| PowerShell: `The token '&&' is not a valid statement separator` | Windows PowerShell 5.1 — put each command on its own line |

---

## 12. Reference

### Accounts

| Account | Purpose | Login | Groups |
|---|---|---|---|
| `<admin>` | you; SSH, git pull, sudo | password/SSH key | `sudo`, `cyrberus` |
| `cyrberus` | runs the scanner daemon | none (`nologin`) | `cyrberus` |
| `kiosk` | shows the screen | console autologin only, no password | `cyrberus`, `video`, `input`, `render` |

### Files

| Path | Owner / mode | What |
|---|---|---|
| `/opt/cyrberus/` | `<admin>` 755 | the repository (P2) |
| `/opt/cyrberus/keys/head_private.pem` | `cyrberus` 600 (dir 700) | signing key (P5) |
| `/opt/cyrberus/venv/` | `<admin>` | Python environment |
| `/var/lib/cyrberus/head_public.pem`, `key_id.txt` | root 644 | public key export for Sentinels |
| `/run/cyrberus/state.json` | `cyrberus` 644 (dir 750) | live status the screen reads |
| `/var/log/cyrberus/head.log` | `cyrberus` (dir 750) | daemon log |
| `/mnt/cyrberus-scan` | `cyrberus` 750 | where drives are mounted for checking |
| `/run/lock/cyrberus-head.lock` | — | single-instance lock |
| `/etc/systemd/system/cyrberus-scanner.service` | root | the service |
| `/etc/default/cyrberus` | root | site settings (§9.7) |
| `/etc/sudoers.d/cyrberus` | root 440 | mount privilege |
| `/etc/tmpfiles.d/cyrberus.conf` | root | recreates runtime dirs at boot |
| `/etc/systemd/system/getty@tty1.service.d/autologin.conf` | root | boot mode on only |
| `/home/kiosk/.xinitrc`, `.bash_profile`, `kiosk-session.log` | `kiosk` | screen session |
| `/etc/clamav/clamd.conf` (+ `.pre-cyrberus` backup) | root | scanner settings |

### Commands

```bash
sudo bash /opt/cyrberus/deploy/install-head.sh [--dry-run]   # set up / update
sudo bash /opt/cyrberus/deploy/preflight.sh [--fix]          # check
bash /opt/cyrberus/deploy/boot-mode.sh status                # what runs
sudo bash /opt/cyrberus/deploy/boot-mode.sh on|off|restart   # standby switch
sudo bash /opt/cyrberus/tests/run_all.sh                     # all tests incl. real mounts
journalctl -u cyrberus-scanner -f                            # live log
sudo poweroff                                                # P12
```
