# Running the Head demo

Two ways to run it. Simulation needs nothing but a screen — use it to show the
operator experience or to work on the UI. Live mode does the real thing.

---

## 1. Install the graphical layer (once)

Raspberry Pi OS Lite has no GUI. This adds a bare X server and one window
manager — about 45 MB, against roughly 900 MB for a full desktop, and
critically no file manager, so nothing starts automounting drives again.

```bash
sudo apt install --no-install-recommends -y \
    xserver-xorg xinit x11-xserver-utils \
    matchbox-window-manager python3-tk unclutter fonts-dejavu-core
```

`python3-tk` is the one people miss — Tkinter ships with Python on most
distributions but Debian splits it into its own package, so the UI fails at
the import line without it.

Confirm the venv can see it:

```bash
/opt/cyrberus/venv/bin/python3 -c "import tkinter; print('tk', tkinter.TkVersion)"
```

---

## 1b. Runtime directories

The daemon publishes its state to `/run/cyrberus`. Under systemd the service
unit creates that directory automatically. Started by hand it does not exist,
and `/run` is root-owned, so the daemon falls back to your per-user runtime
directory and prints which path it chose:

```
INFO  state file: /run/user/1000/cyrberus/state.json
```

The UI resolves the same way and prints what it is watching. If the two ever
disagree, set `CYRBERUS_STATE` on both:

```bash
CYRBERUS_STATE=/tmp/cyrberus-state.json python3 head/daemon.py --simulate
CYRBERUS_STATE=/tmp/cyrberus-state.json python3 ui/kiosk.py --windowed
```

To have the system directories exist from boot regardless of how the daemon is
started:

```bash
sudo cp deploy/tmpfiles.d-cyrberus.conf /etc/tmpfiles.d/cyrberus.conf
sudo systemd-tmpfiles --create
```

---

## 2. Simulation — no hardware, no scanning

Two terminals, or one over SSH and the UI on the attached screen.

```bash
# terminal 1: cycle through every screen
python3 head/daemon.py --simulate

# terminal 2 (or on the Pi's display)
python3 ui/kiosk.py --windowed
```

The daemon walks ready → scanning → hashing with a live progress bar → clean →
threat → blocked, and loops. Nothing is mounted and no drive is touched.

`--windowed` gives an 800×480 window; drop it for fullscreen. `Escape` quits.

This is the mode to use when showing the interface to someone, or when working
on the screens themselves.

---

## 3. Live — the real pipeline

### Prerequisites

Run the preflight rather than checking by hand:

```bash
bash deploy/preflight.sh            # report only
sudo bash deploy/preflight.sh --fix # create and chown what is missing
```

It verifies the service account, key permissions, the three directories, the
sudoers rule, ClamAV and its fail-closed setting, that no automounter is
running, and the Python dependencies. Re-run without `--fix` until it says
READY.

The daemon must run as the `cyrberus` account, not your login — the sudoers
rule granting mount privileges names that account specifically:

```bash
sudo -u cyrberus /opt/cyrberus/venv/bin/python3 /opt/cyrberus/head/daemon.py -v
```

<details>
<summary>What preflight checks, manually</summary>


- ClamAV running: `systemctl is-active clamav-daemon`
- Keys present: `ls -l /opt/cyrberus/keys/`
- Sudoers rule installed (`deploy/sudoers.d/cyrberus`)
- Mountpoint exists: `sudo mkdir -p /mnt/cyrberus-scan && sudo chown cyrberus:cyrberus /mnt/cyrberus-scan`

</details>

### Run it

```bash
# terminal 1
sudo -u cyrberus /opt/cyrberus/venv/bin/python3 /opt/cyrberus/head/daemon.py -v

# terminal 2
python3 ui/kiosk.py --windowed
```

Insert a single-partition FAT32 drive. You should see it identified, scanned,
hashed with real progress, and approved, and `.cyrberus/manifest.json` should
appear on the drive.

### Check the result

```bash
sudo mount -o ro /dev/sda1 /mnt/test
python3 sentinel/verify_manifest.py /mnt/test /opt/cyrberus/keys/head_public.pem
# PASS: valid until ... (N files)
```

---

## 3b. Preparing test media

**No formatting required.** Most USB sticks are already FAT32 or exFAT with a
single partition, which is exactly what the Head admits. Use drives you have.

### The clean drive

Any single-partition FAT32/exFAT stick with a handful of ordinary files on it.
Check what you have:

```bash
lsblk -o NAME,FSTYPE,SIZE,LABEL,MOUNTPOINT
```

One partition line under the disk, `vfat` or `exfat`, is what you want. Two
partition lines means that drive is your "cannot check" demo instead.

### The infected drive

Use EICAR, the industry-standard test string every scanner detects. It is not
malware and does nothing. Never use real malware for a demo.

Create it **on the Pi** — downloading it on Windows just makes Defender
quarantine it before you can copy it anywhere.

With the daemon stopped:

```bash
sudo mkdir -p /mnt/prep
sudo mount /dev/sda1 /mnt/prep
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
  | sudo tee /mnt/prep/invoice.txt > /dev/null
sync && sudo umount /mnt/prep
```

Confirm it is the real thing — the file must be exactly 68 bytes:

```bash
sudo mount /dev/sda1 /mnt/prep
wc -c /mnt/prep/invoice.txt          # 68
clamdscan /mnt/prep/invoice.txt      # ... FOUND
sudo umount /mnt/prep
```

Check `/dev/sda1` is really your stick with `lsblk` first. It is almost
certainly `sda1`, since the Pi boots from `mmcblk0`.

### The tampered drive

Validate a clean drive, then add a file to it afterwards and let the verifier
reject it. Covered in the demo table below.

---

## 4. A demo script that lands

Four drives, in this order. The last two are what make the point.

| # | Drive | Expected | What it shows |
|---|---|---|---|
| 1 | Ordinary FAT32 stick with a few documents | **Clean** | The happy path, with a real progress bar |
| 2 | Same drive, now with a file added by hand afterwards | Sentinel **denies** | Validation binds to contents, not to the drive |
| 3 | Drive with the EICAR test file | **Threat** + reference code | Detection, and no manifest is written |
| 4 | The two-partition drive from the verification checklist | **Cannot check** | A hidden second partition can't slip past |

For #2, show the denial with the verifier rather than a Sentinel — the endpoint
agent isn't built yet, and `verify_manifest.py` is the same logic it will use.

For #3, get the EICAR file with:

```bash
curl -s https://secure.eicar.org/eicar.com.txt -o /path/to/drive/eicar.txt
```

It's a harmless industry-standard test string that every scanner flags. Don't
use real malware for a demo.

---

## 5. Autostart (for a hands-off demo)

```bash
sudo cp deploy/cyrberus-scanner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cyrberus-scanner
systemctl status cyrberus-scanner
```

For the UI, enable console autologin for the `kiosk` account and install
`deploy/cyrberus-kiosk.xinitrc` as `~kiosk/.xinitrc`, with this appended to
`~kiosk/.bash_profile`:

```sh
if [ -z "$DISPLAY" ] && [ "$(tty)" = "/dev/tty1" ]; then
  exec startx -- -nocursor
fi
```

X sessions started directly from systemd are unreliable on a Pi; autologin plus
`.xinitrc` is the arrangement that works.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| UI shows "Checking is unavailable" | Daemon isn't running, hasn't published in 15 s, or the two are using different state paths - compare the paths each prints at startup |
| `PermissionError: '/run/cyrberus'` | Old build. Pull the latest; the path now falls back automatically |
| `ModuleNotFoundError: tkinter` | `python3-tk` not installed |
| Daemon logs "clamdscan not found" | ClamAV not installed, or at a different path — set `scanner.CLAMDSCAN` |
| Drive mounts on its own | An automounter came back; check `udisks2` isn't installed |
| "mount: only root can do that" | Sudoers rule missing or the daemon isn't running as `cyrberus` |
| Nothing happens on insert | Daemon only watches `ID_BUS=usb` disks; check `udevadm monitor` |

Logs: `/var/log/cyrberus/head.log`, or `journalctl -u cyrberus-scanner -f`.
