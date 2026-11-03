# Project Cyrberus

An open-source gatekeeper for removable media threats, built on commodity hardware.

Cyrberus validates USB storage devices at a controlled checkpoint and enforces that validation at the endpoint. Workstations deny USB storage to their users by default and release a drive's contents only when it carries a current, cryptographically signed manifest proving those contents were inspected and have not changed since.

**Status:** senior capstone project, [institution], [term].

| Component | State |
|---|---|
| **Head** (validation node) | **Working** — detects, scans, hashes, signs; kiosk screen; boots straight to standby |
| **Sentinel** (endpoint agent) | **Design ready, build starting** — reference verifier and test vectors in this repo |
| **Warden** (audit and policy) | Not started |

> **New to the project — person or AI assistant? Start with [`docs/HANDOFF.md`](docs/HANDOFF.md).**
> It holds the whole idea, the requirements, every decision and the Sentinel starting point in one file.

---

## Why

Removable media bypasses the controls organizations invest in most heavily — email filtering, web gateways, and perimeter defenses are irrelevant to a device carried through the front door. Honeywell's 2024 USB Threat Report found 51% of analyzed malware is designed to spread via USB, up from 9% in 2019.

The checkpoint-validation architecture that addresses this is sold commercially by OPSWAT and Honeywell, priced and packaged for NERC-CIP-regulated industrial operators. School districts, municipal governments, and small businesses face a comparable threat with neither the budget nor the compliance-driven funding.

Cyrberus is not a novel mechanism. It is an open-source, auditable implementation of a proven one, targeted at the organizations the commercial market does not serve.

---

## Architecture

```
   ┌──────────────┐   signed manifest      ┌──────────────┐
   │   THE HEAD   │   written to the drive │   SENTINEL   │
   │  Raspberry Pi│ ─────────────────────► │  Windows     │
   │  scan · hash │                        │  verify ·    │
   │  sign        │                        │  deny users  │
   └──────┬───────┘                        └──────┬───────┘
          │           ┌──────────────┐            │
          └──────────►│  THE WARDEN  │◄───────────┘
             events   │  audit log   │   events
                      │  key policy  │
                      └──────────────┘
```

**The Head** — a Raspberry Pi at a physical checkpoint. Scans a drive with ClamAV and, on a clean result, writes `.cyrberus/manifest.json` (SHA-256 of every file, a 12-hour expiry) signed with its Ed25519 key. A fullscreen kiosk tells the person at the checkpoint what happened in plain language.

**The Sentinel** — an agent on each workstation. People cannot open USB storage; the Sentinel, running as a system service, verifies the manifest's signature and expiry, re-hashes every file, and releases the contents only if everything matches.

**The Warden** — audit and policy: collects validation and verification events, distributes and revokes Head keys.

Trust is bound to **file contents**, never to device identity — USB descriptors are self-reported by the device and trivially forged.

---

## Repository layout

```
cyrberus/
├── README.md
├── docs/
│   ├── HANDOFF.md             START HERE - whole project, decisions, Sentinel starting point
│   ├── SETUP_HEAD.md          Building a Head from a blank SD card
│   ├── DEMO.md                Running demonstrations
│   ├── MANIFEST_FORMAT.md     Frozen contract between Head and Sentinel (schema 1)
│   └── reports/               Proposal, progress reports, presentation
├── common/
│   └── manifest_lib.py        Shared manifest format code
├── head/                      Validation node (Raspberry Pi OS)
│   ├── daemon.py              Orchestration: udev events, pipeline, states
│   ├── devices.py             Detection and admission rules
│   ├── mounts.py              Hardened read-only mounting
│   ├── scanner.py             ClamAV integration and verdicts
│   ├── state.py               Status file shared with the kiosk screen
│   ├── sign_manifest.py       Signing function + LAB tool for signed test drives (no scanning)
│   ├── keygen.py              One-time Head keypair (installer generates one if absent)
│   └── requirements.txt
├── ui/
│   └── kiosk.py               Fullscreen operator screen (Tkinter)
├── sentinel/
│   └── verify_manifest.py     Reference verifier - the Sentinel ports this
├── warden/                    (not started)
├── tests/
│   ├── run_all.sh             Every suite; with sudo, includes real mounts
│   ├── test_manifest.py       Signing round trip and tamper cases
│   ├── test_head.py           Admission, verdicts, state, boot behaviour
│   ├── test_ui.py             Every screen renders (no display needed)
│   ├── test_root_integration.py   Kernel-enforced mount hardening, end to end
│   ├── make_sentinel_fixtures.py  Golden test vectors for Sentinel developers
│   └── tkstub/                Headless Tk stand-in for test_ui
└── deploy/
    ├── install-head.sh        One-shot, idempotent Head installer
    ├── boot-mode.sh           Boot-to-standby switch (on/off/status/restart)
    ├── preflight.sh           Readiness check
    ├── cyrberus-scanner.service, cyrberus.default, tmpfiles.d-cyrberus.conf
    ├── sudoers.d/cyrberus, clamd.conf.d/cyrberus.conf
    └── cyrberus-kiosk.xinitrc, cyrberus-kiosk.bash_profile, getty-autologin.conf
```

---

## Quick start (Head)

On Raspberry Pi OS Lite 64-bit (full guide: [`docs/SETUP_HEAD.md`](docs/SETUP_HEAD.md)):

```bash
sudo git clone https://github.com/<owner>/<repo>.git /opt/cyrberus
sudo chown -R "$USER":"$USER" /opt/cyrberus
sudo bash /opt/cyrberus/deploy/install-head.sh        # safe to re-run
sudo bash /opt/cyrberus/deploy/boot-mode.sh on        # optional: power on straight into standby
```

### Tests

```bash
bash tests/run_all.sh          # no hardware needed
sudo bash tests/run_all.sh     # on the Pi: adds real FAT32 mounts
```

---

## Security notes

The Head's private key is the root of trust. `keys/` and `*.pem` are gitignored; **never commit a private key.** If one is committed, rotate it rather than deleting the commit — git history is recoverable.

Test with the EICAR test file only. Real malware samples stay offline and out of this repository.

Known limitations — TOCTOU exposure, clock dependence, no HID/BadUSB coverage, the plaintext key — are documented in [`docs/HANDOFF.md`](docs/HANDOFF.md) §12 and [`docs/MANIFEST_FORMAT.md`](docs/MANIFEST_FORMAT.md) §8. This is a laboratory prototype and has not undergone the hardening a production deployment would require.

---

## Team

| Component | Owner |
|---|---|
| Head — scanning, mount control, kiosk | [name] |
| Sentinel — endpoint enforcement | [name] |
| Cryptography, Warden, integration | [name] |

---

## License

MIT — see `LICENSE`.
