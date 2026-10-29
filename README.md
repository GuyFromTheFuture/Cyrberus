# Project Cyrberus

An open-source gatekeeper for removable media threats, built on commodity hardware.

Cyrberus validates USB storage devices at a controlled checkpoint and enforces that validation at the endpoint. Workstations deny USB storage by default and mount a device only when it carries a current, cryptographically signed manifest proving its contents were inspected and have not changed since.

**Status:** in development. Senior capstone project, [institution], [term].

---

## Why

Removable media bypasses the controls organizations invest in most heavily — email filtering, web gateways, and perimeter defenses are irrelevant to a device carried through the front door. Honeywell's 2024 USB Threat Report found 51% of analyzed malware is designed to spread via USB, up from 9% in 2019.

The checkpoint-validation architecture that addresses this is sold commercially by OPSWAT and Honeywell, priced and packaged for NERC-CIP-regulated industrial operators. School districts, municipal governments, and small businesses face a comparable threat with neither the budget nor the compliance-driven funding.

Cyrberus is not a novel mechanism. It is an open-source, auditable implementation of a proven one, targeted at the organizations the commercial market does not serve. See `docs/` for the full background and prior-art comparison.

---

## Architecture

```
   ┌──────────────┐                        ┌──────────────┐
   │   THE HEAD   │   signed manifest      │   SENTINEL   │
   │              │   written to device    │              │
   │  scan        │ ─────────────────────► │  verify      │
   │  hash        │                        │  deny by     │
   │  sign        │                        │  default     │
   └──────┬───────┘                        └──────┬───────┘
          │                                       │
          │           ┌──────────────┐            │
          └──────────►│  THE WARDEN  │◄───────────┘
             events   │  audit log   │   events
                      │  key policy  │
                      └──────────────┘
```

**The Head** — a Raspberry Pi at a physical checkpoint, off the internal network. Scans a device, and on a clean result writes a manifest of SHA-256 file hashes signed with its Ed25519 private key.

**The Sentinel** — an endpoint agent. Workstations deny USB storage by default; the Sentinel verifies the manifest signature, checks expiry, re-hashes the contents, and mounts read-only only if everything matches.

**The Warden** — audit and policy. Receives validation and mount events, holds configuration, supports key distribution and revocation.

Trust is bound to **file contents**, never to device identity — USB descriptors are self-reported by the device and trivially forged.

---

## Repository layout

```
cyrberus/
├── docs/
│   ├── MANIFEST_FORMAT.md     Frozen contract between Head and Sentinel
│   ├── SETUP_HEAD.md          Pi provisioning and hardening
│   ├── THREAT_MODEL.md        Assets, attack surface, residual risk
│   └── reports/               Proposal, progress reports, presentation
├── common/
│   └── manifest_lib.py        Shared format logic
├── head/                      Scanner node (Linux / Raspberry Pi)
│   ├── daemon.py              udev monitoring, mount control, orchestration
│   ├── scanner.py             ClamAV integration
│   ├── mounts.py              Read-only mount handling
│   ├── sign_manifest.py       Manifest generation and signing
│   └── keygen.py              One-time Ed25519 keypair generation
├── sentinel/                  Endpoint agent (Windows)
│   └── verify_manifest.py     Reference verifier
├── warden/                    Audit and policy service
├── ui/
│   └── kiosk.py               Head's fullscreen operator interface
├── tests/
│   └── test_manifest.py       Round-trip and tamper cases
└── deploy/
    ├── cyrberus-scanner.service
    ├── clamd.conf.d/
    └── xinitrc
```

Component directories map to team ownership, which keeps merge conflicts rare.

---

## Quick start (Head)

Full provisioning in `docs/SETUP_HEAD.md`. In brief:

```bash
git clone git@github.com:<org>/cyrberus.git /opt/cyrberus
cd /opt/cyrberus
python3 -m venv venv && source venv/bin/activate
pip install -r head/requirements.txt
sudo -u cyrberus venv/bin/python3 head/keygen.py
```

Requires Raspberry Pi OS Lite 64-bit with ClamAV configured per the setup guide.

### Tests

```bash
python3 tests/test_manifest.py
```

---

## Security notes

The Head's private key is the root of trust. `keys/` and `*.pem` are gitignored; **never commit a private key.** If one is committed, rotate it rather than deleting the commit — git history is recoverable.

Malware samples used in testing stay offline. Do not commit them.

Known limitations, including TOCTOU exposure, clock dependence, and the absence of HID/BadUSB coverage, are documented in `docs/THREAT_MODEL.md` and `docs/MANIFEST_FORMAT.md` §8. This is a laboratory prototype and has not undergone the hardening production deployment would require.

---

## Team

| Component | Owner |
|---|---|
| Head — scanning, mount control | [name] |
| Sentinel — endpoint enforcement | [name] |
| Cryptography, Warden, integration | [name] |

---

## License

MIT — see `LICENSE`.
