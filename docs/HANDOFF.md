# Project Cyrberus — Handoff and Continuation Guide

**Purpose:** everything needed to continue Project Cyrberus without the people or the chat history that built the Head: the whole idea, the goals and requirements, how the Head works in detail, every decision made or still open, and a researched starting point for the Sentinel.
**Audience:** the two teammates building the Sentinel, and any AI assistant (ChatGPT, Claude, other) they work with.
**State as of:** 30 October 2026. Head complete and tested; Sentinel not started; Warden not started.
**Single-file by design:** an assistant given only this file can understand the project, plan, and write documentation correctly. For **porting the verifier** it also has the exact reference source in Appendix C. `docs/MANIFEST_FORMAT.md` is the normative source for the manifest; §9 summarises it, and where wording differs, MANIFEST_FORMAT.md wins.

---

## 0. Read me first

### 0.1 For people
Read §3 (the idea), §5 (requirements), §10 (the Sentinel starting point) and §15 (next steps) first. Everything else is reference. To work with an AI assistant, give it this whole file and use a prompt from §20.

### 0.2 For AI assistants — ground rules
You are helping a three-person undergraduate cybersecurity capstone team. Before doing any task, follow these rules; they override general habits.

1. **Do not change the manifest format** (§9) silently. Schema 1 is frozen. Any change to fields, serialization or the verification algorithm requires a new schema number *and* changes to both Head and Sentinel. If a task seems to need one, stop and say so.
2. **Fail closed, always.** Any error, exception, timeout or unknown condition in the Head or the Sentinel must result in *deny / not approved*, never in a silent pass.
3. **Never trust device identity.** USB vendor ID, product ID and serial number are self-reported by the device. Record them for audit; never use them in a trust decision.
4. **Verify before parse.** The Sentinel verifies the Ed25519 signature over the raw manifest bytes *before* treating any manifest content as trusted (§9.3).
5. **Private keys never move.** Never suggest copying a Head's private key off the Pi, committing it, emailing it, or pasting it into a chat. Only public keys are distributed.
6. **EICAR only.** Never produce, fetch or suggest real malware samples. The EICAR test string is the only "malware" used in this project.
7. **Disclosure integrity.** Never attribute an attack or incident to a named organization unless it was publicly disclosed and you can cite the source. The team's original motivation included an unverified, privately relayed anecdote about a school; it must never be named or presented as fact.
8. **Respect PARAMOUNT items** (§2). Do not propose shortcuts that weaken them.
9. **Keep it buildable by students.** Prefer policy and user-mode code over kernel drivers; prefer Python (the team's language); explain Windows administrative steps precisely.
10. **Say what you are unsure of.** Several Windows behaviours below are marked *SPIKE* — they must be tested on a real machine before being relied on. Do not present them as settled.

### 0.3 Conventions in this document
- **PARAMOUNT** — crucial for correct or secure operation. Listed in §2.
- Status words: **DONE**, **PARTIAL**, **NOT STARTED**, **OPEN** (decision not yet made), **SPIKE** (must be tested before relying on it).
- IDs: `O`/`FR`/`SR`/`NFR` = proposal requirements (verbatim); `HEAD-`/`SEN-`/`WAR-` = component requirements; `L` = locked decision; `D` = open decision; `H` = hardening backlog; `P`/`SP` = PARAMOUNT items.
- Placeholders: `<admin>` (login on the Pi), `<pi-ip>`, `<owner>/<repo>` (GitHub), `[Member 1–3]`.

---

## 1. Project at a glance

```yaml
project: Project Cyrberus
one_line: Open-source checkpoint validation for USB storage - a Pi scans and signs, workstations verify before releasing contents.
context: Senior capstone, B.S. Cybersecurity, team of 3, fall 2026
name_origin: Cerberus, the three-headed guardian of the gate (three components); "Cyr" for cyber
threat_addressed: Removable media threats, including USB drop attacks (MITRE ATT&CK T1091, T1052.001, T1200)
target_users: K-12 districts, municipal governments, small businesses (cannot afford commercial kiosks)
components:
  head:
    role: validation node at a physical checkpoint
    platform: Raspberry Pi 4 Model B 8 GB (design target 4 GB), Raspberry Pi OS Lite 64-bit
    status: DONE (scan, hash, sign, kiosk screen, boot-to-standby, installer, tests)
    stack: Python 3 (venv), ClamAV clamd/clamdscan, pyudev, cryptography (Ed25519), Tkinter + X + matchbox, systemd
  sentinel:
    role: endpoint agent on Windows 10/11; users denied USB storage; agent verifies and releases contents
    status: NOT STARTED (design recommended, reference verifier + 16 golden test vectors + lab signing tool ready)
    recommended_design: "C - SYSTEM service verifies the manifest and copies verified bytes to a user inbox in one hashing pass"
  warden:
    role: audit log + key distribution/revocation
    status: NOT STARTED (scope is open decision D8)
manifest:
  location_on_drive: .cyrberus/manifest.json + .cyrberus/manifest.sig
  schema: 1 (FROZEN)
  hash: SHA-256 per file
  signature: Ed25519, detached, over the literal manifest bytes, base64 in manifest.sig
  validity: 12 hours
admission_rules: USB-attached storage (flash drives and USB hard drives); exactly one partition; FAT32, exFAT or NTFS; not encrypted
repo_layout_root: /opt/cyrberus on the Pi; GitHub <owner>/<repo>; MIT licence
tests: 124 checks in 4 suites, all passing (23 manifest, 51 head, 21 ui, 29 root integration) + 16 Sentinel golden vectors
top_open_decisions: [D1 Sentinel delivery model, D3 Windows enforcement scope, D4 Windows writing to drives, D5 Head update path]
next_milestone: Sentinel spike (weeks 1-2) - prove a SYSTEM service can read a drive users are denied
```

---

## 2. PARAMOUNT index

### Head (operational)
| ID | Rule |
|---|---|
| P1 | Raspberry Pi OS **Lite 64-bit** only — a desktop brings an automounter; 32-bit cannot hold ClamAV's database |
| P2 | Repository at **`/opt/cyrberus`** — the service, screen and permissions assume it |
| P3 | **Nothing but the Head mounts a drive** — `udisks2` masked, no desktop |
| P4 | ClamAV **fails closed** — `AlertExceedsMax yes`, `AlertEncrypted*` on |
| P5 | The **private key never leaves the Pi** (mode 600, owner `cyrberus`); exposed → rotate |
| P6 | **One Head daemon at a time** — the daemon enforces it with a lock (if the lock file itself cannot be opened, it warns and continues, so still stop the service before hand-running) |
| P7 | **Correct clock and timezone** — manifests carry issue/expiry times |
| P8 | Accept drives only after the screen shows **"Virus list version N"** |
| P9 | **Preflight READY** before every demo |
| P10 | Screen account `kiosk`: **no password, no sudo**; X from the physical console only |
| P11 | **EICAR only**; no real malware anywhere |
| P12 | **`sudo poweroff`**, never pull power mid-write |
| P13 | Distribute only the **public** key (`/var/lib/cyrberus/head_public.pem`) |
| P14 | **Manifest schema 1 is frozen** — changes need a new schema and both halves updated |

### Sentinel (design)
| ID | Rule |
|---|---|
| SP1 | **Deny-by-default applies to people, not to the Sentinel.** Block users' access; never block the drive at the driver level, or the Sentinel cannot read it either (§10.1) |
| SP2 | Workstation users are **standard users** — an administrator can undo every control below |
| SP3 | **Windows must never write to USB storage** — not before verification (its housekeeping files would break the manifest) and not after (the drive would fail at the next workstation within its 12 hours) (D4) |
| SP4 | **Verify the signature over raw bytes before parsing**; follow the normative order (§9.3) |
| SP5 | **Release only bytes that were hashed** — hash while copying, in one pass (closes TOCTOU for delivered content) |
| SP6 | Trust store and Sentinel binaries **writable only by Administrators/SYSTEM** — otherwise users can trust their own "Head" |
| SP7 | **Fail closed** on any exception, timeout or surprise |
| SP8 | Copy **only the main data stream** of each file (no NTFS alternate data streams); **never execute** anything from a drive |
| SP9 | Workstation clock synchronised and **users cannot change the time** |
| SP10 | **Never use VID/PID/serial for trust** |

---

## 3. Cyrberus in one page

**The problem.** A USB drive walks past every network defence an organization owns. Attackers seed infected drives (USB drop attacks), mail them, or — far more often — infect a drive a person legitimately carries (a conference handout, a vendor's update stick, a teacher's own drive used at home). Small organizations have two bad options: ban USB storage (unenforceable, obstructs work) or allow it (accept the risk). The architecture that solves this — a scanning kiosk that marks drives plus an endpoint agent that refuses unmarked drives — exists only as expensive proprietary appliances (OPSWAT MetaDefender Kiosk + Media Validation Agent; Honeywell Secure Media Exchange) aimed at regulated industrial operators.

**The idea.** Build that architecture openly, on a ~$100–200 Raspberry Pi, for the organizations that cannot buy it.

**How it works, as a story.**
1. A teacher walks to the technology office with a USB drive and plugs it into the **Head**, a Raspberry Pi with a screen that says *"Insert your USB drive."*
2. The Head checks the drive is something it can verify (one partition; FAT32/exFAT/NTFS; not encrypted), mounts it read-only and non-executable, scans every file with ClamAV, and computes a SHA-256 hash of every file.
3. If clean, it writes a **manifest** — the list of every file and its hash, the Head's ID, and an expiry 12 hours away — onto the drive, signed with the Head's private Ed25519 key. The screen says *"Your drive is clean — Good until 4:47 PM."* If not, it says *"Do not use this drive"* with a reference code for IT, or *"We cannot check this drive"* with a plain reason.
4. Back at a classroom workstation, the teacher cannot open the drive: USB storage is denied to users by policy. The **Sentinel**, a service running with system privileges, checks the manifest's signature against the Heads it trusts, checks the expiry, confirms the drive holds exactly the files listed with exactly the listed hashes, and only then releases the contents to the teacher.
5. Every validation and every verification is logged; the **Warden** collects those logs and manages which Head keys are trusted.

**Why it holds.** The signature means only a trusted Head can create a manifest. The hashes mean any change — a file added, removed or altered after scanning — is detected. Trust is bound to the *contents*, never to the drive's claimed identity, so cloning or spoofing a drive gains nothing. The 12-hour lifetime bounds how long a validated drive stays trusted, the same reasoning as **Kerberos ticket lifetimes**.

**What it does not claim.** Not novel — the contribution is an open, auditable, affordable implementation. "Clean" means *no known malware at scan time and unchanged since*, never "safe". It does not address devices that pretend to be keyboards (HID/BadUSB), data leaving the organization on USB, or zero-day malware.

**The three heads of Cerberus.** Head (examines whoever arrives), Sentinel (guards each door), Warden (keeps the records).

---

## 4. Background, terminology, prior art

### 4.1 Terminology (use consistently)
- **Removable media threats** — the general term used throughout.
- **USB drop attack** — the specific case of a deliberately seeded or mailed device.
- Avoid **"dead drop"** as a technical term: MITRE ATT&CK uses *Dead Drop Resolver* (T1102.001) for an unrelated command-and-control technique.
- Relevant ATT&CK techniques: **T1091** Replication Through Removable Media; **T1052.001** Exfiltration over USB; **T1200** Hardware Additions.
- **"RSA"** in this document means Windows *Removable Storage Access* policies, **not** the RSA algorithm (the project uses Ed25519).

### 4.2 Evidence used in the proposal (re-verify citations before final submission)
- Honeywell GARD USB Threat Report 2024: 51% of analysed malware designed to spread via USB, up from 9% in 2019.
- Tischer et al., IEEE S&P 2016 ("Users really do plug in USB drives they find"): 297 drives dropped on a campus; files opened on 45%, 98% removed; first connected within six minutes; people plugged them in to find the owner.
- Operation Buckshot Yankee (2008): a flash drive infected U.S. Central Command networks; ~14 months of remediation; contributed to creating U.S. Cyber Command.
- FIN7 mailed malicious USB devices to U.S. transportation, insurance and defence companies (FBI alerts); the Texas Department of Information Resources circulated an advisory.
- ICS-CERT reports (2012): a turbine control system infected by a technician's update drive; Mariposa spread from a conference flash drive.
- Check Point Research 2023: a European hospital compromised via an employee's drive infected at a conference (WispRider/Camaro Dragon).
- Publicly reported cyber incidents affecting South Texas municipalities and school systems (2019–2025) are used only as evidence that such organizations are targeted — **not** as evidence of USB vectors.

### 4.3 Prior art and the contribution
| System | What it does | Gap Cyrberus fills |
|---|---|---|
| OPSWAT MetaDefender Kiosk + Media Validation Agent | Kiosk scans, writes signed hash manifest; endpoint agent blocks unvalidated media (since 2017) | Proprietary, priced for regulated industry |
| Honeywell Secure Media Exchange (SMX) | Comparable, industrial sites; adds device substantiation | Same |
| CIRCLean (CIRCL) | Pi-based sanitizer, converts files onto a second drive | No marking, no endpoint enforcement |
| USBGuard (Linux) | Device authorization by descriptor | No content inspection; trusts forgeable identity; Linux only |
| Windows Group Policy | Blanket removable-storage denial | All-or-nothing |
| Academic (GoodUSB, USBFilter, Cinch, LBM, USBlock) | Lower-layer USB defences | Research prototypes; different layer |

**Contribution:** accessibility and auditability, not conceptual originality. Regulatory context: NERC CIP-003-8 / CIP-010-4 R4 (transient cyber assets and removable media) and NIST SP 800-53 MP-7 / SI-3 drive the commercial market; schools and municipalities have the risk without the mandate.

---

## 5. Goals and requirements (the guideline)

### 5.1 Objectives — verbatim from the proposal, with status
| ID | Objective | Status | Evidence / remaining |
|---|---|---|---|
| O1 | Implement a validation node that scans USB mass-storage devices and writes a cryptographically signed manifest of approved content. | **DONE** | Head (§8); `tests/test_root_integration.py` |
| O2 | Implement an endpoint agent that denies USB storage by default and permits mounting only on successful manifest verification. | **NOT STARTED** | Sentinel (§10). Wording of "permits mounting" depends on D1 |
| O3 | Bind validation to file content rather than device identity, so that post-validation modification causes verification to fail. | **DONE at format and reference level**; enforcement on workstations arrives with the Sentinel (FR4) | `test_manifest.py`; fixtures `deny_file_*`, `deny_manifest_copied_to_other_drive` |
| O4 | Enforce a configurable validation lifetime, defaulting to twelve hours. | **DONE** (Head issues; reference verifier enforces) | `CYRBERUS_VALIDITY_HOURS`; fixture `deny_expired` |
| O5 | Log all validation and mount-attempt events centrally to support audit and incident response. | **PARTIAL** | Head logs locally; central collection = Warden (D8) |
| O6 | Deliver the system as open-source software on commodity hardware under [$X] in materials. | **PARTIAL** | MIT repo; Head < $200 — fill in [$X] |
| O7 | Evaluate the implementation against a defined threat model and report residual risk honestly. | **PARTIAL** | Threat model §12; evaluation pending Sentinel |

### 5.2 Requirements — verbatim from the proposal, with status
| ID | Requirement | Type | Status |
|---|---|---|---|
| FR1 | Scan connected device and classify contents as clean or malicious | Functional | **DONE** (plus a third class: *cannot check*) |
| FR2 | Generate and write a signed manifest to validated devices | Functional | **DONE** |
| FR3 | Deny mount of any device lacking a valid, unexpired manifest | Functional | Sentinel — **NOT STARTED** |
| FR4 | Recompute and compare content hashes at mount time | Functional | Reference verifier **DONE**; Sentinel **NOT STARTED** |
| SR1 | Manifests signed with a key held only by the validation node | Security | **DONE** (Ed25519, key mode 600, never exported) — caveat H2: plaintext on the SD card |
| SR2 | System fails closed on any component or verification failure | Security | Head **DONE**; Sentinel **NOT STARTED** (must follow SP7) |
| SR3 | Validation node isolated from the internal production network | Security | **OPEN** (D5) — lab Head uses Wi-Fi |
| NFR1 | Validation of a 16 GB device completes within [X] minutes | Nonfunctional | **To measure** — time ten runs on a full 16 GB drive |
| NFR2 | Endpoint agent operable without specialized security staff | Nonfunctional | Sentinel — design for zero user interaction |

### 5.3 Component requirements (derived; these guide the build)

**Head** (all DONE unless noted)
| ID | Requirement |
|---|---|
| HEAD-1 | Detect USB mass-storage insertion without user action; ignore the system's own disks |
| HEAD-2 | Admit only: USB-attached storage (flash drives *and* USB hard drives/SSDs — the kernel "removable" flag is deliberately not required), exactly one partition (or superfloppy), FAT32/exFAT/NTFS, not encrypted |
| HEAD-3 | Mount read-only with `noexec,nosuid,nodev`; never auto-mount |
| HEAD-4 | Scan every file with ClamAV; oversized/encrypted/unreadable content → not approved |
| HEAD-5 | Record every regular file (path, size, SHA-256); any symlink or special file → not approved |
| HEAD-6 | Sign the manifest with Ed25519; write it in a separate, brief read-write mount |
| HEAD-7 | Show status in plain language; never color alone; reference code for threats |
| HEAD-8 | Run unprivileged except for mount/umount |
| HEAD-9 | Survive restarts; start into standby at boot when enabled |
| HEAD-10 | Log every decision with enough detail for incident response |
| HEAD-11 | Signature updates without bridging networks — **OPEN (D5)** |

**Sentinel** (all NOT STARTED)
| ID | Requirement |
|---|---|
| SEN-1 | Users (non-administrators) cannot read, write or execute anything on USB storage by default (SP1, SP2) |
| SEN-2 | Detect drive arrival automatically, as a service, with no user action |
| SEN-3 | Verify per the normative algorithm (§9.3), in order; any failure → deny |
| SEN-4 | Release only verified bytes to the user (SP5); never execute drive content (SP8) |
| SEN-5 | Never use device descriptors for trust (SP10) |
| SEN-6 | Prevent Windows from writing to USB storage at all — before or after verification (SP3, D4) |
| SEN-7 | Tell the user, in plain language, what happened (Session 0 isolation: needs a user-session helper) |
| SEN-8 | Log every arrival, verdict and release to the Windows Event Log and a local file (for the Warden) |
| SEN-9 | Trust store of Head public keys, administrator-managed only (SP6) |
| SEN-10 | Fail closed on any exception, timeout, removal mid-operation (SP7) |
| SEN-11 | Work offline; no network needed to verify |
| SEN-12 | Pass all 16 golden test vectors (§10.10) |
| SEN-13 | Release files only to the user signed in at the console; nobody signed in → deny and log (§10.4) |

**Warden** (OPEN scope, D8)
| ID | Requirement |
|---|---|
| WAR-1 | Collect Head and Sentinel events centrally (O5) |
| WAR-2 | Distribute Head public keys to Sentinels; support revocation |
| WAR-3 | Tamper-evident storage of events |

### 5.4 Scope (from the proposal)
**In scope:** USB mass storage with FAT32/exFAT/NTFS; enforcement on Windows 10/11; malware detection; ingress protection; audit logging.
**Out of scope:** HID/BadUSB (keyboard-emulating devices); firmware analysis; data exfiltration (validation is ingress only); non-USB media; encrypted devices the Head cannot read. **Laboratory prototype**, not production-hardened.

### 5.5 Success criteria — proposal §7 test plan, mapped
| Requirement | Method | Expected | Where it is (or will be) tested |
|---|---|---|---|
| FR1 | Scan device seeded with EICAR | flagged, rejected, no manifest | `test_root_integration.py` (stubbed engine); live demo drive 3 |
| FR3 | Device with no manifest | denied + logged | fixture `deny_no_manifest`; Sentinel |
| FR4 | Modify, add, delete files after validation | fails in all three | `test_manifest.py`; fixtures `deny_file_*`; demo drive 2 |
| O3 | Copy valid manifest to another device | fails | fixture `deny_manifest_copied_to_other_drive` |
| O4 | Present device after lifetime | denied | fixture `deny_expired` |
| SR2 | Kill agent; corrupt manifest and signature | denial every time | fixtures `deny_corrupt_signature`, `deny_manifest_edited`; Sentinel kill test |
| NFR1 | Time 16 GB validation ×10 | mean within [X] | to do on the Pi |
| Security | TOCTOU device; local admin disables Sentinel | findings reported honestly | §12.4 |

---

## 6. Architecture

```
                         PHYSICAL CHECKPOINT                         |        PROTECTED WORKSTATION (Windows)
                                                                     |
  person + USB drive                                                 |   person + validated drive
        │                                                            |          │
        ▼                                                            |          ▼
 ┌───────────────────── HEAD (Raspberry Pi) ─────────────────┐       |  ┌──────────────── SENTINEL ─────────────────┐
 │ udev ─► daemon.py (user cyrberus)                         │       |  │ Windows mounts volume; USERS are denied   │
 │          admit ─► mount ro,noexec ─► clamdscan ─► hash    │       |  │ (Removable Storage Access policy)         │
 │          ─► sign (Ed25519) ─► brief rw mount ─► write     │       |  │ Sentinel service (LocalSystem):           │
 │             .cyrberus/manifest.json + manifest.sig        │       |  │  verify sig ─► expiry ─► file sets ─►     │
 │          ─► state.json ─► kiosk.py (user kiosk) screen    │       |  │  hash-while-copying ─► user's Inbox       │
 │ private key: /opt/cyrberus/keys (600)                     │       |  │ trust store: ProgramData\...\trusted_heads│
 └──────────────┬────────────────────────────────────────────┘       |  └──────────────┬────────────────────────────┘
                │ public key (once, by hand / Warden)                |                 │ events
                └──────────────────────────────────────────────────────────────►  ┌──────────┐ ◄┘
                                     events ─────────────────────────────────────►│  WARDEN  │ (not built)
                                                                                  └──────────┘
 TRUST BOUNDARIES: (1) the drive is untrusted everywhere until verified; (2) the Head's private key is the root of trust;
 (3) on the workstation, the user is untrusted relative to the Sentinel (standard user, SP2).
```

**Chain of trust:** Head private key → signature over manifest bytes → manifest lists `{path, size, sha256}` for every file → bytes on the drive. Break any link → deny.

**Data flow (Head):** insert → `WORKING/identifying` → admit → mount ro → `WORKING/scanning` → verdict → `WORKING/hashing` (progress) → `WORKING/signing` → unmount → mount rw → write manifest + sig → unmount → `CLEAN` → remove → `READY`.

---

## 7. Decision log

### 7.1 Locked decisions
| ID | Decision | Why | Where |
|---|---|---|---|
| L1 | Trust bound to content (SHA-256 per file), never device identity | Descriptors are forgeable | MANIFEST_FORMAT §7.1 |
| L2 | Ed25519 detached signature over the literal manifest bytes | Avoids canonical-JSON bugs; 64-byte signatures; fast | §9 |
| L3 | 12-hour validity | One working day; bounded bearer credential (Kerberos analogy) | proposal O4 |
| L4 | `.cyrberus/manifest.json` + `.sig` at partition root; schema 1 frozen | Simple; matches commercial practice | MANIFEST_FORMAT |
| L5 | Reject multi-partition, non-FAT/exFAT/NTFS, encrypted drives | Hidden partitions evade; Windows must be able to verify | `devices.admit` |
| L6 | Fail closed: inspection limits, unreadable files, engine errors → not approved | A file not inspected is not evidence of safety | `daemon._inspect` |
| L7 | Privilege separation: daemon `cyrberus` (sudo mount/umount only), screen `kiosk` (no rights) | Least privilege | `deploy/` |
| L8 | Scan mount `ro,noexec,nosuid,nodev`; manifest written in a *fresh* rw mount (never remount), still `noexec,nosuid,nodev` | In-place remount failed on write-protected loop devices; phases stay distinct | `mounts.py` |
| L9 | Daemon→screen status via an atomic JSON file + 5 s heartbeat | Restart-tolerant, no connection state (changed from planned socket) | `state.py` |
| L10 | Kiosk: Tkinter on bare X + matchbox; no buttons; plain language; icon + heading + layout, never colour alone | Small footprint (~45 MB), accessible | `ui/kiosk.py` |
| L11 | Raspberry Pi OS Lite 64-bit; 4 GB design target | No automounter; ClamAV memory; affordability | progress report |
| L12 | ClamAV through `clamdscan --fdpass` | Daemon keeps signatures loaded; files stay unreadable to the clamav user | `scanner.py` |
| L13 | A drive present when the daemon starts is never processed silently | Avoid surprise processing after crashes/boot | `daemon.run` |
| L14 | Single-instance lock for the daemon | Two daemons fight over drives | `daemon.single_instance` |
| L15 | The Head ignores disks the system is using (boot SSD) | USB-booted Pi | `devices.in_use` |
| L16 | FAT mounted with `utf8,shortname=mixed` | Names must match what Windows shows | `mounts._opts_for` |
| L17 | Repo at `/opt/cyrberus`; LF line endings; never commit on the Pi | Fixed paths; Windows dev machines | `.gitattributes` |

### 7.2 Open decisions
| ID | Question | Options | Recommendation | Decide by |
|---|---|---|---|---|
| **D1** | How does the Sentinel give the user a verified drive's contents? | A: toggle policy after verifying · B: expose the drive read-only via a filesystem minifilter driver · B-lite: hide/show drive letters · **C: SYSTEM service verifies and copies verified bytes to a user inbox** · Defender for Endpoint device control | **C** (§10.3). Requires rewording MANIFEST_FORMAT §5 step 12 ("mount read-only") and every "mount" in O2, O5 ("mount-attempt events"), FR3 and FR4 ("at mount time") in the final report — justify as the proposal's own identified risk (§8 "Windows enforcement mechanism proves impractical") | end of spike, week 2 |
| D2 | Sentinel language | **Python 3 + pywin32** (reuse `manifest_lib`, team skill) · C#/.NET (native, but no built-in Ed25519 — needs a library) | Python; package with PyInstaller (one-dir) | week 1 |
| D3 | Scope of the user denial | **User-scope RSA "Deny all" for non-administrators** (SYSTEM unaffected) · computer-scope (may also block SYSTEM — SPIKE) | User scope, applied to Non-Administrators | spike T1–T4 |
| **D4** | Windows writes housekeeping files (e.g. `System Volume Information\WPSettings.dat`, `IndexerVolumeGuid`) to drives it mounts read-write — an *added file* under schema 1 → every drive denied after first use | **Prevent writes**: `StorageDevicePolicies\WriteProtect=1` or computer-scope "Removable Disks: Deny write access" (SPIKE both) · amend schema to exclude `System Volume Information/` (schema 2, both halves) | Prevent writes (keeps schema 1; also blocks USB exfiltration). Fixture `deny_windows_wrote_system_volume_information` documents the problem | spike T3 |
| D5 | How does an isolated Head get signature updates (SR3)? | cellular out-of-band link · offline signature bundles (`freshclam` on another machine, imported by USB/SD — itself removable media!) · data diode · lab network (current) | Document the lab choice; propose cellular or offline bundles as deployment design | before final report |
| D6 | Verifier strictness beyond the spec | reject `issued_at` in the future (beyond ~5 min skew) · cap validity (`expires_at - issued_at ≤ 12 h + skew`) · cap manifest size/file count | Allow as **stricter-only local policy**, documented; never more permissive. Note: spec §9 says algorithm changes need a schema bump — record that the team treats stricter policy as outside the format. **A validity cap turns the one-year `valid*` fixtures into DENY:** regenerate them with `--hours 12` shortly before each test run | week 2 |
| D7 | How the verifier picks the public key | spec step 3: peek `key_id` from unverified JSON (reference impl) · try every trusted key before parsing anything | Try-all is compatible with schema 1 and avoids parsing untrusted JSON; reasonable with few Heads | Sentinel build |
| D8 | Warden scope for the capstone | full service · minimal log collector (JSON lines over HTTPS) · Windows Event Forwarding + a script · descope with justification | Minimal collector or WEF; key distribution manual | week 4 |
| D9 | Head limits on huge drives | cap file count / total size (MANIFEST_FORMAT §8 suggests matching ClamAV MaxFiles) — not implemented | Add a cap (e.g. 50,000 files) → BLOCKED | optional |
| D10 | What the Sentinel delivers | everything · withhold shortcut/launcher types (`.lnk .url .scf .hta`, `autorun.inf`) · add Mark-of-the-Web (Zone.Identifier ZoneId=3) · total size cap | Verify the **whole** drive first (a failure anywhere denies everything). Then deliver every file with MOTW **except** withheld types, which are skipped, logged and named to the user (classic USB-worm launchers). Drives over **4 GB** of files: deny the whole drive with a clear message (configurable) | Sentinel build |
| D11 | Head clock for demos without network | network at boot · DS3231 RTC module | RTC if the venue has no network | before final demo |

### 7.3 Changes from the original plan (for report §9)
- Validity: the first idea was 24 hours; the proposal set **12 hours**.
- Sentinel mechanism: the proposal (§6) expected Group Policy denial released by the agent after verification. Research showed policy is machine- or user-wide, cannot target one drive, and may need a restart — so design C is recommended (D1). The proposal anticipated this risk (§8, "Windows enforcement mechanism proves impractical — High").
- Daemon↔UI: planned Unix socket → implemented as an atomic status file with heartbeat (L9).
- Resolved since the progress report: manifest path (`.cyrberus/`), multi-partition (reject).
- Added beyond plan: one-command installer, boot-to-standby automation, preflight checker, Sentinel golden test vectors, a lab signing tool, kernel-level integration test, and an independent two-pass review of this handoff whose findings were fixed (§14).
- Platform: built on Raspberry Pi OS Bookworm (Debian 12); Raspberry Pi OS has since moved to Trixie (Debian 13); the installer supports both.

---

## 8. The Head — complete reference

### 8.1 Pipeline (exact behaviour)
1. **Event.** `devices.monitor()` (pyudev) yields `add` for a whole disk with `ID_BUS=usb`; waits 1.2 s for partitions to enumerate; describes it. Partition events are ignored (the unit is the device). Every 15 s of quiet it yields `idle`.
2. **System disk?** If any of the disk's nodes is mounted or swapping (`/proc/self/mountinfo`, `/proc/swaps`, by device number) → ignored silently (L15).
3. **Identify.** Screen `WORKING/identifying`.
4. **Admit** (`devices.admit`): in use → "That drive is in use by this station." (second guard; normally step 2 already ignored it); not USB-attached → "That device is not a removable drive."; >1 partition → "This drive has more than one section on it."; 0 → "This drive has no readable section on it."; `crypto_LUKS`/`BitLocker` → "This drive is locked with a password."; filesystem not in {vfat, fat, fat32, exfat, ntfs, ntfs3} → "This drive uses a format we cannot read." A filesystem directly on the disk (superfloppy) counts as one partition.
5. **Mount read-only** at `/mnt/cyrberus-scan` via `sudo -n /usr/bin/mount -o ro,noexec,nosuid,nodev[,uid,gid,umask=0077][,utf8,shortname=mixed]`. Failure → "This drive could not be opened for checking."
6. **Scan** (`WORKING/scanning`): `clamdscan --fdpass --multiscan --infected --no-summary <mount>`, timeout 1800 s. Outcomes in §8.4.
7. **Hash** (`WORKING/hashing`, progress every 0.2 s): walk every regular file except `.cyrberus/`, sorted, forward slashes; any symlink (file *or* directory), reparse point, special file, unreadable file or unreadable directory → "This drive contains something we cannot record."
8. **Sign** (`WORKING/signing`): load private key; build manifest (head_id, key_id, issued/expires UTC, device block, scan block with engine and signature versions, files); serialize (`indent=2, sort_keys, ensure_ascii=False`, UTF-8); Ed25519-sign the bytes.
9. **Write**: unmount ro → **fresh** rw mount (still noexec/nosuid/nodev) → write `manifest.json` and `manifest.sig`, each `fsync`ed → `sync` → unmount (in `finally`). Failure → "The approval could not be written to this drive."
10. **CLEAN** screen with expiry and file count. Drive left unmounted.
11. **Remove** event → unmount anything left → `READY`.
12. Any unhandled exception → "Something went wrong while checking this drive." (fail closed). SIGTERM → clean exit that unmounts.

### 8.2 Verdict table
Checked in this order (`daemon._inspect`); the first match decides.

| # | ClamAV outcome | Screen | Manifest |
|---|---|---|---|
| 1 | any real detection (e.g. `Win.Test.EICAR_HDB-1`) — **even if the scan also hit errors** (exit 1 or 2) | THREAT + reference code `H<d>-<dddd>`; log `DETECTION ref= sig= path=` | **none** |
| 2 | engine failure: clamd unreachable, timeout, or exit 2 with nothing reported | BLOCKED "The checking service is not available right now." | none |
| 3 | only `Heuristics.Limits.Exceeded.*` / `Heuristics.Encrypted.*` | BLOCKED "Some files on this drive are too large or locked to be checked." | none |
| 4 | file errors ("Can't open file … ERROR") with no real detection or limit, whatever the exit status | BLOCKED "Some files on this drive could not be checked." | none |
| 5 | exit 1 but nothing parseable | BLOCKED "This drive could not be checked." | none |
| 6 | exit 0, no findings | → hashing and signing → CLEAN | written |

ClamAV settings (`deploy/clamd.conf.d/cyrberus.conf`): `AlertExceedsMax yes`, `MaxFileSize 1000M`, `MaxScanSize 2000M`, `MaxFiles 50000`, `MaxRecursion 32`, `Scan{Archive,PE,OLE2,PDF,HTML} yes`, `AlertEncrypted{,Archive,Doc} yes`.

### 8.3 State contract — `/run/cyrberus/state.json`
Written only by the daemon, atomically (temp file + fsync + rename), mode 0644, re-stamped every 5 s by a heartbeat. The screen treats data older than 15 s as "Checking is unavailable".
```json
{"state": "working", "updated_at": 1793350000.12,
 "detail": {"phase": "hashing", "model": "SanDisk Ultra", "size": "32 GB", "done": 1284, "total": 2061}}
```
| state | detail keys |
|---|---|
| `ready` | `signatures_updated` (virus list version, "" while clamd loads) |
| `working` | `phase` (identifying·scanning·hashing·signing), `model`, `size`, `done`, `total` |
| `clean` | `expires_at` (UTC ISO-Z), `file_count`, `model` |
| `threat` | `reference`, `detection_count`, `model` |
| `blocked` | `reason` (operator sentence), `model` |

Path resolution: `CYRBERUS_STATE` overrides; writers use the first writable of `/run/cyrberus`, `$XDG_RUNTIME_DIR/cyrberus`, `/tmp`; readers use the **most recently written** existing file among readable candidates, and the screen re-resolves whenever its file goes stale (so hand-run and service modes both work).

### 8.4 Screens (`ui/kiosk.py`, 800×480 design, scales)
| State | Heading | Body | Bottom bar |
|---|---|---|---|
| ready | Insert your USB drive | Checking starts on its own. / You do not need to press anything. | ● Ready · "Virus list version N" or "Virus list not ready yet" |
| working | Reading / Checking / Recording / Approving your drive | progress bar + "N of M files"; "Please leave the drive plugged in" | ● Working · model · size |
| clean | Your drive is clean | You can now use it on a work computer. · "Good until 4:47 PM" | You may remove your drive |
| threat | Do not use this drive (red layout) | Something harmful was found on it. · "Show this code to your IT staff" + code | Leave the drive here and tell your IT staff |
| blocked | We cannot check this drive | the reason · "A drive we cannot check is never approved." | Ask your IT staff for help |
| (stale) | Checking is unavailable | This station is not running right now. | Ask your IT staff for help |

### 8.5 Processes, accounts, permissions
| Process | Account | Rights |
|---|---|---|
| `head/daemon.py` (service `cyrberus-scanner`) | `cyrberus` (no login) | `sudo` for `/usr/bin/mount`, `/usr/bin/umount` only; reads key; writes `/run/cyrberus`, `/var/log/cyrberus` |
| `ui/kiosk.py` (X session on tty1) | `kiosk` (no password, no sudo) | read `/run/cyrberus` (0755: readable by all, writable only by `cyrberus`) |
| `clamd` | `clamav` | receives file descriptors from `clamdscan --fdpass` |

Service sandboxing: `ProtectSystem=full`, `ProtectHome=yes`, `PrivateTmp=yes`, `ReadOnlyPaths=/opt/cyrberus`; `NoNewPrivileges=no` (sudo needs setuid). These give the service a private mount namespace — scan mounts are invisible from SSH (`nsenter` to inspect).

### 8.6 Configuration
| Variable | Default | Meaning |
|---|---|---|
| `CYRBERUS_HEAD_ID` | `head-01` | `head_id` in manifests (audit only) |
| `CYRBERUS_VALIDITY_HOURS` | `12` | manifest lifetime (O4) |
| `CYRBERUS_KEY_DIR` | `/opt/cyrberus/keys` | key location |
| `CYRBERUS_MOUNT` | `/mnt/cyrberus-scan` | scan mountpoint |
| `CYRBERUS_LOG` | `/var/log/cyrberus/head.log` (fallbacks) | log file |
| `CYRBERUS_STATE` | resolved (§8.3) | status file override |
| `CYRBERUS_LOCK` | `/run/lock/cyrberus-head.lock` | single-instance lock |

Site settings go in `/etc/default/cyrberus` (read by the service).

### 8.7 Boot-to-standby chain
`systemd-tmpfiles` creates `/run/cyrberus` (the unit's `RuntimeDirectory=` also creates it and resets it to 0755 when the service starts) → `clamav-daemon` loads signatures (~1 min) → `cyrberus-scanner.service` (`Restart=always`, `Wants=` clamd so it starts even if clamd is late and refuses drives until it answers) → `getty@tty1` with autologin drop-in logs in `kiosk` → `~kiosk/.bash_profile` runs `startx` on tty1 only (Ctrl+C ignored; on exit sleeps 3 s and ends the session; getty restarts it) → `~kiosk/.xinitrc` runs matchbox + `kiosk.py`. The daemon's idle tick refreshes "Virus list version" once clamd answers. Switch: `deploy/boot-mode.sh on|off|restart|status`.

### 8.8 Edge cases
| Situation | Behaviour |
|---|---|
| Drive plugged in before boot / daemon restart | BLOCKED "Unplug this drive and plug it in again to check it." |
| Two drives at once | Processed one after the other (events queue). Operate one at a time — removing the first sets READY even if the second's result was showing |
| Drive pulled mid-scan | Scan/read errors → BLOCKED; then READY on removal |
| Empty drive | CLEAN, manifest with `"files": []` (valid per spec) |
| Non-ASCII filenames | Recorded exactly (UTF-8) |
| Write-protected or full drive | Scanned, but "The approval could not be written to this drive." |
| NTFS from a hibernated Windows ("Fast Startup") | may refuse read-write → approval cannot be written |
| SD card inserted into an already-attached USB card reader | **not detected** (kernel sends `change`, not `add`) — re-plug the reader (H6) |
| Huge drive | scan timeout 30 min → BLOCKED |
| clamd down | BLOCKED "checking service not available" |
| Daemon crash | systemd restarts it in 3 s; screen shows "unavailable" up to ~15 s |
| USB-booted Pi | boot disk ignored (L15) |

### 8.9 Hardening backlog
| ID | Item |
|---|---|
| H1 | `cyrberus` may run **any** `mount` command via sudo (could bind-mount over system paths if the daemon were compromised). Replace with a root-owned wrapper accepting only `/dev/sd*` → `/mnt/cyrberus-scan` with the fixed option set |
| H2 | Private key is plaintext on the SD card (physical theft = key theft). Future: TPM/secure element, or encrypted storage |
| H3 | Network isolation and firewall (SR3, D5); SSH keys only |
| H4 | Logs are local and not tamper-evident until the Warden |
| H5 | No file-count/size cap (D9) |
| H6 | Card-reader media-change events unsupported |
| H7 | Kernel FAT/exFAT parsers process untrusted filesystems (NTFS uses user-space ntfs-3g) — residual risk; keep the kernel patched |

### 8.10 Tests (run `sudo bash tests/run_all.sh` on the Pi)
| Suite | Checks | Proves |
|---|---|---|
| `test_manifest.py` | 23 | sign/verify round trip; added/modified/deleted file, expiry (including *exactly* at expiry), edited manifest, unknown Head, corrupt or wrong-length signature, no manifest all deny; empty drive valid; case-insensitive paths pass, case-twins deny, and folding is simple uppercase (ß ≠ SS); symlinked directories reported; step 9 before step 10; a broken trusted key denies instead of crashing; lab tool keygen/sign/verify, complete lab manifests, owner-only lab key, and refusal of the real key; CLI works from any directory |
| `test_head.py` | 51 | admission rules, verdict parsing and classification (including clamdscan exit 2), the daemon's verdict order, mount option sets, state file (round trip, stale, missing, corrupt, permissions), heartbeat, single-instance lock, present-at-boot handling, idle refresh, in-use disks |
| `test_ui.py` | 21 | every screen renders, repaint rules, wrapping, expiry formatting, status-file following, the unavailable screen explaining its cause |
| `test_root_integration.py` (root) | 29 | **kernel-enforced** ro/noexec/nosuid/nodev; full pipeline on a real filesystem image; Sentinel verifier accepts, then rejects after tampering; infected/limited/multi-partition refused with no manifest; Unicode names; mounted block devices detected as in use. Uses FAT32 on the Pi; where FAT is unavailable (no `mkfs.vfat` or kernel driver, e.g. a container) it says so and falls back to ext4 with admission patched — the last line shows which: `(vfat)` or `(ext4)` |
| `make_sentinel_fixtures.py` | 16 cases | golden vectors for the Sentinel (§10.10); `run_all.sh` regenerates them in a temporary folder and checks them against the reference verifier |

### 8.11 Module map
| File | Responsibility | Key functions |
|---|---|---|
| `head/daemon.py` | orchestration, states, lock | `Head.run`, `handle`, `_inspect`, `_sign`, `idle`, `single_instance` |
| `head/devices.py` | udev, admission, system-disk detection | `monitor`, `describe`, `admit`, `in_use`, `current_usb_disks`, `device_block` |
| `head/mounts.py` | hardened mount/unmount via sudo | `mount_ro`, `mount_rw`, `unmount`, `_opts_for` |
| `head/scanner.py` | clamdscan, verdict parsing | `scan_tree`, `parse_output`, `ScanResult.malware/.limited`, `engine_info` |
| `head/state.py` | status file | `publish`, `read`, `start_heartbeat`, `resolve_state_path`, `current` |
| `head/sign_manifest.py` | `sign_device()` for tests/fixtures, and a **lab tool**: `keygen <dir>` makes a lab keypair, `sign <drive> <priv> <pub>` signs test drives **without scanning**; refuses the Head's real key | `sign_device` |
| `head/keygen.py` | one-time Head keypair, refuses to overwrite (in the team repository; if absent, `install-head.sh` generates the key itself) | — |
| `common/manifest_lib.py` | the format | `build_manifest`, `serialize`, `walk_payload`, `key_id`, `encode_sig/decode_sig`, `parse_iso_z` |
| `sentinel/verify_manifest.py` | **reference verifier** (full source in Appendix C) | `verify_device(mount_root, {key_id: pem}) -> (ok, reason)`, `load_trusted(paths)`; CLI |
| `ui/kiosk.py` | screen | `Kiosk.screen_*`, `poll`, `redraw` |
| `deploy/install-head.sh`, `boot-mode.sh`, `preflight.sh` | setup, boot switch, checks | — |

---

## 9. The manifest contract (summary of `docs/MANIFEST_FORMAT.md`, schema 1, FROZEN)

### 9.1 Files on the drive
`.cyrberus/manifest.json` (UTF-8 JSON, exactly the signed bytes) and `.cyrberus/manifest.sig` (base64 Ed25519 signature + newline). `.cyrberus/` is excluded from the file list.

### 9.2 Fields
`schema` (1) · `head_id` (audit only) · `key_id` (first 16 hex of SHA-256 over the **exact bytes** of the Head's `head_public.pem` as written — LF line endings, no BOM, nothing normalised) · `issued_at`, `expires_at` (UTC `YYYY-MM-DDTHH:MM:SSZ`) · `device{vendor_id, product_id, serial, model, size_bytes, filesystem, partition_count}` (**descriptive only**) · `scan{engine, engine_version, signature_version, files_scanned, bytes_scanned, duration_seconds}` · `files[]{path, size, sha256}` sorted by path, forward slashes, no leading slash, lowercase hex.

### 9.3 Verification algorithm — normative, in this order
1. Locate both files. Missing → **deny**.
2. Read manifest as raw bytes; base64-decode the signature. Malformed → **deny**.
3. Extract `key_id` only, to select a public key. Unknown → **deny**. *(D7: trying every trusted key instead is compatible.)*
4. **Verify Ed25519 over the raw bytes.** Invalid → **deny**.
5. Only now parse the JSON as trusted.
6. `schema` not implemented → **deny**.
7. `expires_at` in the past → **deny**.
8. Walk the partition excluding `.cyrberus/`. Any symlink, reparse point, device node or unreadable entry → **deny**.
9. Any file on disk absent from `files[]` → **deny**.
10. Any `files[]` entry absent from disk → **deny**.
11. Any size or hash mismatch → **deny**.
12. All pass → **mount read-only** *(under D1-C: release verified bytes to the user; steps 11 and 12 merge into hash-while-copying)*.

**Exact behaviour of the reference verifier** (`sentinel/verify_manifest.py`, Appendix C) — a port must match it:
| Point | Rule |
|---|---|
| Trusted keys | `{key_id: pem_bytes}`, key_id computed from each PEM file's **content**, never its filename |
| `manifest.sig` | standard base64 of exactly 64 bytes; surrounding whitespace ignored; anything else → deny "malformed" |
| Expiry | `now >= expires_at` → deny (exactly at expiry is expired); compare in UTC |
| Step 8 | lists paths and sizes only; symlinks, reparse points, special files, unreadable files **or directories** → deny |
| Steps 9–10 | sets compared **case-insensitively** per spec §8, using **simple per-character uppercase** — the NTFS / .NET `OrdinalIgnoreCase` rule: a character whose uppercase is several characters is left unchanged, so `Straße` ≠ `STRASSE` (do **not** use Python `str.casefold()`); two paths equal under this folding on either side → deny |
| Step 11 | size first, then SHA-256 |
| Anything unexpected | exception → deny ("verification error: …") |
| Output | `(ok: bool, reason: str)`; CLI prints `PASS: …` / `DENY: …`, exit code 0 / 1 |

### 9.4 Known limitations (spec §8)
TOCTOU against devices that emulate mass storage; dependence on the endpoint clock; probabilistic detection; no HID coverage; ~230 bytes per file entry; FAT/exFAT/NTFS are case-insensitive but case-preserving — the Head records the preserved case and **a Windows Sentinel compares paths case-insensitively** (spec §8; fixture `valid_path_case_differs`).

---

## 10. The Sentinel — starting point

### 10.1 The central question: "If workstations deny USB by default, how can they verify a drive?" (SP1)
Windows can block USB storage at three different layers, and only one of them is right for Cyrberus:

| Layer | Examples | Effect | Fit |
|---|---|---|---|
| **Driver / device installation** | `USBSTOR` service `Start=4`; Device Installation Restrictions on the disk class | Windows never loads the drive at all | **Wrong** — the Sentinel cannot read it either |
| **Access policy (who may access)** | Removable Storage Access (RSA) policies: Deny read/write/execute/all, per user or per computer | Windows mounts the volume, but the denied accounts cannot open it | **Right** — deny the *people*, not the Sentinel |
| **Agent logic** | the Sentinel | decides what is released | the gatekeeper |

So: **deny-by-default applies to user accounts.** The Sentinel runs as a Windows service under **LocalSystem**, which a user-scope policy does not cover. Windows mounts the drive as usual; users cannot open it; the Sentinel reads it, verifies it, and hands the user only what verified. The user never touches the drive directly.

This must be proved on a real machine in week 1 (spike T1–T2): it is the premise of the whole design.

### 10.2 Why not simply "turn the policy off after verifying"? (option A)
RSA policies apply to *all* removable drives for that user or machine, not one drive; Microsoft documents that without a forced reboot an access-right change may not take effect until restart; and while the policy is relaxed, any other drive inserted is also open. Infeasible and racy.

### 10.3 Options compared
| Option | Mechanism | Verdict |
|---|---|---|
| A | Toggle RSA policy after verification | Infeasible (above) |
| B | Filesystem minifilter driver exposes only verified drives, read-only | Strongest UX, but kernel development, driver signing — beyond a student team (the proposal already prefers policy over drivers) |
| B-lite | Hide drive letters until verified | UX only — not a security boundary (raw volume paths still work) |
| **C** | **Users denied by policy; Sentinel (SYSTEM) verifies and copies verified bytes into a per-user Inbox, hashing while copying** | **Recommended.** User-mode, policy-based, closes TOCTOU for delivered content, read-only by construction (also blocks USB exfiltration) |
| — | Microsoft Defender for Endpoint device control | Real per-device allow rules, but licensed and identity-based (conflicts with L1). Cite as the commercial-grade alternative |

### 10.4 Design C architecture
```
 Windows (Pro/Education/Enterprise), users are standard accounts
 ├─ Policy baseline (§10.5): users denied all removable storage; USB write-protected machine-wide
 ├─ CyrberusSentinel service (LocalSystem)  C:\Program Files\Cyrberus\
 │    ├─ arrival watcher   WMI Win32_VolumeChangeEvent (EventType=2) or service device notifications
 │    ├─ verifier          port of sentinel/verify_manifest.py (normative order)
 │    ├─ copier            hash-while-copying into a staging folder, then atomic rename
 │    ├─ logger            Windows Event Log (source "Cyrberus") + JSON lines in C:\ProgramData\Cyrberus\logs
 │    └─ status writer     per-user status file (same pattern as the Head's state.json)
 ├─ Notifier (runs in the user's session, started at logon)  - Session 0 isolation: services cannot show UI
 │    shows "Checking…", "N files are in your Cyrberus Inbox", or the denial reason
 ├─ Trust store  C:\ProgramData\Cyrberus\trusted_heads\*.pem   (Admins/SYSTEM write, Users read;
 │               key_id computed from each file's content, never from its name)
 ├─ Staging      C:\ProgramData\Cyrberus\staging\<random>\      (SYSTEM + Admins ONLY - users never
 │               see unverified bytes)
 ├─ Status       C:\ProgramData\Cyrberus\status\<user-SID>.json (SYSTEM writes, that user reads)
 └─ Inbox        C:\Users\<user>\Cyrberus Inbox\<yyyy-mm-dd hhmm> <volume label>\
                 (inherits the user's profile permissions)
```

**Who receives the files (SEN-13):** the user signed in at the **physical console** (`WTSGetActiveConsoleSessionId` → that session's user). Nobody signed in, or the console locked to a different user → deny and log "no one signed in to receive it". Remote Desktop and fast-user-switching sessions are not served in v1.

**Staging and permissions (SP5):** copy into staging (SYSTEM/Admins only), verify every hash, then move the folder into the Inbox. A move within one volume keeps the folder's original restrictive ACL, so **after the move explicitly reset permissions to inherit from the Inbox** (`icacls "<dest>" /reset /T`, or `SetNamedSecurityInfo` with inheritance enabled). If `C:\ProgramData` and the user profile are on different volumes the move becomes a copy — detect and handle. Verify in spike T7 that the user can open delivered files and could not see staging.

**Formats to standardise now (feed the Warden, §11):**
| Item | Definition |
|---|---|
| Event Log | source `Cyrberus`; event IDs **1000** drive arrived · **1001** released · **1002** denied · **1003** error · **1004** files withheld (D10) |
| JSON-lines log | `C:\ProgramData\Cyrberus\logs\sentinel.jsonl`, one object per event with the §11 fields |
| Status file | `{"state": "checking"\|"released"\|"denied"\|"error", "updated_at": <epoch>, "detail": {"reason", "file_count", "inbox_path", "withheld": [...]}}` — same atomic-write pattern as the Head's `state.json` |

**Algorithm (per drive):**
```
on arrival of removable volume V (drive letter or \\?\Volume{GUID}\):
    log arrival (VID/PID/serial recorded for audit ONLY - SP10)
    user = console session user; none -> deny "no one signed in"           # SEN-13
    notify user "Checking your drive…"
    blob, sig  = read .cyrberus/manifest.json and manifest.sig as bytes      # steps 1-2
    key        = trusted key whose verify(sig, blob) succeeds                  # steps 3-4 (D7)
    manifest   = json.loads(blob)                                             # step 5
    require schema == 1                                                       # step 6
    require now_utc < expires_at  (+ D6 policy checks)                        # step 7
    entries    = walk V excluding .cyrberus/; deny on reparse point, special,
                 unreadable (Windows: check FILE_ATTRIBUTE_REPARSE_POINT)    # step 8
    require fold(disk paths) == fold(manifest paths), no fold-twins (§9.3)  # steps 9-10
    (D10) total size over cap -> deny
    for each file:                                                            # step 11 + release
        open the main data stream only; read chunk -> SHA-256 update -> write
        to ProgramData staging copy (never Windows copy APIs: they copy ADS)
        size/hash mismatch -> delete staging, deny
    (D10) drop withheld types from staging (log + tell user); add Zone.Identifier ZoneId=3 to each copy
    move staging -> Inbox; reset ACL to inherit; log 1001 with head_id, key_id, file count
    notify user "N files are ready in your Cyrberus Inbox"
on ANY exception, timeout or removal: delete staging, log, deny, notify     # SP7
```
Why hash-while-copying matters: a malicious device can serve different bytes on different reads (TOCTOU). If the Sentinel hashed in one pass and copied in another, it could deliver bytes it never verified. Copying exactly the bytes being hashed means the user only ever receives verified content.

### 10.5 Workstation baseline — Group Policy and registry
Apply on a lab machine first; reboot once after applying. **SPIKE** = confirm in week 1–2.

| # | Control | Group Policy path → setting | Registry equivalent | Why |
|---|---|---|---|---|
| 1 **PARAMOUNT** | Users are standard (not local administrators) | Computer Management → Local Users and Groups; or domain | — | Admins can undo everything (SP2) |
| 2 **PARAMOUNT** | Deny users all removable storage | **User** Configuration → Administrative Templates → System → Removable Storage Access → **All Removable Storage classes: Deny all access** = Enabled. Apply to *Non-Administrators* via Multiple Local Group Policy (`mmc` → Group Policy Object Editor → Browse → Users → Non-Administrators) | `HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices` → `Deny_All` (DWORD) = 1 — **HKCU is per user**: writing it from a script affects only the account running the script. To target Non-Administrators: use the MLGPO editor (manual, reliable), or Microsoft's `LGPO.exe` (Security Compliance Toolkit) importing into the Non-Administrators policy (SPIKE), or load each standard user's `NTUSER.DAT` and set it there | SP1. SYSTEM is not covered (SPIKE T2) |
| 2b | (narrower alternative) | User Configuration → … → Removable Disks: Deny read / write / execute access | `HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}` → `Deny_Read`, `Deny_Write`, `Deny_Execute` = 1 | same |
| 3 **PARAMOUNT** | Machine-wide write protection for USB storage | (or) **Computer** Configuration → … → Removable Storage Access → Removable Disks: Deny write access (SPIKE: does it stop SYSTEM's/Windows' own writes?) | `HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies` → `WriteProtect` (DWORD) = 1 — documented through Windows 10; SPIKE on 11 | SP3/D4: Windows cannot write housekeeping files that would break manifests; also blocks USB exfiltration (T1052.001) |
| 4 | AutoPlay / AutoRun off | Computer Configuration → Administrative Templates → Windows Components → AutoPlay Policies → Turn off AutoPlay = Enabled, **All drives**; Set the default behavior for AutoRun = Enabled, **Do not execute any autorun commands** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` → `NoDriveTypeAutoRun` = `0xFF`, `NoAutorun` = 1 | CIS Control 10.3 |
| 5 | Defender real-time protection on; scan removable drives | Computer Configuration → Administrative Templates → Windows Components → Microsoft Defender Antivirus → Scan → Scan removable drives = Enabled | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan` → `DisableRemovableDriveScanning` = 0 | Defence in depth: copies in the Inbox are scanned on write (CIS 10.1, 10.4) |
| 6 **PARAMOUNT** | Time sync on; users cannot change the clock | Windows Time service running with a sync source; Computer Configuration → Windows Settings → Security Settings → Local Policies → User Rights Assignment → **Change the system time** = Administrators, LOCAL SERVICE only (default) | — | Expiry depends on the clock (SP9) |
| 7 | Audit removable storage and device arrival | Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Object Access → **Audit Removable Storage** (Success, Failure) → event **4663**; Detailed Tracking → **Audit PNP Activity** → event **6416** (SPIKE: confirm both) | — | O5 / AU-2; feeds the Warden |
| 8 **PARAMOUNT** | Trust store ACL | `icacls "C:\ProgramData\Cyrberus\trusted_heads" /inheritance:r /grant:r Administrators:(OI)(CI)F SYSTEM:(OI)(CI)F Users:(OI)(CI)R` | — | SP6 |
| 9 **PARAMOUNT** | Sentinel installed under `C:\Program Files\Cyrberus` (admin-only write); service as LocalSystem, start Automatic | — | — | Writable service binaries = privilege escalation |
| 10 | *Optional* long paths | Computer Configuration → Administrative Templates → System → Filesystem → Enable Win32 long paths | `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem` → `LongPathsEnabled` = 1 | Paths > 260 chars on drives |
| ✗ | **Do not use** for design C | `USBSTOR` `Start=4`; Device Installation Restrictions denying disk drives | `HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR` → `Start` | Blinds the Sentinel (§10.1). Mention as the "no USB storage at all" alternative |

Edition: use Windows **Pro, Education or Enterprise** (Group Policy Editor and Multiple Local Group Policy). Home has no `gpedit`.

### 10.6 Pitfalls checklist
- **Session 0 isolation:** the service cannot display anything; a per-user notifier is required.
- **System Volume Information / `WPSettings.dat` / `IndexerVolumeGuid`:** written by Windows to drives mounted read-write → manifests break (D4, control 3).
- **NTFS alternate data streams:** the manifest describes only main streams. Copy with your own read → hash → write loop (which hash-while-copying needs anyway): opening `E:\path\file` reads only the main stream. Do not use Windows copy APIs or tools (`CopyFile`, `copy`, `robocopy`, and library helpers that call them) — they also copy ADS (SP8).
- **Reparse points / junctions:** treat as deny (step 8).
- **Hidden and system files** are real files and must be in the manifest — do not skip them when walking.
- **Paths:** forward slashes in the manifest, backslashes on Windows; compare **case-insensitively** with case-twins denied (§9.3 table); long paths need `\\?\`.
- **Trust store PEMs:** copy them in binary (scp, USB). Opening and re-saving in Notepad or sending by email can add CRLF or a BOM, which changes `key_id` → every drive "unknown Head". `.gitattributes` already marks `*.pem` binary.
- **NTFS permissions travel with the drive:** the Head (ntfs-3g) ignores NTFS permissions, but Windows enforces them — a folder locked down on another PC may be unreadable even to SYSTEM → deny. Expected and fail-closed; test it (T7).
- **USB disks that report as "fixed":** some USB hard drives/SSDs present as fixed disks; Removable Storage Access policies may not cover them (SPIKE T1).
- **Removal mid-copy:** delete staging; never leave partial files in the Inbox.
- **Two drives at once:** handle each independently or queue.
- **Clock:** parse `expires_at` as UTC; never local time.
- **PyInstaller executables** are sometimes flagged by antivirus; use one-dir builds, test early.
- **Licensing:** `dissect.fat` (raw FAT parsing) is AGPL-3.0 — incompatible with keeping the repo MIT if distributed. Avoid raw parsing unless the spike forces it.
- **Do not trust the drive letter label or volume serial** for anything but display/logging.

### 10.7 Week 1–2 spike plan (decision gate for D1/D3/D4)
Run on a Windows 10/11 Pro VM or spare PC with a standard user account and a Head-validated drive. `psexec -s -i cmd` (Sysinternals) gives a SYSTEM shell for testing.

| Test | Steps | Pass condition |
|---|---|---|
| T1 | Apply control 2 to Non-Administrators; log in as the standard user; insert a validated flash drive, then a USB hard drive/SSD | user gets access denied in Explorer and `dir E:` for **both** (a USB disk reporting as "fixed" may escape — record it) |
| T2 | In a SYSTEM shell: `dir E:\` and `py sentinel\verify_manifest.py E:\ head_public.pem` (needs Python installed *for all users* and, from an admin prompt, `py -m pip install cryptography`; on Windows the command is `py`, not `python3`) | **PASS** — SYSTEM can read while users cannot (the premise) |
| T3 | Without control 3: insert a validated drive as an admin, eject, re-verify. Then enable `WriteProtect=1` (and separately computer-scope Deny_Write), reboot, repeat | without: `System Volume Information` files may appear and verification fails; with: no writes, verification passes |
| T4 | Computer-scope Deny_All/Deny_Read, then repeat T2 | learn whether computer scope also blocks SYSTEM (decides D3) |
| T5 | For each control: does it apply after `gpupdate /force` + re-plug, or only after reboot? | documented |
| T6 | Python script as SYSTEM subscribing to `Win32_VolumeChangeEvent` | arrival detected within ~2 s |
| T7 | Prototype verify-and-copy of a 1 GB drive into a test Inbox; include an NTFS drive with a folder locked by permissions, and an NTFS drive previously used on Windows | correct copies; user can open them, could not see staging; throughput measured; all fixtures pass; the locked folder denies cleanly |
| T8 | Toast/notification from a user-session helper triggered by the service | user sees the result |

**Gate (end of week 2)** — record each outcome as a decision:
| Result | Then |
|---|---|
| T1 + T2 pass | build design C (D1, D3 settled) |
| **T1 fails** (users can still open drives) | check edition (Pro/Edu/Ent), reboot, and that the policy reached Non-Administrators; if USB disks escape as "fixed", add a policy for them or document the limit |
| **T2 fails** (SYSTEM blocked too) | apply the denial to specific user SIDs only; or read the raw volume (`\\.\E:`) with a filesystem parser (licensing!); or adopt Defender device control and document |
| **T3 fails** (Windows still writes to drives on Windows 11) | try computer-scope Deny_Write; if nothing stops the writes, D4 falls back to a **schema 2** amendment excluding `System Volume Information/` — this changes the frozen format, so it needs the Head owner [Member 1] and the integration owner [Member 3] to agree, an update to MANIFEST_FORMAT.md (§9 of that file), and changes to both halves |

### 10.7.1 Getting test drives and keys for the spike
- **With the Pi:** have [Member 1] validate a drive on the Head. Copy the public key **in binary**: `scp <admin>@<pi-ip>:/var/lib/cyrberus/head_public.pem .` (never re-save it in an editor).
- **Without the Pi (recommended for week 1):** generate the fixtures (`python3 tests/make_sentinel_fixtures.py sentinel-fixtures`; on Windows the command is `py` instead of `python3`). Then **prepare the stick on a non-Windows machine** — the Pi itself (boot mode off), any Linux machine, or a Mac: format it FAT32 with one partition and copy **everything** inside `sentinel-fixtures/drives/valid/`, including the hidden `.cyrberus` folder, to its root. Trust `sentinel-fixtures/trusted/fixture_head_public.pem`. *Why not on Windows:* Windows mounts the stick read-write while you copy and may add `System Volume Information` files — the stick would then fail before you test anything. If you do prepare it on Windows, run the verifier immediately: a DENY naming `System Volume Information` is your T3 finding, not a broken fixture.
- **Your own content:** `python3 head/sign_manifest.py keygen labkeys` once, then `python3 head/sign_manifest.py sign <drive or folder> labkeys/lab_private.pem labkeys/lab_public.pem`. Lab manifests carry every field a Head writes (device and scan blocks are placeholders, `scan.engine` says "NOT scanned"). Lab keys are for test machines only; the tool does **not** scan for malware and refuses the Head's real key.
- **Treat `device` and `scan` as descriptive in the port:** read them with defaults (`.get()`), log them, never let a missing or odd value change a verdict.

### 10.8 Suggested repository additions
```
sentinel/
├── verify_manifest.py        (exists - reference; keep in sync)
├── service.py                pywin32 service: start/stop, arrival loop
├── arrival.py                WMI volume events
├── release.py                walk + hash-while-copy + MOTW + atomic rename
├── trust.py                  load trusted_heads\*.pem -> {key_id: pem}
├── notify.py                 user-session notifier
├── policy/
│   ├── apply-baseline.ps1    controls 2-10 for a lab machine (+ revert script)
│   └── README.md
└── tests/                    run against sentinel-fixtures
```
Tooling: Python 3.12+ 64-bit for Windows; `pywin32` (service, file APIs, ACLs); `wmi` (or pywin32 COM); `cryptography` (same library as the Head); PyInstaller for packaging. Reuse `common/manifest_lib.py` directly — it is pure Python.

### 10.9 First tasks and a possible split
- **[Member 1] — Head (built it):** keeps the Pi running; validates real test drives for the spike; measures NFR1; owns D5; joins any D4 schema discussion; integration testing.
- **[Member 2] — enforcement:** build the lab VM; write `apply-baseline.ps1` and its revert; run spike T1–T5; record D3/D4 outcomes.
- **[Member 3] — engine:** port `verify_manifest.py` into `release.py` with hash-while-copy; make all 16 fixtures pass on Windows (T7); write the trust store loader.
- **Together:** service skeleton + arrival (T6), notifier (T8), event logging (feeds the Warden), the D1 write-up for the report.
- Integration milestone: a drive validated by the Pi releases its files into a standard user's Inbox on Windows, and a tampered drive is denied with a logged reason.

### 10.10 Golden test vectors
```bash
python3 tests/make_sentinel_fixtures.py sentinel-fixtures   # Linux/macOS/Pi
py tests\make_sentinel_fixtures.py sentinel-fixtures        # Windows
```
Needs Python with the `cryptography` package. Produces `drives/<case>/` folders laid out like drive roots, `trusted/fixture_head_public.pem` (a throwaway key — never a real Head's), `README.txt`, and `expected.json` in the form `{"<case>": {"verdict": "PASS"|"DENY", "why": "<spec step>"}}`. Cases: `valid`, `valid_empty_drive`, `valid_unicode_names`, `valid_path_case_differs`, `deny_case_fold_is_simple`, `deny_file_added`, `deny_file_modified`, `deny_file_deleted`, `deny_expired`, `deny_unknown_head`, `deny_manifest_edited`, `deny_wrong_schema`, `deny_no_manifest`, `deny_corrupt_signature`, `deny_manifest_copied_to_other_drive`, `deny_windows_wrote_system_volume_information`. The reference verifier passes all 16; **a Sentinel is conformant when it reaches the same verdict on every case** (SEN-12). The *reason* text may differ; the verdict may not.

- Valid cases last one year by default. If the Sentinel enforces a validity cap (D6), regenerate with `--hours 12` shortly before testing, or they will (correctly) deny.
- The output folder is replaced on each run **only** if it is empty or was made by the script; it refuses to touch anything else.

---

## 11. The Warden
**Status:** NOT STARTED; scope is D8. Purpose: satisfy O5 (central logging) and manage keys (WAR-2).
**Minimal viable version:** a small service (Python/Flask or FastAPI) on a lab machine that accepts JSON events over HTTPS from Heads and Sentinels, appends them to a hash-chained log (each record carries the SHA-256 of the previous one — tamper-evident, H4), and offers a page listing recent events. Alternative with less code: Windows Event Forwarding for Sentinels plus a script that ingests the Head's `head.log`.
**Event fields to standardise early:** `time_utc, source (head|sentinel), host, head_id, key_id, event (validated|threat|blocked|verified|denied|released), reason, file_count, device{vid,pid,serial}, reference`.
**Key management:** v1 manual (copy `head_public.pem` into each trust store; remove to revoke). Warden-pushed trust stores are future work.

---

## 12. Threat model

### 12.1 Assets
Workstation integrity and the network behind it; the Head private key; Sentinel trust stores; audit logs; users' data.

### 12.2 Attack surface
Head USB port and filesystem parsers; the manifest (an attacker-reachable file on untrusted media); the Head's update path; the Sentinel service and its trust store; administrator accounts; the clocks.

### 12.3 STRIDE
| Category | Threat | Mitigation | Residual |
|---|---|---|---|
| **S**poofing | Forged manifest / rogue Head | Ed25519 signature; trust store of known keys | Key theft (H2) |
| | Spoofed device descriptors | Never used for trust (L1, SP10) | — |
| **T**ampering | Files added/changed/removed after validation | Per-file SHA-256, both-direction set comparison | — |
| | Manifest edited | Signature over raw bytes | — |
| | TOCTOU device serving different bytes | Head hashes what it scanned; Sentinel hashes while copying (SP5) | Content the Head scanned may differ from content a *direct* read would have shown (firmware attacks) |
| | Windows itself writing to drives | Write protection (SP3, D4) | SPIKE |
| **R**epudiation | "Who approved this drive?" | Manifest records head_id, key_id, times, engine & signature versions; Head log with reference codes | Logs local until Warden (H4) |
| **I**nformation disclosure | Manifest exposes file names/sizes/hashes on the drive | Accepted — no secrets in the manifest; note for privacy section | Low |
| **D**enial of service | Zip bombs, giant drives, endless files | ClamAV limits fail closed; 30 min timeout | Head can be kept busy (physical access) |
| **E**levation of privilege | Malicious filesystem or file attacking the Head | No automount; `ro,noexec,nosuid,nodev`; unprivileged daemon; ntfs-3g in user space; sandboxed service | Kernel FAT/exFAT parsers (H7); broad mount sudo rule (H1) |
| | User bypasses Sentinel | Standard users; policy denial; admin-only trust store and binaries | Local administrator can disable everything (documented) |

### 12.4 Explicit residual risks (report these honestly — objective O7)
Zero-day or unknown malware (signature detection is probabilistic); HID/BadUSB devices (T1200, out of scope — recommend separate controls such as physical port blockers or HID device-class policies); a local administrator on a workstation; physical theft of the Head (key on SD card); clock manipulation by an administrator; data exfiltration (out of scope, though control 3 blocks writes).

---

## 13. Development workflow and repo conventions
- **Develop on laptops, push to GitHub, `git pull` on the Pi. Never commit on the Pi.** (`git config pull.rebase true` on all machines.)
- **Line endings:** `.gitattributes` forces LF for scripts/Python/units — Windows checkouts otherwise break shell scripts (`/bin/bash^M`). Scripts are run as `bash script.sh`, so the executable bit does not matter.
- **Windows PowerShell 5.1:** `&&` is not valid — one command per line; use `$env:USERPROFILE` not `~` in some contexts. `cyrberus.local` may not resolve — use the Pi's IP.
- **Never commit:** private keys (`keys/`, `*.pem` are ignored), malware samples, `sentinel-fixtures/` (regenerate instead).
- **Before pushing:** `bash tests/run_all.sh` → ALL SUITES PASSED.
- **After pulling on the Pi:** `sudo bash deploy/install-head.sh` (idempotent; restarts the scanner only if its code changed), then `sudo bash deploy/boot-mode.sh restart` if boot mode is on.
- **Do not edit `docs/MANIFEST_FORMAT.md`** without a team decision (P14).

---

## 14. Lessons learned (report §6 "Difficulties encountered")
| Problem | Cause | Resolution |
|---|---|---|
| Key generation `PermissionError` | Keys directory is 700 owned by `cyrberus`; script run as the admin user | Run as `cyrberus`; now automated by the installer |
| "Divergent branches" on the Pi | Commits made on the Pi | Pull-only rule; `pull.rebase true` |
| Writing the manifest failed on write-protected loop device | In-place `remount,rw` refused | Unmount + fresh rw mount (L8) |
| Tests could not override paths | Python default arguments evaluated at definition time | Resolve at call time |
| "PermissionError" on `/run/cyrberus` | `/run` is tmpfs, emptied at boot; manual runs cannot create it | tmpfiles.d rule + path fallback |
| Screen said "Checking is unavailable" while idle | Daemon only wrote on transitions; screen judged it dead after 15 s | Heartbeat every 5 s |
| "Daemon hangs on ready" | Misread — it waits for a drive | Documented as normal |
| Preflight false alarms | `pipefail` with `clamconf`; key dir unreadable to non-root; stale log ownership | Capture output first; "cannot check" state; check file ownership |
| Oversized/encrypted files showed the red "harmful" screen | ClamAV reports limits as detections | Classified as *cannot check* (BLOCKED) |
| "Virus list loaded" shown with no version | Screen text assumed success | Honest "not ready yet" + idle refresh after boot |
| Git "unrelated histories" on a new laptop | Repository initialised in the wrong folder | Fresh clone |
| Reference verifier CLI crashed (`ModuleNotFoundError`) | Run as a script, `common/` not on the path | Path fix + regression test |
| A failing manifest test still reported success | Test file never set its exit code | Fixed; all suites now fail loudly |
| Two daemons possible | Boot service + hand-run | Single-instance lock |
| USB-booted Pi would treat its own SSD as a drive | Boot disk is also `ID_BUS=usb` | System-disk detection by device number |
| Non-ASCII filenames at risk on FAT | Kernel-default FAT charset | Explicit `utf8,shortname=mixed` |
| Screen could read a stale file while a hand-run daemon wrote elsewhere | Reader/writer path mismatch after group permissions changed | Readers follow the freshest status file |
| *Live demo, 2 Nov:* scans ran over SSH but the Pi's screen stayed on "Checking is unavailable" | `/run/cyrberus` was 0750 + group `cyrberus`; the console login predated the installer adding the user to the group, so the screen could not see the status | Status folder made world-readable (0755, nothing sensitive in it); the unavailable screen now prints the exact reason; the daemon warns when it cannot write the shared folder |
| *Found by an independent cold-read review of this handoff:* | | |
| Reference verifier compared paths exactly; the spec says case-insensitively | Linux habits | Case-folded comparison, case-twins deny; new fixture |
| Verifier checked step 10 before step 9 and hashed before comparing file sets | Convenience walk | Normative order; hashing only in step 11 |
| Unreadable directories and symlinked directories silently skipped | `os.walk` defaults | Reported as problems → not approved / deny |
| Infected drive with one unreadable file showed "service unavailable", no DETECTION log | clamdscan exit 2 treated as engine failure | Findings kept on exit 2; malware checked first |
| A broken trusted key crashed the verifier | unguarded key load | Any exception → deny |
| Fixture generator would delete whatever folder it was pointed at | unconditional `rmtree` | Refuses folders it did not create |
| `sign_manifest.py` crashed when run standalone | same import-path bug as the verifier | Fixed; now a guarded lab tool |
| *Found by the reviewer's re-check of those fixes:* | | |
| `run_all.sh` could not fail on the fixture check | piping into `tail` reported `tail`'s exit status | Output captured first; proved by sabotaging the verifier in a copy |
| Case folding unspecified for a port | Python `str.casefold()` folds `ß` to `ss`; NTFS does not | Simple per-character uppercase, pinned by fixture `deny_case_fold_is_simple` |
| Lab manifests lacked device/scan fields; lab key world-readable | minimal blocks; default file mode | Every field present; key created 0600 |

---

## 15. Status and next steps
Fill in the calendar: week 1 starts **[date]**; final report due **[date]**; live demonstration **[date]**.

- [x] Head: detection, admission, scanning, hashing, signing, screen, logging, boot-to-standby, installer, preflight, tests
- [x] Manifest format frozen; reference verifier; golden vectors; lab signing tool
- [ ] **Sentinel spike T1–T8** and decisions D1, D3, D4 — *weeks 1–2* — [Member 2], [Member 3]; test drives from [Member 1] or §10.7.1
- [ ] Sentinel build to SEN-1…SEN-13 — *weeks 3–5*
- [ ] Warden scope decision D8 and minimal version — *week 4*
- [ ] D5 (Head update path) written up for the report
- [ ] NFR1 measurement (16 GB, ten runs) on the Pi
- [ ] Fill proposal placeholders: [$X] budget, [X] minutes, names, course, institution
- [ ] Coursework mapping (§16) once transcripts and syllabi are available
- [ ] Final report (structure in §17) and live demonstration (`docs/DEMO.md`)

---

## 16. Coursework mapping (for the presentation and report)
The team will add transcripts and syllabi near the end. Until then this maps the project to concepts every cybersecurity curriculum covers; when syllabi arrive, fill §16.4 with each course's own objectives.

### 16.1 Concepts → where Cyrberus applies them
| Concept area | Concept | In Cyrberus |
|---|---|---|
| Cryptography | Digital signatures (authenticity, integrity) | Ed25519 over manifest bytes |
| | Cryptographic hashing | SHA-256 per file; `key_id` fingerprint |
| | Key management | one-time generation, mode 600, public-key distribution, rotation, revocation (Warden) |
| | Canonicalization pitfalls | detached signature over literal bytes (L2) |
| Security principles (Saltzer & Schroeder) | Least privilege | unprivileged daemon with one sudo rule; screen with no rights; standard users |
| | Fail-safe defaults | deny by default; every error = not approved |
| | Complete mediation | Sentinel verifies every drive, every time |
| | Economy of mechanism | file-based status; Tkinter; plain shell installer |
| | Separation of privilege | signing (Head) and enforcement (Sentinel) on different machines |
| | Least common mechanism | screen and scanner are separate processes and accounts |
| | Open design (Kerckhoffs) | open source; security rests on the key alone |
| | Psychological acceptability | no-button kiosk, plain language, never colour alone |
| CIA triad | Integrity first; availability traded for safety (fail closed); confidentiality out of scope (manifest has no secrets) | |
| Defence in depth | Head scan + manifest + Sentinel + Defender + write protection + MOTW | |
| Identity & access | Authenticate *content*, not devices; Kerberos-style time-limited credentials; access control per user | |
| Operating systems & hardening | Linux mount options, udev, systemd sandboxing, sudoers, groups/permissions, tmpfs, namespaces; Windows Group Policy, registry, services, ACLs, Session 0 | |
| Secure programming | TOCTOU; verify-before-parse; untrusted input (filesystems, JSON); atomic writes; no shell injection (argument lists); automated tests | |
| Malware & threats | USB worms, LNK launchers, EICAR, signature vs heuristic detection, archive bombs, BadUSB/HID; MITRE ATT&CK T1091/T1052.001/T1200 | |
| Network security | Head isolation (SR3), out-of-band updates, data diodes | |
| Risk management | threat model (STRIDE), residual risk, risk register, cost-benefit for small organisations | |
| Governance & compliance | NIST SP 800-53, CIS Controls v8, NERC CIP, NIST CSF | §16.2 |
| Incident response & forensics | reference codes → logs; manifest scan block answers "validated before or after the signature update?"; leave suspect drives with IT (custody) | |
| Human factors | Tischer et al.: people plug drives in to help; usable security | |
| Ethics, law, professionalism | EICAR only; disclosure integrity; privacy of scanned files; licensing (MIT vs AGPL) | |
| Systems administration | idempotent automation, monitoring (preflight), logging (journald), boot services | |
| Project management | phased plan, risk register, decision log, version control | |

### 16.2 Framework mappings
| Framework | Control / item | Cyrberus mechanism |
|---|---|---|
| NIST SP 800-53 Rev. 5 | MP-7 Media Use | deny users removable media; allow only validated content |
| | SI-3 Malicious Code Protection | ClamAV on the Head; Defender on workstations |
| | SI-7 Software, Firmware, and Information Integrity | signed hash manifest; re-verification |
| | AC-6 Least Privilege | daemon/screen/user separation |
| | AU-2 Event Logging | Head log; Sentinel events; audit policies 4663/6416 |
| | SC-12 Cryptographic Key Establishment and Management; SC-13 Cryptographic Protection | Ed25519 keys, SHA-256 |
| | CM-6 / CM-7 Configuration Settings / Least Functionality | GPO baseline; Lite OS, no desktop |
| | IA-3 Device Identification and Authentication | deliberately *not* relied upon (forgeable) |
| | SC-7 Boundary Protection | Head isolation (SR3) |
| CIS Controls v8 | 10.1 anti-malware; 10.2 automatic signature updates; 10.3 disable autorun/autoplay for removable media; 10.4 scan removable media; 5.4 restrict admin privileges; 8.2 collect audit logs | freshclam; baseline controls 4–7; standard users |
| MITRE ATT&CK | T1091, T1052.001, T1200 (and T1102.001 naming note) | §4.1 |
| NERC CIP | CIP-003-8, CIP-010-4 R4 (transient cyber assets & removable media) | market context |
| NIST CSF 2.0 | Protect (access control, platform security), Detect (continuous monitoring) | Head + Sentinel; Warden |

### 16.3 National knowledge units (if your program is a CAE-CD institution)
Many U.S. cybersecurity degrees map courses to CAE-CD Knowledge Units; names vary by year and school, so prefer your syllabi's wording. Typical units this project exercises: Basic Cryptography, Cybersecurity Foundations, Cybersecurity Principles, IT System Components, Basic Networking, Network Defense, Operating Systems Concepts, Basic Scripting and Programming; optional units such as Operating System Hardening, Security Risk Analysis, Cyber Threats, Cybersecurity Ethics, Cybersecurity Planning and Management, IA Standards.

### 16.4 Template — fill when syllabi arrive
| Course (code, title) | Syllabus objective (verbatim) | Cyrberus element | Evidence (file, section, demo moment) | Slide / report section | Presenter |
|---|---|---|---|---|---|
| | | | | | |

Instructions for the assistant: for each course, quote the objectives, match each to rows of §16.1–16.2, cite concrete evidence (a file, a test, a screen, a decision ID), and flag objectives the project does not touch rather than stretching.

---

## 17. Report and presentation crosswalk
Course report structure → where the material is:
| Report section | Source in this document |
|---|---|
| 1 Introduction | §3, §4, §5.4 |
| 2 Background & related work | §4 |
| 3 Requirements & specifications | §5 |
| 4 System design | §6, §8, §9, §10.4 |
| 5 Cybersecurity analysis & design | §12, §10.5, §16.2 |
| 6 Implementation | §8, §13, §14 |
| 7 Testing & evaluation | §5.5, §8.10, §10.10 |
| 8 Results & discussion | §5.1–5.2 status, §12.4 |
| 9 Project management | §7.3, §15 |
| 10 Ethical, legal, professional | §0.2 rules 5–7, §16.1 |
| 11 Conclusion & future work | §8.9, §7.2, §12.4 |
| Appendices | `SETUP_HEAD.md` (installation), `DEMO.md` (user manual), `MANIFEST_FORMAT.md` |

The existing presentation guide (11 slides, three speakers: WHY/WHAT, HOW, FEASIBILITY) stays valid; for later presentations add a live Head demo (`DEMO.md` script) and a "what changed and why" slide from §7.3.

---

## 18. Deliverables produced so far (outside the repository)
Project proposal (docx), progress report with five kiosk screen images (docx), proposal sections 1–2 draft, presentation guide (11 slides) and intro statement, short-answer background paragraphs, SVG logo (Cerberus with a cyber twist), kiosk UI designs (design canvas), earlier Head setup notes (superseded by `SETUP_HEAD.md`), extended research report on prior art and incidents. Store final copies in `docs/reports/`.

---

## 19. Glossary
| Term | Meaning |
|---|---|
| Head | Raspberry Pi validation node at a checkpoint |
| Sentinel | Windows endpoint agent |
| Warden | audit/key-management server |
| Manifest | signed list of every file and its SHA-256 on a validated drive |
| key_id | first 16 hex characters of SHA-256 over a Head's public-key PEM |
| Trust store | the set of Head public keys a Sentinel accepts |
| Ed25519 | elliptic-curve signature scheme used for manifests |
| EICAR | harmless standard antivirus test string |
| ClamAV / clamd / clamdscan / freshclam | open-source scanner / its daemon / its client / its updater |
| AlertExceedsMax | ClamAV setting: flag files over limits instead of skipping them |
| udev / pyudev | Linux device-event system / its Python binding |
| sudoers | file granting specific root commands to specific accounts |
| systemd unit / tmpfiles.d | service definition / rules creating runtime directories at boot |
| Kiosk | the fullscreen operator screen, and the account that runs it |
| state.json | status file the daemon writes and the screen reads |
| Heartbeat | periodic re-write proving the daemon is alive |
| Fail closed | on any doubt, refuse |
| TOCTOU | time-of-check to time-of-use: something changes between checking and using |
| Superfloppy | drive formatted with no partition table |
| RSA (Windows) | Removable Storage Access policies — not the cipher |
| MLGPO | Multiple Local Group Policy (e.g. a policy for Non-Administrators only) |
| LocalSystem / SYSTEM | the Windows account services run as |
| Session 0 isolation | services run in a session with no user desktop |
| MOTW | Mark-of-the-Web (`Zone.Identifier` stream) making Windows treat files as downloaded |
| ADS | NTFS alternate data stream |
| System Volume Information | folder where Windows keeps per-volume housekeeping files |
| HID / BadUSB | devices posing as keyboards; firmware attacks — out of scope |
| PARAMOUNT | this project's marker for crucial steps |

---

## 20. Continuation prompts (copy, paste, then attach this file)
1. **Onboarding:** "You are joining Project Cyrberus as a technical assistant. Read the attached HANDOFF.md completely. Restate the ground rules in §0.2 in your own words, list the open decisions D1–D11 with the recommended option for each, and ask me which task to start."
2. **Sentinel spike script:** "Using HANDOFF §10.7 and the reference verifier in Appendix C, write a Python script for Windows that runs as SYSTEM (we will launch it with `psexec -s -i`), subscribes to Win32_VolumeChangeEvent, and on each arrival verifies the new drive and logs the verdict. Explain how to test T2 and T6 step by step, including installing Python for all users."
3. **Workstation baseline:** "Using the table in HANDOFF §10.5, write `apply-baseline.ps1` and `revert-baseline.ps1` for a lab Windows 11 Pro machine. Script only the machine-wide (HKLM) controls; for the user-scope control 2, explain the manual MLGPO steps for Non-Administrators and, separately, how LGPO.exe could do it (mark it SPIKE). Mark every SPIKE item with a comment and print what changed."
4. **Release engine:** "Port the reference verifier in HANDOFF Appendix C (also attach sentinel/verify_manifest.py and common/manifest_lib.py) into a module that verifies a drive in the normative order (§9.3, including the exact-behaviour table) and releases files by hashing while copying into a SYSTEM-only staging folder, then moving them into the console user's Inbox and resetting permissions (§10.4). Copy only main data streams. It must reach the expected verdict on every case produced by tests/make_sentinel_fixtures.py."
5. **Service:** "Wrap the release engine in a pywin32 Windows service running as LocalSystem, with event-log logging and a per-user status file a notifier can read (Session 0 isolation). Include install/uninstall commands."
6. **Report writing:** "Using HANDOFF §5, §7.3, §8 and §14, draft the Implementation and Project Management sections of our progress report in the course structure (§17). Keep claims to what the document shows as DONE."
7. **Coursework mapping:** "Here are our transcript and the syllabi of relevant courses. Fill the table in HANDOFF §16.4: for each course, quote objectives, map them to Cyrberus elements with concrete evidence, and flag anything not covered."
8. **Threat model review:** "Review HANDOFF §12 against the Sentinel design in §10. Add threats specific to design C, propose mitigations, and identify which residual risks we must state in the final report."

---

## Appendix A — Head command cheat sheet
```bash
sudo bash /opt/cyrberus/deploy/install-head.sh [--dry-run]     # install / update (idempotent)
sudo bash /opt/cyrberus/deploy/preflight.sh                    # readiness: must say READY
bash /opt/cyrberus/deploy/boot-mode.sh status                  # what runs now / at boot
sudo bash /opt/cyrberus/deploy/boot-mode.sh on|off|restart     # boot-to-standby switch
sudo bash /opt/cyrberus/tests/run_all.sh                       # all tests incl. real mounts
journalctl -u cyrberus-scanner -f                              # live log
/opt/cyrberus/venv/bin/python3 /opt/cyrberus/sentinel/verify_manifest.py <mount> /var/lib/cyrberus/head_public.pem
python3 tests/make_sentinel_fixtures.py sentinel-fixtures      # Sentinel test vectors
python3 head/sign_manifest.py keygen labkeys                   # lab keypair (test machines only)
python3 head/sign_manifest.py sign <drive> labkeys/lab_private.pem labkeys/lab_public.pem
sudo poweroff
```

## Appendix B — where to find more
`docs/SETUP_HEAD.md` (build a Head, operate, troubleshoot) · `docs/DEMO.md` (demonstrations) · `docs/MANIFEST_FORMAT.md` (normative format) · `README.md` (overview).

## Appendix C — reference verifier source
Verbatim copies of the code a Sentinel port must reproduce, included so this file is self-contained. **The repository files are authoritative**; if they change, regenerate this appendix.

<!-- APPENDIX-C-START -->
### `sentinel/verify_manifest.py`
```python
"""Sentinel side: reference verifier for manifest schema 1.

Returns (ok, reason). The Windows Sentinel ports this logic. The ORDER of the
checks is normative (MANIFEST_FORMAT.md section 5): the signature is verified
over the raw bytes BEFORE the JSON is parsed as trusted input, so untrusted
media never reaches the parser as authenticated data.

Behaviour a port must reproduce exactly:
  * key_id = first 16 hex of SHA-256 over the trusted PEM file's exact bytes
  * manifest.sig = standard base64 of 64 bytes; surrounding whitespace ignored
  * expired when now >= expires_at (UTC); exactly at expiry is expired
  * paths compared case-insensitively (MANIFEST_FORMAT.md section 8 - FAT,
    exFAT and NTFS are case-insensitive) using SIMPLE per-character upper-
    casing, as NTFS and .NET StringComparison.OrdinalIgnoreCase do: a
    character whose uppercase is several characters is left as it is, so
    "Straße" and "STRASSE" are different names. Two paths that are equal
    under this folding on either side make the drive ambiguous -> deny
  * any exception anywhere -> deny (fail closed)

    python3 sentinel/verify_manifest.py <drive_root> <trusted_pub.pem> [more.pem ...]
"""
import json
import os
import sys
from datetime import datetime, timezone

# Run as a script, Python only searches sentinel/. The shared format code
# lives in common/.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "common"))

from cryptography.hazmat.primitives import serialization       # noqa: E402
from cryptography.exceptions import InvalidSignature           # noqa: E402
import manifest_lib as M                                       # noqa: E402


def fold(path):
    """Case-insensitive key: simple per-character uppercase (see module doc)."""
    out = []
    for ch in path:
        up = ch.upper()
        out.append(up if len(up) == 1 else ch)
    return "".join(out)


def _by_folded_path(items, side):
    """{folded path: entry}; refuses paths that differ only in case."""
    out = {}
    for e in items:
        k = fold(e["path"])
        if k in out:
            raise ValueError("%s has two paths that differ only in case: %s / %s"
                             % (side, out[k]["path"], e["path"]))
        out[k] = e
    return out


def verify_device(mount_root, trusted_pubkeys, now=None):
    """trusted_pubkeys: {key_id: pem_bytes} for every Head this endpoint trusts."""
    try:
        return _verify(mount_root, trusted_pubkeys, now or datetime.now(timezone.utc))
    except Exception as e:                       # fail closed on anything unforeseen
        return False, "verification error: %s: %s" % (type(e).__name__, e)


def _verify(mount_root, trusted_pubkeys, now):
    mpath = os.path.join(mount_root, M.MANIFEST_DIR, M.MANIFEST_NAME)
    spath = os.path.join(mount_root, M.MANIFEST_DIR, M.SIG_NAME)

    # 1. Both files present.
    if not (os.path.isfile(mpath) and os.path.isfile(spath)):
        return False, "no manifest present"

    # 2. Raw bytes; decode the signature.
    with open(mpath, "rb") as f:
        blob = f.read()
    with open(spath, "rb") as f:
        try:
            sig = M.decode_sig(f.read())
        except Exception:
            return False, "signature file is malformed"

    # 3. key_id only, to choose a public key. Nothing else is trusted yet.
    try:
        kid = json.loads(blob.decode("utf-8")).get("key_id")
    except Exception:
        return False, "manifest is not valid JSON"
    pem = trusted_pubkeys.get(kid)
    if pem is None:
        return False, "manifest signed by an unknown Head (key_id %s)" % kid

    # 4. Signature over the raw bytes.
    try:
        pub = serialization.load_pem_public_key(pem)
    except Exception:
        return False, "trusted key for key_id %s is unreadable" % kid
    try:
        pub.verify(sig, blob)
    except InvalidSignature:
        return False, "signature does not match manifest"

    # 5. Only now is the content trusted.
    manifest = json.loads(blob.decode("utf-8"))

    # 6. Schema.
    if manifest.get("schema") != M.SCHEMA:
        return False, "unsupported manifest schema %r" % manifest.get("schema")

    # 7. Expiry (UTC). Exactly at expires_at counts as expired.
    try:
        expires = M.parse_iso_z(manifest["expires_at"])
    except Exception:
        return False, "manifest has an unreadable expiry"
    if now >= expires:
        return False, "validation expired at %s" % manifest["expires_at"]

    # 8. Walk the drive: anything that is not a plain file denies. No hashing yet.
    entries, problems = M.walk_payload(mount_root, hash_files=False)
    if problems:
        return False, "device contains %s: %s" % (problems[0][0], problems[0][1])

    try:
        on_disk = _by_folded_path(entries, "drive")
        listed = _by_folded_path(manifest.get("files", []), "manifest")
    except ValueError as e:
        return False, str(e)

    # 9. Nothing on the drive that the manifest does not list.
    extra = sorted(set(on_disk) - set(listed))
    if extra:
        return False, "file not covered by manifest: %s" % on_disk[extra[0]]["path"]

    # 10. Nothing listed that is missing from the drive.
    missing = sorted(set(listed) - set(on_disk))
    if missing:
        return False, "file listed in manifest is missing: %s" % listed[missing[0]]["path"]

    # 11. Every file the expected size and hash. (A Sentinel that releases
    # files does this while copying - see HANDOFF.md section 10.4.)
    for k in sorted(listed):
        want, got = listed[k], on_disk[k]
        full = os.path.join(mount_root, *got["path"].split("/"))
        if got["size"] != want["size"] or M.sha256_file(full) != want["sha256"]:
            return False, "file changed since validation: %s" % got["path"]

    # 12. All checks passed.
    return True, "valid until %s (%d files)" % (manifest["expires_at"], len(listed))


def load_trusted(paths):
    """{key_id: pem} from PEM files, key_id computed from content (never filename)."""
    trusted = {}
    for p in paths:
        with open(p, "rb") as f:
            pem = f.read()
        trusted[M.key_id(pem)] = pem
    return trusted


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("usage: verify_manifest.py <drive_root> <trusted_pub.pem> [...]")
    ok, reason = verify_device(sys.argv[1], load_trusted(sys.argv[2:]))
    print(("PASS: " if ok else "DENY: ") + reason)
    sys.exit(0 if ok else 1)
```

### `common/manifest_lib.py`
```python
"""Cyrberus manifest: shared format logic for the Head (writer) and Sentinel (verifier).

Schema 1. See MANIFEST_FORMAT.md for the normative spec.
"""
import base64, hashlib, json, os, stat
from datetime import datetime, timezone

SCHEMA = 1
MANIFEST_DIR = ".cyrberus"
MANIFEST_NAME = "manifest.json"
SIG_NAME = "manifest.sig"

# Filesystems a Windows Sentinel can mount and verify natively.
SUPPORTED_FS = {"vfat", "fat32", "exfat", "ntfs"}


def key_id(public_key_bytes: bytes) -> str:
    """Short, stable identifier for a Head's public key.

    SHA-256 over the EXACT bytes of head_public.pem as the Head wrote it (LF
    line endings, no BOM), first 16 hex characters. Nothing is normalised: a
    copy that gained CRLF endings or a BOM (Notepad, email) has a different
    key_id and every drive from that Head reads as "unknown Head". Copy the
    file in binary (scp, a USB stick) and compute key_id from its content.
    """
    return hashlib.sha256(public_key_bytes).hexdigest()[:16]


def sha256_file(path, chunk=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def enumerate_files(root):
    """Paths of every regular file under root, excluding the manifest dir.

    Cheap compared to hashing, so the daemon calls this first to learn the
    total for the progress bar.
    """
    out = []
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == MANIFEST_DIR or rel_dir.startswith(MANIFEST_DIR + os.sep):
            dirnames[:] = []
            continue
        if rel_dir == ".":
            dirnames[:] = [d for d in dirnames if d != MANIFEST_DIR]
        for name in filenames:
            out.append(os.path.join(dirpath, name))
    return out


_REPARSE_POINT = 0x400    # FILE_ATTRIBUTE_REPARSE_POINT; only Windows reports it


def _special(full):
    """Why this entry cannot be described, or None if it is ordinary.

    Symlinks anywhere, and on Windows any reparse point (junctions, mount
    points, cloud placeholders). Checked with lstat so nothing is followed.
    """
    try:
        st = os.lstat(full)
    except OSError as e:
        return "unreadable: %s" % e.strerror
    if stat.S_ISLNK(st.st_mode):
        return "symlink"
    if getattr(st, "st_file_attributes", 0) & _REPARSE_POINT:
        return "reparse point"
    return None


def walk_payload(root, on_progress=None, hash_files=True):
    """Every regular file under root, excluding the manifest directory.

    Returns (entries, problems). A non-empty problems list means the device
    must be rejected: the manifest can only describe regular files, and a
    directory that cannot be read hides files nobody inspected.

    on_progress(done, total) is called as hashing proceeds, so the operator
    screen can show real progress rather than a spinner. hash_files=False
    lists paths and sizes only (the verifier compares file sets first).
    """
    entries, problems = [], []
    total = len(enumerate_files(root)) if on_progress else 0
    done = 0
    root = os.path.abspath(root)

    def rel_of(path):
        return os.path.relpath(path, root).replace(os.sep, "/")

    def unreadable_dir(err):
        # os.walk silently skips directories it cannot list unless told.
        problems.append(("unreadable directory: %s" % err.strerror,
                         rel_of(err.filename or root)))

    for dirpath, dirnames, filenames in os.walk(root, onerror=unreadable_dir):
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == MANIFEST_DIR or rel_dir.startswith(MANIFEST_DIR + os.sep):
            dirnames[:] = []
            continue
        if rel_dir == ".":
            dirnames[:] = [d for d in dirnames if d != MANIFEST_DIR]
        # A symlinked or reparse-point directory is listed here but never
        # descended into - report it rather than silently leaving it out.
        keep = []
        for d in sorted(dirnames):
            why = _special(os.path.join(dirpath, d))
            if why:
                problems.append((why, rel_of(os.path.join(dirpath, d))))
            else:
                keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = rel_of(full)
            why = _special(full)
            if why:
                problems.append((why, rel))
                continue
            if not os.path.isfile(full):
                problems.append(("not-a-regular-file", rel))
                continue
            try:
                entry = {"path": rel, "size": os.path.getsize(full)}
                if hash_files:
                    entry["sha256"] = sha256_file(full)
                entries.append(entry)
            except OSError as e:
                problems.append(("unreadable: %s" % e.strerror, rel))
            if on_progress:
                done += 1
                on_progress(done, total)
    entries.sort(key=lambda e: e["path"])
    return entries, problems


def build_manifest(head_id, kid, issued, expires, device, scan, entries):
    return {
        "schema": SCHEMA,
        "head_id": head_id,
        "key_id": kid,
        "issued_at": issued.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "device": device,
        "scan": scan,
        "files": entries,
    }


def serialize(manifest) -> bytes:
    """The exact bytes written to disk AND the exact bytes signed."""
    return json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")


def parse_iso_z(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def encode_sig(raw: bytes) -> bytes:
    return base64.b64encode(raw) + b"\n"


def decode_sig(blob: bytes) -> bytes:
    """Standard base64 of the 64-byte Ed25519 signature; surrounding
    whitespace (the trailing newline, a stray CR) is ignored, anything else
    outside the base64 alphabet is an error."""
    raw = base64.b64decode(blob.strip(), validate=True)
    if len(raw) != 64:
        raise ValueError("an Ed25519 signature is 64 bytes, got %d" % len(raw))
    return raw
```
<!-- APPENDIX-C-END -->
