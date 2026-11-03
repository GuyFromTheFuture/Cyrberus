# Cyrberus Manifest Format — Schema 1

**Status:** frozen for v1 implementation
**Applies to:** the Head (writer) and the Sentinel (verifier)

This is the contract between the two halves of Cyrberus. Once frozen, the Head and the Sentinel can be developed independently against it. Any change to this document after freeze requires incrementing `schema` and updating both halves.

---

## 1. What the manifest asserts

A manifest is a signed statement by a named Head that, at a stated time, it inspected a removable device and found a specific set of files, each with a specific SHA-256 hash, and no others.

It asserts nothing about the device's identity, and nothing about whether the files are *safe* — only that they contained no malware known to the scanning engine at that moment, and that they have not changed since.

---

## 2. Files written to the device

At the root of the device's single partition:

```
.cyrberus/
    manifest.json      UTF-8 JSON, exactly the bytes that were signed
    manifest.sig       base64-encoded Ed25519 signature, one line
```

The `.cyrberus/` directory is excluded from the manifest's own file list — it cannot describe itself.

---

## 3. Structure

```json
{
  "schema": 1,
  "head_id": "head-01",
  "key_id": "3f9a2c1d8e4b7006",
  "issued_at": "2026-10-29T05:10:18Z",
  "expires_at": "2026-10-29T17:10:18Z",
  "device": {
    "vendor_id": "0781",
    "product_id": "5581",
    "serial": "4C530001",
    "model": "SanDisk Ultra",
    "size_bytes": 32015679488,
    "filesystem": "vfat",
    "partition_count": 1
  },
  "scan": {
    "engine": "ClamAV",
    "engine_version": "1.0.7",
    "signature_version": "27234",
    "files_scanned": 4,
    "bytes_scanned": 4203,
    "duration_seconds": 1.2
  },
  "files": [
    {
      "path": "Documents/2026/notes.md",
      "size": 8,
      "sha256": "4a28fc250c09e1f28c9f37486fca6db3c7a4ee707373216f6f7bd62ade5d9330"
    }
  ]
}
```

### Field reference

| Field | Type | Meaning |
|---|---|---|
| `schema` | int | Format version. A Sentinel rejects any value it does not implement. |
| `head_id` | string | Human-readable name of the issuing Head, for audit. Not a trust basis. |
| `key_id` | string | First 16 hex chars of SHA-256 over the Head's public key PEM. Selects which trusted key verifies this manifest. |
| `issued_at` | string | UTC, `YYYY-MM-DDTHH:MM:SSZ`. |
| `expires_at` | string | UTC, same format. After this instant the device is untrusted. |
| `device.*` | object | Descriptive only — recorded for logging and incident response. **Never used to decide trust** (see §7.2). |
| `scan.*` | object | What inspected the device and with which signature set. Lets an incident responder ask "was this drive validated before or after the signature update that would have caught it?" |
| `files[]` | array | Exhaustive list of every regular file on the partition, sorted by `path`. |
| `files[].path` | string | Relative to partition root, forward-slash separated, no leading slash, UTF-8. |
| `files[].size` | int | Bytes. Checked before the hash as a cheap early mismatch. |
| `files[].sha256` | string | Lowercase hex. |

An empty device produces a manifest with `"files": []`. This is valid.

---

## 4. Signing

The signature covers **the exact bytes written to `manifest.json`** — not a re-serialization of the parsed object.

Serialization is `json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False)` encoded UTF-8. Sorted keys and fixed indentation make the output reproducible, but the verifier never depends on that: it signs and verifies over literal file bytes.

Signature: Ed25519 over those bytes, base64-encoded with a trailing newline in `manifest.sig`.

> **Why a detached signature.** Embedding the signature inside the JSON would require canonical serialization — both sides agreeing byte-for-byte on key order, whitespace, and Unicode escaping before hashing. That is a well-known source of signature-bypass bugs. Signing the file's literal bytes eliminates the problem: there is exactly one byte sequence, and it is the one on disk.

---

## 5. Verification algorithm (normative)

The Sentinel performs these steps **in this order**. The ordering is part of the spec.

1. Locate `.cyrberus/manifest.json` and `.cyrberus/manifest.sig`. Either missing → **deny**.
2. Read `manifest.json` as raw bytes. Read and base64-decode `manifest.sig`. Malformed → **deny**.
3. Extract `key_id` only, to select a public key. Unknown `key_id` → **deny**.
4. **Verify the Ed25519 signature over the raw bytes.** Invalid → **deny**.
5. Only now parse the JSON as trusted input.
6. `schema` not implemented → **deny**.
7. `expires_at` in the past → **deny**.
8. Walk the partition, excluding `.cyrberus/`. Any symlink, reparse point, device node, or unreadable entry → **deny**.
9. Any file on disk absent from `files[]` → **deny**.
10. Any entry in `files[]` absent from disk → **deny**.
11. Any size or hash mismatch → **deny**.
12. All checks pass → **mount read-only**.

Step 4 before step 5 matters: untrusted media must never reach a JSON parser as authenticated input. Step 3 reads one field from unverified bytes purely to select a key, and nothing else is trusted until the signature verifies.

Steps 9 and 10 are both required. Checking only one direction would let an attacker add a file (9 catches it) or substitute a removal (10 catches it).

---

## 6. Rejection rules outside the manifest

The Head refuses to issue a manifest at all when:

- The device presents **more than one partition.** Validating one partition while another goes uninspected is the evasion this closes. Multi-partition devices get the "cannot check" screen.
- The filesystem is not FAT32, exFAT, or NTFS. These are the filesystems a Windows Sentinel can mount and verify natively; validating an ext4 drive would produce a manifest no Sentinel could check.
- The device is encrypted or otherwise unreadable.
- Any entry is not a regular file.
- The scan reports a detection, or reports files it could not fully inspect (`AlertExceedsMax`).

---

## 7. Design rationale

### 7.1 Why content, not device identity

USB descriptors — vendor ID, product ID, serial number — are values stored in device firmware and reported by the device itself. A programmable device presents whatever it likes. Binding trust to them is binding trust to an attacker-controlled string.

The manifest therefore binds to a hash of the actual bytes on the device. `device.*` is recorded for audit value only, and the Sentinel must not use it in any trust decision.

### 7.2 Why read-only mounting

Because the manifest is an exhaustive statement about the device's contents, any write invalidates it. Mounting read-only keeps a validated device valid for its full window across repeated mounts, and avoids a confusing failure mode where a drive that worked at 9 a.m. is refused at 2 p.m. because the user saved a file to it.

**Consequence worth stating plainly:** Cyrberus v1 provides no supported way to copy data *out* of a protected workstation onto removable media. Organizations needing data export require a separate process. This is a deliberate limitation and should be documented as such.

### 7.3 Why a time limit

A manifest is a bearer credential. The `expires_at` field bounds how long a compromised or re-acquired device remains trusted, on the same reasoning as Kerberos ticket lifetimes. Twelve hours covers one working day.

---

## 8. Known limitations

| Limitation | Notes |
|---|---|
| **TOCTOU** | A device capable of emulating mass storage can serve different content to the Head than to the Sentinel. Re-hashing at mount time raises the cost substantially but does not close it. Applies equally to commercial products in this category. |
| **Clock dependence** | `expires_at` is checked against the endpoint's clock. An attacker with local admin can set the clock back and extend validity. |
| **Detection is probabilistic** | A valid manifest means "no *known* malware at scan time," never "safe." |
| **No HID coverage** | The manifest describes storage contents. A device enumerating as a keyboard is outside this format entirely. |
| **Manifest size** | Roughly 230 bytes per file entry. A 50,000-file device yields a manifest around 12 MB — large but parseable. Cap the file count in Head configuration to match ClamAV's `MaxFiles`. |
| **Path case** | FAT32, exFAT, and NTFS are case-insensitive but case-preserving. The Head records the preserved case. A Windows Sentinel should compare paths case-insensitively to avoid false denials. |

---

## 9. Changing this format

Any change to field meaning, serialization, or the verification algorithm requires incrementing `schema`. A Sentinel must deny manifests whose schema it does not implement rather than attempting a best-effort parse.

During development, both halves are pinned to `schema: 1`.
