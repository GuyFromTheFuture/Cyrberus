"""Device detection and admission.

The admission rules are pure functions over a plain dict, so they can be
tested without hardware. Only `monitor()` and `describe()` touch udev.

Admission policy (MANIFEST_FORMAT.md s6):
  - exactly one partition
  - filesystem is FAT32, exFAT or NTFS
  - the device is USB-attached removable storage, not an internal disk
"""
import subprocess

SUPPORTED_FS = {"vfat", "fat", "fat32", "exfat", "ntfs", "ntfs3"}

# Reasons are phrased for the operator screen, not for a log.
R_OK = None
R_MULTI_PARTITION = "This drive has more than one section on it."
R_NO_PARTITION = "This drive has no readable section on it."
R_UNSUPPORTED_FS = "This drive uses a format we cannot read."
R_ENCRYPTED = "This drive is locked with a password."
R_NOT_REMOVABLE = "That device is not a removable drive."


def admit(record):
    """Decide whether a device may proceed to scanning.

    record: dict from describe(). Returns (ok: bool, reason: str|None).
    """
    if not record.get("is_usb") or not record.get("is_removable"):
        return False, R_NOT_REMOVABLE

    parts = record.get("partitions", [])

    if len(parts) > 1:
        return False, R_MULTI_PARTITION
    if len(parts) == 0:
        return False, R_NO_PARTITION

    part = parts[0]
    fstype = (part.get("fstype") or "").lower()

    if fstype in ("crypto_luks", "bitlocker") or part.get("encrypted"):
        return False, R_ENCRYPTED
    if fstype not in SUPPORTED_FS:
        return False, R_UNSUPPORTED_FS

    return True, R_OK


def device_block(record):
    """The `device` object for the manifest.

    Descriptive only. Per MANIFEST_FORMAT.md s7.1 none of this is ever used
    to decide trust - USB descriptors are self-reported by the device.
    """
    part = (record.get("partitions") or [{}])[0]
    return {
        "vendor_id": record.get("vendor_id", ""),
        "product_id": record.get("product_id", ""),
        "serial": record.get("serial", ""),
        "model": record.get("model", ""),
        "size_bytes": record.get("size_bytes", 0),
        "filesystem": (part.get("fstype") or "").lower(),
        "partition_count": len(record.get("partitions", [])),
    }


# --------------------------------------------------------------------------
# udev adapter. Everything below talks to hardware and is not unit-tested.
# --------------------------------------------------------------------------

def _int_attr(dev, name, default=0):
    try:
        return int(dev.attributes.asstring(name))
    except (KeyError, ValueError, UnicodeDecodeError, AttributeError):
        return default


def describe(dev):
    """Build a device record from a pyudev block device (the whole disk)."""
    parts = []
    for child in dev.children:
        if child.get("DEVTYPE") != "partition":
            continue
        parts.append({
            "node": child.device_node,
            "fstype": child.get("ID_FS_TYPE") or "",
            "label": child.get("ID_FS_LABEL") or "",
            "uuid": child.get("ID_FS_UUID") or "",
            "size_bytes": _int_attr(child, "size") * 512,
            "encrypted": (child.get("ID_FS_TYPE") or "").lower()
                         in ("crypto_luks", "bitlocker"),
        })
    parts.sort(key=lambda p: p["node"])

    # A device formatted without a partition table ("superfloppy") carries a
    # filesystem on the whole disk. Treat that as a single partition.
    if not parts and dev.get("ID_FS_TYPE"):
        parts.append({
            "node": dev.device_node,
            "fstype": dev.get("ID_FS_TYPE") or "",
            "label": dev.get("ID_FS_LABEL") or "",
            "uuid": dev.get("ID_FS_UUID") or "",
            "size_bytes": _int_attr(dev, "size") * 512,
            "encrypted": False,
        })

    return {
        "node": dev.device_node,
        "is_usb": (dev.get("ID_BUS") == "usb"),
        "is_removable": bool(_int_attr(dev, "removable", 0)) or dev.get("ID_BUS") == "usb",
        "vendor_id": dev.get("ID_VENDOR_ID", ""),
        "product_id": dev.get("ID_MODEL_ID", ""),
        "serial": dev.get("ID_SERIAL_SHORT", ""),
        "model": (dev.get("ID_MODEL") or "").replace("_", " ").strip(),
        "vendor": (dev.get("ID_VENDOR") or "").replace("_", " ").strip(),
        "size_bytes": _int_attr(dev, "size") * 512,
        "partitions": parts,
    }


def describe_by_node(node):
    """Describe a device by path, e.g. /dev/sda. Used by the CLI."""
    import pyudev
    ctx = pyudev.Context()
    dev = pyudev.Devices.from_device_file(ctx, node)
    return describe(dev)


def monitor():
    """Yield ('add'|'remove', record) as whole USB disks appear and vanish.

    Partition events are deliberately ignored: the unit of validation is the
    device, and a partitioned disk emits one event per partition.
    """
    import pyudev
    ctx = pyudev.Context()
    mon = pyudev.Monitor.from_netlink(ctx)
    mon.filter_by("block")

    for action, dev in iter(mon):
        if dev.get("DEVTYPE") != "disk":
            continue
        if dev.get("ID_BUS") != "usb":
            continue
        if action == "add":
            # udev announces the disk before its partitions are enumerated.
            import time
            time.sleep(1.2)
            try:
                dev = pyudev.Devices.from_device_file(ctx, dev.device_node)
            except Exception:
                pass
            yield "add", describe(dev)
        elif action == "remove":
            yield "remove", {"node": dev.device_node}


def current_usb_disks():
    """Every USB disk attached right now. Used at startup."""
    import pyudev
    ctx = pyudev.Context()
    out = []
    for dev in ctx.list_devices(subsystem="block", DEVTYPE="disk"):
        if dev.get("ID_BUS") == "usb":
            out.append(describe(dev))
    return out


def human_size(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return "%g %s" % (round(n, 1), unit)
        n /= 1024.0
