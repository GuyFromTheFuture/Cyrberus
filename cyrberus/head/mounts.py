"""Mounting untrusted media.

Every scan mount is read-only and stripped of the ability to execute, escalate
or expose devices. To write the manifest the daemon unmounts, mounts fresh
read-write (noexec/nosuid/nodev still applied) for exactly as long as the write
takes, then unmounts again. It never remounts in place - see mount_rw().

Mount options, and why each is there:
  ro        the Head never modifies evidence, and nothing can change mid-scan
  noexec    nothing on the device can be executed, even by accident
  nosuid    setuid bits on the device are ignored - blocks a planted binary
            from gaining privilege
  nodev     device nodes on the device are ignored
"""
import os
import subprocess

SAFE_OPTS = ["ro", "noexec", "nosuid", "nodev"]
MOUNT = "/usr/bin/mount"
UMOUNT = "/usr/bin/umount"


class MountError(Exception):
    pass


def _opts_for(fstype, uid, gid, writable=False):
    opts = list(SAFE_OPTS)
    if writable:
        opts[0] = "rw"
    fstype = (fstype or "").lower()
    # FAT and exFAT carry no ownership metadata, so it must be supplied at
    # mount time or the unprivileged daemon cannot read the files.
    if fstype in ("vfat", "fat", "fat32", "exfat", "ntfs", "ntfs3"):
        opts += ["uid=%d" % uid, "gid=%d" % gid, "umask=0077"]
    # FAT stores long names as UTF-16. How Linux shows them otherwise depends
    # on a kernel build default (often ASCII or Latin-1), and a mangled name
    # in the manifest would make every Sentinel deny the drive. utf8 is the
    # option the kernel's vfat documentation recommends; shortname=mixed shows
    # 8.3 names as stored, the way Windows shows them. exFAT already defaults
    # to UTF-8 and rejects the utf8 flag, so it is left alone.
    if fstype in ("vfat", "fat", "fat32"):
        opts += ["utf8", "shortname=mixed"]
    return ",".join(opts)


def mount_ro(node, mountpoint, fstype=None, uid=None, gid=None, sudo=True):
    """Mount read-only with the hardened option set."""
    uid = os.getuid() if uid is None else uid
    gid = os.getgid() if gid is None else gid
    os.makedirs(mountpoint, exist_ok=True)

    cmd = ([ "sudo", "-n" ] if sudo else []) + [MOUNT, "-o", _opts_for(fstype, uid, gid)]
    if fstype:
        cmd += ["-t", fstype]
    cmd += [node, mountpoint]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise MountError((proc.stderr or proc.stdout).strip() or
                         "mount failed with status %d" % proc.returncode)
    return mountpoint


def mount_rw(node, mountpoint, fstype=None, uid=None, gid=None, sudo=True):
    """Mount writable, for the manifest write only.

    The daemon unmounts the read-only scan mount first and mounts fresh
    rather than remounting in place: an in-place ro->rw remount can be
    refused when the backing device is write-protected, and a fresh mount
    makes the two phases unambiguous. noexec, nosuid and nodev still apply.
    """
    uid = os.getuid() if uid is None else uid
    gid = os.getgid() if gid is None else gid
    os.makedirs(mountpoint, exist_ok=True)

    cmd = (["sudo", "-n"] if sudo else []) + \
          [MOUNT, "-o", _opts_for(fstype, uid, gid, writable=True)]
    if fstype:
        cmd += ["-t", fstype]
    cmd += [node, mountpoint]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise MountError((proc.stderr or proc.stdout).strip() or
                         "read-write mount failed with status %d" % proc.returncode)
    return mountpoint


def unmount(mountpoint, sudo=True, force=False):
    """Unmount, tolerating an already-unmounted path."""
    if not os.path.ismount(mountpoint):
        return False
    cmd = (["sudo", "-n"] if sudo else []) + [UMOUNT]
    if force:
        cmd.append("-l")               # lazy: detach even if something holds it
    cmd.append(mountpoint)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        if not force:
            return unmount(mountpoint, sudo=sudo, force=True)
        raise MountError((proc.stderr or proc.stdout).strip() or "unmount failed")
    return True


def sync():
    """Flush pending writes before the user pulls the drive out."""
    subprocess.run(["sync"], capture_output=True)
