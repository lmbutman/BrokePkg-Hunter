#!/usr/bin/env python3
"""
find_hidden_no_marker_filtered.py
Like find_hidden_no_marker.py but filters out self-generated noise (script filename, commands used, temp files).
Usage: sudo ./find_hidden_no_marker_filtered.py [--no-raw] [--raw-only] [--minlen 8] [--devices /dev/sda,/dev/sdb]
"""
import os
import re
import sys
import argparse
import subprocess
from shutil import which
from collections import defaultdict

DEFAULT_MIN_PRINTABLE = 8
CHUNK = 4 * 1024 * 1024
OVERLAP = 4096

def run_find(min_len):
    print("[1] Gathering visible paths via find (kernel view)...")
    cmd = ["find", "/", "-xdev", "-print"]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except subprocess.CalledProcessError:
        print("  (find returned nonzero; streaming output)")
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        out = p.communicate()[0] if p.stdout is not None else ""
    visible = set()
    for line in out.splitlines():
        line = line.strip()
        if len(line) >= min_len:
            visible.add(line)
    print(f"  -> collected {len(visible)} visible path entries\n")
    return visible

def run_debugfs_on_exts():
    if which("debugfs") is None:
        print("[2] debugfs not found — skipping ext2/3/4 metadata scan.\n")
        return set()
    print("[2] Attempting debugfs on mounted ext2/3/4 partitions (direct metadata reads)...")
    candidates = set()
    try:
        with open("/proc/mounts", "r") as f:
            mounts = [line.split()[:3] for line in f]
    except Exception as e:
        print("  Could not read /proc/mounts:", e)
        return candidates

    for dev, mnt, fstype in mounts:
        if not dev.startswith("/") or fstype not in ("ext2","ext3","ext4"):
            continue
        print(f"  - device {dev} mounted on {mnt} ({fstype})")
        try:
            dbg_cmd = ["sudo", "debugfs", "-R", f"ls -p {mnt}", dev]
            out = subprocess.check_output(dbg_cmd, stderr=subprocess.DEVNULL, text=True)
            for line in out.splitlines():
                s = line.strip()
                if "/" in s and len(s) > 3:
                    candidates.add(s)
        except Exception as e:
            print("    debugfs failed for", dev, ":", e)
    print(f"  -> debugfs returned ~{len(candidates)} candidate tokens\n")
    return candidates

def list_block_devices():
    devs=[]
    if which("lsblk"):
        try:
            out = subprocess.check_output(["lsblk","-ndo","NAME,TYPE"], text=True)
            for line in out.splitlines():
                parts=line.split()
                if len(parts)>=2 and parts[1] in ("disk","part"):
                    devs.append("/dev/"+parts[0])
        except Exception:
            pass
    if not devs:
        for p in ("/dev/sda","/dev/nvme0n1","/dev/rdisk0"):
            if os.path.exists(p):
                devs.append(p)
    devs=[d for d in devs if os.path.exists(d)]
    return devs

def extract_printable_paths_from_bytes(buf, min_len):
    printable_re = re.compile(rb"[ -~]{%d,}" % min_len)
    out = set()
    for m in printable_re.finditer(buf):
        try:
            s = m.group(0).decode('ascii', errors='ignore')
        except:
            continue
        if "/" in s:
            parts = re.split(r"[\x00-\x1F\s]+", s)
            for p in parts:
                if "/" in p and len(p) >= min_len:
                    p = p.strip(" \t\n\r\x00\"'<>|,;")
                    if len(p) >= min_len and p.count("/")>=1:
                        out.add(p)
    return out

def raw_scan_devices(devices, min_len):
    print("[3] Raw block device scan (extract printable sequences that look like paths).")
    print("    Note: this can be slow and noisy.")
    candidates = set()
    for dev in devices:
        print("  Scanning", dev)
        try:
            with open(dev, "rb", buffering=0) as f:
                offset=0
                prev=b""
                while True:
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    data = prev + chunk
                    found = extract_printable_paths_from_bytes(data, min_len)
                    if found:
                        for p in found:
                            candidates.add(p)
                    prev = data[-OVERLAP:]
                    offset += len(chunk)
        except PermissionError:
            print("    Permission denied for", dev, "- run as root to scan raw devices.")
        except Exception as e:
            print("    Error scanning", dev, ":", e)
    print(f"  -> raw scan produced {len(candidates)} unique candidate path-like strings\n")
    return candidates

def normalize_candidates(cands):
    out=set()
    for c in cands:
        if "\x00" in c:
            c = c.split("\x00",1)[0]
        c = c.strip()
        if len(c) < 4:
            continue
        out.add(c)
    return out

def build_self_blacklist(script_path):
    """
    Build blacklist of tokens that indicate self-noise:
     - script filename and directory
     - interpreter binary path (sys.executable)
     - common commands the script runs (find, debugfs, strings, dd, lsblk, grep)
     - any temp file patterns we might produce (/tmp/*debugfs*, /tmp/*)
    """
    bl = set()
    # script absolute path and components
    try:
        script_abspath = os.path.abspath(script_path)
        bl.add(script_abspath)
        for p in script_abspath.split(os.sep):
            if p:
                bl.add(p)
    except Exception:
        pass

    # python interpreter
    try:
        bl.add(sys.executable)
        bl.update([os.path.basename(sys.executable)])
    except Exception:
        pass

    # commands used by script
    known_cmds = ["find", "debugfs", "strings", "dd", "lsblk", "grep", "sudo", "python", "python3"]
    for c in known_cmds:
        bl.add(c)
        bl.add("/usr/bin/" + c)
        bl.add("/bin/" + c)

    # tmp patterns (generic)
    bl.add("/tmp")
    bl.add("tmp")
    bl.add("/var/tmp")

    # cwd and its components
    try:
        cwd = os.path.abspath(os.getcwd())
        bl.add(cwd)
        for p in cwd.split(os.sep):
            if p:
                bl.add(p)
    except Exception:
        pass

    # also include the current username
    try:
        bl.add(os.getlogin())
    except Exception:
        pass

    # reduce tokens to those longer than 1 char to avoid over-filtering
    bl = {t for t in bl if isinstance(t, str) and len(t) > 1}
    return bl

def is_blacklisted(candidate, blacklist_tokens):
    """
    Return True if candidate contains any blacklist token (case-sensitive),
    or looks obviously like a short command path we don't care about.
    """
    # quick rejects
    for tok in blacklist_tokens:
        if tok in candidate:
            return True

    # reject very short filename fragments like '/bin/ls' only if bin/tool in blacklist
    # otherwise keep
    return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-raw", action="store_true", help="skip raw block-device scan")
    parser.add_argument("--raw-only", action="store_true", help="only run raw block-device scan")
    parser.add_argument("--devices", help="comma-separated device list to scan (e.g. /dev/disk0s2,/dev/sda1)")
    parser.add_argument("--minlen", type=int, default=DEFAULT_MIN_PRINTABLE, help="min printable sequence length to consider (default 8)")
    args = parser.parse_args()
    min_len = args.minlen

    if os.geteuid() != 0:
        print("Warning: running without root may prevent scanning raw devices. For best results, run as root.")

    visible = set()
    raw_candidates = set()
    meta_candidates = set()

    if not args.raw_only:
        visible = run_find(min_len)
        meta_candidates = run_debugfs_on_exts()

    if not args.no_raw:
        devices = []
        if args.devices:
            devices = [d.strip() for d in args.devices.split(",") if d.strip()]
        else:
            devices = list_block_devices()
            if not devices:
                print("No block devices auto-detected; on macOS you may need to supply --devices /dev/diskX (raw device nodes).")

        if devices:
            raw_candidates = raw_scan_devices(devices, min_len)
        else:
            print("Skipping raw scan (no devices available).")

    # Build blacklist and normalize candidates
    blacklist = build_self_blacklist(__file__)
    visible_norm = set(p.rstrip("/") for p in visible)
    raw_norm = normalize_candidates(raw_candidates | meta_candidates)

    # Filter out candidates containing any blacklist token
    filtered_raw = set()
    for cand in raw_norm:
        if is_blacklisted(cand, blacklist):
            continue
        filtered_raw.add(cand)

    # find candidates likely hidden (present in raw/meta but not in visible)
    hidden = []
    for cand in sorted(filtered_raw):
        if cand.startswith("/"):
            if cand not in visible_norm:
                hidden.append(cand)
        else:
            segs = [s for s in cand.split("/") if s]
            if len(segs) >= 2:
                maybe = "/" + "/".join(segs[-3:])
                if maybe not in visible_norm:
                    hidden.append(cand)

    print("\n=== Summary ===")
    print(f"Visible entries (find): {len(visible_norm)}")
    print(f"Raw/meta candidate path-like strings (before filtering): {len(raw_norm)}")
    print(f"Raw/meta after self-noise filtering: {len(filtered_raw)}")
    print(f"Likely-hidden candidates (not visible): {len(hidden)}\n")

    if hidden:
        print("Likely hidden items (examples):")
        for i,c in enumerate(hidden[:200], 1):
            print(f" {i:3d}. {c}")
    else:
        print("No obvious hidden path candidates found (after filtering).")

    print("\nNotes & next steps:")
    print(" - The blacklist is conservative; it tries to exclude script/tool artefacts. If you see legitimate paths being filtered, we can relax it.")
    print(" - If you still get many false positives, consider imaging the device and analyzing on a clean system (most reliable).")
    print(" - You can supply --devices to target a specific block device (helps on macOS).")

if __name__ == "__main__":
    main()
