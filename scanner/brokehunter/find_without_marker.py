#!/usr/bin/env python3
"""
find_hidden_no_marker.py
Defensive tool: try to discover files/dirs hidden by a kernel rootkit WITHOUT knowing a marker.
Techniques:
 - collect visible names via `find` (what the running kernel exposes)
 - (optional) gather metadata-driven listings via debugfs for ext filesystems
 - raw block-device scan: extract printable sequences that look like paths (contain '/')
 - report candidates that appear in raw metadata/strings but are NOT visible via find

Usage: sudo ./find_hidden_no_marker.py [--no-raw] [--raw-only] [--minlen 8] [--devices /dev/sda,/dev/sdb]
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
        # sometimes find returns nonzero; try streaming instead
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
            # Use debugfs to recursively list directories; its output often reveals names hidden from userspace
            dbg_cmd = ["sudo", "debugfs", "-R", f"ls -p {mnt}", dev]
            out = subprocess.check_output(dbg_cmd, stderr=subprocess.DEVNULL, text=True)
            # extract printable-looking tokens with slashes
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
        # fallback: common device patterns (Linux); macOS will need providing device list via --devices
        for p in ("/dev/sda","/dev/nvme0n1"):
            if os.path.exists(p):
                devs.append(p)
    # filter
    devs=[d for d in devs if os.path.exists(d)]
    return devs

def extract_printable_paths_from_bytes(buf, min_len):
    # find ASCII printable sequences with slashes
    # printable = bytes 0x20..0x7e
    printable_re = re.compile(rb"[ -~]{%d,}" % min_len)
    out = set()
    for m in printable_re.finditer(buf):
        try:
            s = m.group(0).decode('ascii', errors='ignore')
        except:
            continue
        if "/" in s:
            # split by whitespace/newline to get probable path segments
            parts = re.split(r"[\x00-\x1F\s]+", s)
            for p in parts:
                if "/" in p and len(p) >= min_len:
                    # Normalize possible trailing punctuation
                    p = p.strip(" \t\n\r\x00\"'<>|")
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
                    # extract printable strings containing '/'
                    found = extract_printable_paths_from_bytes(data, min_len)
                    if found:
                        for p in found:
                            candidates.add(p)
                    # keep overlap
                    prev = data[-OVERLAP:]
                    offset += len(chunk)
        except PermissionError:
            print("    Permission denied for", dev, "- run as root to scan raw devices.")
        except Exception as e:
            print("    Error scanning", dev, ":", e)
    print(f"  -> raw scan produced {len(candidates)} unique candidate path-like strings\n")
    return candidates

def normalize_candidates(cands):
    # Try to cleanup common artifacts and collapse duplicates
    out=set()
    for c in cands:
        #truncate at first null if present
        if "\x00" in c:
            c = c.split("\x00",1)[0]
        c = c.strip()
        # skip very short or obviously garbage ones
        if len(c) < 4:
            continue
        # if there's no leading slash, keep as-is (could be relative or part of string)
        out.add(c)
    return out

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

        # try ext metadata read
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

    # normalize and compare sets
    visible_norm = set(p.rstrip("/") for p in visible)
    raw_norm = normalize_candidates(raw_candidates | meta_candidates)

    # find raw candidates that are not visible
    hidden = []
    for cand in sorted(raw_norm):
        # heuristics: candidate should have at least one absolute-looking path or reasonable length
        if cand.startswith("/"):
            if cand not in visible_norm:
                hidden.append(cand)
        else:
            # if candidate contains an absolute-looking segment, try to extract
            segs = [s for s in cand.split("/") if s]
            if len(segs) >= 2:
                # try to form absolute by prefixing root
                maybe = "/" + "/".join(segs[-3:])  # last up to 3 segments
                if maybe not in visible_norm:
                    hidden.append(cand)

    print("\n=== Summary ===")
    print(f"Visible entries (find): {len(visible_norm)}")
    print(f"Raw/meta candidate path-like strings: {len(raw_norm)}")
    print(f"Likely-hidden candidates (raw/meta NOT in visible): {len(hidden)}\n")

    if hidden:
        print("Likely hidden items (examples):")
        for i,c in enumerate(hidden[:200], 1):
            print(f" {i:3d}. {c}")
    else:
        print("No obvious hidden path candidates found. That does not mean nothing is hidden — rootkits can hide names in ways this scan cannot detect.")
    print("\nRecommendations:")
    print(" - If you find interesting candidates, **do not** delete or modify them on the infected host.")
    print(" - Prefer making a full disk image (dd) and analyze on a clean system or live USB.")
    print(" - If your filesystem is APFS/HFS or other macOS-specific FS, debugfs won't help; raw scanning still can find name strings embedded on disk.")
    print(" - If you want, supply --devices to target specific block devices (helpful on macOS).")

if __name__ == "__main__":
    main()
