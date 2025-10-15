#!/usr/bin/env python3
# scan_hidden_brokepkg.py
# Defensive tool to locate files/dirs hidden by brokepkg-like rootkits (searches for marker in names).
# Usage: sudo ./scan_hidden_brokepkg.py [--marker MAGIC_HIDE] [--no-raw] [--raw-only]
#
# Written for investigation/defensive use. Run as root.

import os
import re
import sys
import argparse
import subprocess
from shutil import which

DEFAULT_MARKER = "MAGIC_HIDE"
CHUNK = 4 * 1024 * 1024  # 4 MiB read window
OVERLAP = 4096  # overlap so matches straddling chunk edges are found
PRINT_MIN_LEN = 6  # minimum printable string length to show

def run_find(marker):
    print("\n[1] Userland 'find' (may be fooled by rootkits):")
    try:
        # search for both files and dirs
        cmd = ["find", "/", "-xdev", "-name", f"*{marker}*", "-print"]
        print(" Running: " + " ".join(cmd))
        subprocess.run(cmd, check=False)
    except Exception as e:
        print(" find step failed:", e)

def run_debugfs_on_exts(marker):
    if which("debugfs") is None:
        print("\n[2] debugfs not found; skipping ext2/3/4 metadata checks.")
        return

    print("\n[2] Attempting debugfs on ext2/3/4 mounts (may bypass readdir hooks):")
    # Parse /proc/mounts for devices and fstype
    try:
        with open("/proc/mounts", "r") as f:
            mounts = [line.split()[:3] for line in f.readlines()]
    except Exception as e:
        print(" Could not read /proc/mounts:", e)
        return

    for dev, mnt, fstype in mounts:
        if not dev.startswith("/"):
            continue
        if fstype not in ("ext2", "ext3", "ext4"):
            continue
        print(f"  -> {dev} mounted on {mnt} ({fstype})")
        dbg_out = f"/tmp/debugfs_list_{os.path.basename(dev)}.txt"
        # debugfs expects the device file and commands via -R
        # We'll run 'ls -p' recursively from '/', capture output and grep for marker.
        try:
            cmd = ["sudo", "debugfs", "-R", f"ls -p {mnt}", dev]
            print("     running debugfs (this might fail if device busy).")
            with open(dbg_out, "wb") as out:
                subprocess.run(cmd, check=False, stdout=out, stderr=subprocess.DEVNULL)
            # search file for marker
            with open(dbg_out, "rb") as out:
                content = out.read()
            if marker.encode() in content:
                print(f"     FOUND marker '{marker}' in debugfs output for {dev}:")
                for i, line in enumerate(content.splitlines()):
                    if marker.encode() in line:
                        print("       " + line.decode(errors="replace"))
            else:
                print(f"     no '{marker}' names found by debugfs on {dev}")
        except Exception as e:
            print("     debugfs step failed for", dev, ":", e)

def list_block_devices():
    # prefer lsblk if available for nicer names
    devs = []
    if which("lsblk"):
        try:
            out = subprocess.check_output(["lsblk", "-ndo", "NAME,TYPE"]).decode()
            for line in out.splitlines():
                name, type_ = line.split()
                if type_ in ("disk", "part"):
                    devs.append("/dev/" + name)
        except Exception:
            pass
    # fallback to /proc/partitions
    if not devs:
        try:
            with open("/proc/partitions","r") as f:
                for l in f:
                    parts = l.split()
                    if len(parts) == 4 and parts[3].isdigit() is False:
                        continue
                    if len(parts) == 4:
                        name = parts[3]
                        devs.append("/dev/" + name)
        except Exception:
            pass
    # filter out non-existent
    devs = [d for d in devs if os.path.exists(d)]
    # dedupe
    seen = set()
    out = []
    for d in devs:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out

print("Brokepkg-hidden discovery tool (defensive).")
parser = argparse.ArgumentParser()
parser.add_argument("--marker", default=DEFAULT_MARKER, help="Marker string used by rootkit (default MAGIC_HIDE)")
parser.add_argument("--no-raw", action="store_true", help="Skip raw block device scan")
parser.add_argument("--raw-only", action="store_true", help="Only perform raw block device scan")
args = parser.parse_args()
marker = args.marker

if os.geteuid() != 0:
    print("Warning: This script should be run as root to access block devices and debugfs.")
print(f"Searching for marker: '{marker}'")

if not args.raw_only:
    run_find(marker)
    run_debugfs_on_exts(marker)

if args.no_raw and not args.raw_only:
    print("\nSkipping raw block device scan as requested.")
    sys.exit(0)

# RAW BLOCK SCAN
print("\n[3] Raw block device scan: searching block devices for literal occurrences of the marker.")
devs = list_block_devices()
if not devs:
    print(" No block devices detected. Exiting raw scan.")
    sys.exit(0)

print(" Block devices to scan:", ", ".join(devs))
# We'll look for marker bytes in each device; for each match extract printable window
print_re = re.compile(rb"[ -~]{%d,}" % PRINT_MIN_LEN)  # printable ASCII sequences min length

def extract_printables(buf):
    return [m.group(0).decode('ascii', errors='replace') for m in print_re.finditer(buf)]

for dev in devs:
    try:
        print(f"\nScanning {dev} ... (this may take a while; reading in {CHUNK} byte chunks)")
        with open(dev, "rb", buffering=0) as f:
            offset = 0
            prev = b""
            while True:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                data = prev + chunk
                idx = data.find(marker.encode())
                while idx != -1:
                    # compute real offset on device
                    real_off = offset - len(prev) + idx
                    # window around the match
                    start = max(0, idx - 512)
                    end = min(len(data), idx + len(marker) + 512)
                    window = data[start:end]
                    print(f"  [HIT] device={dev} offset={real_off} (0x{real_off:x})")
                    # find and print nearby printable strings (likely names or paths)
                    strs = extract_printables(window)
                    if strs:
                        print("    nearby printable sequences (candidates):")
                        for s in strs:
                            if marker in s:
                                # mark the exact sequence containing the marker
                                print("      * " + s)
                            else:
                                # show sequences that include slashes (likely paths)
                                if "/" in s:
                                    print("        " + s)
                    else:
                        print("    no printable sequences found nearby.")
                    # search for next occurrence in this data buffer
                    idx = data.find(marker.encode(), idx + 1)
                # prepare for next read: keep overlap bytes from end
                prev = data[-OVERLAP:]
                offset += len(chunk)
    except PermissionError:
        print(" Permission denied reading", dev, "- need root.")
    except Exception as e:
        print(" Error scanning", dev, ":", e)

print("\nScan completed.")
print("Notes:")
print(" - If you see candidate paths above, record device and offset; consider imaging the device for offline analysis.")
print(" - If nothing shows up but you still know something is hidden, only forensic imaging and analysis on a clean system is reliable.")
