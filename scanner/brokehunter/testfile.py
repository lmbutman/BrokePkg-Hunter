#!/usr/bin/env python3
# scan_hidden_brokepkg.py (filtered)
# Defensive tool to locate files/dirs hidden by brokepkg-like rootkits (searches for marker in names).
# This variant filters out self-generated noise so the script's own commands and temp files don't appear.
# Usage: sudo ./scan_hidden_brokepkg.py [--marker MAGIC_HIDE] [--no-raw] [--raw-only] [--show-blacklist]

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

def build_self_blacklist(script_path, extra_list=None):
    bl = set()
    try:
        abspath = os.path.abspath(script_path)
        bl.add(abspath)
        bl.update(part for part in abspath.split(os.sep) if part)
    except Exception:
        pass
    try:
        bl.add(sys.executable)
        bl.add(os.path.basename(sys.executable))
    except Exception:
        pass
    # commands this script may invoke
    known_cmds = ["find", "debugfs", "strings", "dd", "lsblk", "grep", "sudo", "python", "python3"]
    for c in known_cmds:
        bl.add(c)
        bl.add("/usr/bin/" + c)
        bl.add("/bin/" + c)
    # tmp and var tmp
    bl.add("/tmp")
    bl.add("tmp")
    bl.add("/var/tmp")
    # cwd and components
    try:
        cwd = os.path.abspath(os.getcwd())
        bl.add(cwd)
        bl.update(part for part in cwd.split(os.sep) if part)
    except Exception:
        pass
    # username
    try:
        bl.add(os.getlogin())
    except Exception:
        pass
    # extra user-provided tokens
    if extra_list:
        for e in extra_list:
            if e:
                bl.add(e)
    # keep tokens >1 char to avoid over-filtering
    return {t for t in bl if isinstance(t, str) and len(t) > 1}

def run_find(marker):
    print("\n[1] Userland 'find' (may be fooled by rootkits):")
    try:
        cmd = ["find", "/", "-xdev", "-name", f"*{marker}*", "-print", "-o", "-name", f"*{marker}*", "-type", "d", "-print"]
        print(" Running: " + " ".join(cmd))
        subprocess.run(cmd, check=False)
    except Exception as e:
        print(" find step failed:", e)

def run_debugfs_on_exts(marker, blacklist):
    if which("debugfs") is None:
        print("\n[2] debugfs not found — skipping ext2/3/4 metadata checks.")
        return
    print("\n[2] Using debugfs on ext mounts to search filesystem metadata (bypasses many readdir hooks).")
    # Parse mounts
    try:
        with open("/proc/mounts", "r") as f:
            mounts = [line.split()[:3] for line in f]
    except Exception as e:
        print(" Could not read /proc/mounts:", e)
        return

    for dev, mp, fs in mounts:
        if not dev.startswith("/"):
            continue
        if fs not in ("ext2", "ext3", "ext4"):
            continue
        print(f"  Checking {dev} mounted on {mp} ({fs})...")
        inside_path = mp.rstrip("/") or "/"
        dbg_out = f"/tmp/debugfs_$(basename_{os.path.basename(dev)})_out.txt"
        try:
            # We'll capture debugfs output and search for marker; filter lines containing blacklist tokens
            proc = subprocess.Popen(["sudo", "debugfs", "-R", f"ls -p {inside_path}", dev],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            stdout, _ = proc.communicate(timeout=60)
            if not stdout:
                print("    debugfs returned no output (or timed out).")
                continue
            b = stdout
            if marker.encode() in b:
                print(f"    FOUND (debugfs):")
                for line in b.splitlines():
                    try:
                        s = line.decode(errors="replace").strip()
                    except Exception:
                        s = str(line)
                    if marker in s:
                        # filter out if blacklisted
                        if any(tok in s for tok in blacklist):
                            continue
                        print("     " + s)
            else:
                print(f"    No names with '{marker}' found by debugfs on {dev}")
        except subprocess.TimeoutExpired:
            print("    debugfs timed out for", dev)
        except Exception as e:
            print("    debugfs failed for", dev, ":", e)
        print()

def list_block_devices():
    devs = []
    if which("lsblk"):
        try:
            out = subprocess.check_output(["lsblk", "-ndo", "NAME,TYPE"], text=True)
            for line in out.splitlines():
                name_type = line.split()
                if len(name_type) >= 2 and name_type[1] in ("disk", "part"):
                    devs.append("/dev/" + name_type[0])
        except Exception:
            pass
    if not devs:
        # fallback attempt
        candidates = ["/dev/sda", "/dev/nvme0n1", "/dev/rdisk0", "/dev/disk0"]
        for p in candidates:
            if os.path.exists(p):
                devs.append(p)
    # dedupe & exist
    out = []
    for d in devs:
        if d not in out and os.path.exists(d):
            out.append(d)
    return out

print("Brokepkg-hidden discovery tool (filtered).")
parser = argparse.ArgumentParser()
parser.add_argument("--marker", default=DEFAULT_MARKER, help="Marker string used by rootkit (default MAGIC_HIDE)")
parser.add_argument("--no-raw", action="store_true", help="Skip raw block device scan")
parser.add_argument("--raw-only", action="store_true", help="Only perform raw block device scan")
parser.add_argument("--show-blacklist", action="store_true", help="Show the auto-generated blacklist and exit")
parser.add_argument("--extra-ignore", help="Comma-separated extra tokens to ignore (e.g. suspicious-temp)")
args = parser.parse_args()
marker = args.marker

if os.geteuid() != 0:
    print("Warning: This script should be run as root to access block devices and debugfs.")
extra_tokens = args.extra_ignore.split(",") if args.extra_ignore else None
blacklist = build_self_blacklist(__file__, extra_tokens)

if args.show_blacklist:
    print("Auto-generated blacklist tokens (will filter candidates that include any of these):")
    for t in sorted(blacklist):
        print(" -", t)
    sys.exit(0)

if not args.raw_only:
    run_find(marker)
    run_debugfs_on_exts(marker, blacklist)

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
print_re = re.compile(rb"[ -~]{%d,}" % PRINT_MIN_LEN)

def extract_printables(buf):
    return [m.group(0).decode('ascii', errors='replace') for m in print_re.finditer(buf)]

for dev in devs:
    try:
        print(f"\nScanning {dev} ... (reading in {CHUNK} byte chunks)")
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
                    real_off = offset - len(prev) + idx
                    start = max(0, idx - 512)
                    end = min(len(data), idx + len(marker) + 512)
                    window = data[start:end]
                    # extract printable candidates in the window
                    strs = extract_printables(window)
                    # filter printable sequences by blacklist tokens
                    filtered = []
                    for s in strs:
                        # skip very short
                        if len(s) < PRINT_MIN_LEN:
                            continue
                        # if any blacklist token present, skip this printable
                        if any(tok in s for tok in blacklist):
                            continue
                        filtered.append(s)
                    if filtered:
                        print(f"  [HIT] device={dev} offset={real_off} (0x{real_off:x})")
                        print("    nearby printable sequences (candidates):")
                        for s in filtered:
                            print("      * " + s)
                    else:
                        # If everything was blacklisted, don't print the hit to avoid self-noise
                        # but you might want to log quiet hits — omitted here for clarity
                        pass
                    idx = data.find(marker.encode(), idx + 1)
                prev = data[-OVERLAP:]
                offset += len(chunk)
    except PermissionError:
        print(" Permission denied reading", dev, "- need root.")
    except Exception as e:
        print(" Error scanning", dev, ":", e)

print("\nScan finished. If you found hits, record the device and path and consider further incident response.")
print(" - Do not delete files prematurely. Prefer collecting a forensic copy (dd) and work offline.")
print("Cleanup: none (no temp files created by this run).")
