#!/usr/bin/env bash
set -euo pipefail

MAGIC="MAGIC_HIDE"
TMPDIR="/tmp/scan_brokepkg.$$"
mkdir -p "$TMPDIR"

echo "Brokepkg hidden-files scan — looking for names containing: '$MAGIC'"
echo

if ! [ "$(id -u)" -eq 0 ]; then
  echo "WARNING: it's best to run this script as root (some checks need it)."
fi

# 1) Informational: is brokepkg loaded?
echo "Checking for brokepkg kernel module (informational)..."
if lsmod 2>/dev/null | grep -q "^brokepkg"; then
  echo "  -> brokepkg module appears to be loaded (lsmod shows it)."
else
  echo "  -> brokepkg module not currently visible via lsmod (may be unloaded or hidden)."
fi
echo

# 2) Fast userland search (may be fooled by LKM that hooks getdents)
echo "1) Running userland 'find' for names containing '$MAGIC' (standard filesystem view)"
echo "   This may be fooled if a kernel rootkit hides entries."
echo "   Results (if any):"
sudo find / -xdev -name "*${MAGIC}*" -type f -print -o -name "*${MAGIC}*" -type d -print 2>/dev/null || true
echo

# 3) For ext2/3/4 partitions: use debugfs to read directory listings from the block device
#    debugfs reads filesystem metadata directly from the device and can often reveal names that
#    a getdents-hooking rootkit hides from normal userspace readdir-based tools.
if command -v debugfs >/dev/null 2>&1; then
  echo "2) Using debugfs on ext mounts to search filesystem metadata (bypasses many readdir hooks)."
  echo
  # Parse mounts
  awk '$1 ~ /^\// { print $1, $2, $3 }' /proc/mounts > "$TMPDIR/mounts.txt"
  while read -r DEV MP FS; do
    # Only handle ext filesystems
    case "$FS" in
      ext2|ext3|ext4)
        echo "  Checking $DEV mounted on $MP ($FS)..."
        # run debugfs to recursively list names under the mountpoint inside the filesystem
        # We use ls -p to include full path entries; wrap in timeout in case device is slow
        # Note: debugfs expects the path inside the filesystem, so we pass the $MP path (rooted)
        # but ensure we remove trailing slash for root mount
        inside_path="${MP%%/}"
        # debugfs may require the path relative to filesystem root; we will try with the mountpoint path.
        # Capture results to a temp file to search for MAGIC.
        dbg_out="$TMPDIR/debugfs_$(basename "$DEV").txt"
        if sudo debugfs -R "ls -p $inside_path" "$DEV" > "$dbg_out" 2>/dev/null; then
          if grep -q "$MAGIC" "$dbg_out"; then
            echo "    FOUND (debugfs):"
            grep --color=always -n "$MAGIC" "$dbg_out" || true
          else
            echo "    No names with '$MAGIC' found by debugfs on $DEV"
          fi
        else
          echo "    debugfs failed for $DEV (maybe not an ext fs device or permission issue)."
        fi
        echo
        ;;
      *)
        # skip other FS types
        ;;
    esac
  done < "$TMPDIR/mounts.txt"
else
  echo "debugfs not installed — skipping low-level ext fs checks. Install e2fsprogs to get debugfs."
fi

# 4) Optional fallback: scan block devices with strings (noisy). Prompt user.
echo "3) Optional: raw block-scan using strings+grep (noisy, may produce false positives)."
read -r -p "Do you want to run the raw device strings scan? [y/N] " run_raw
run_raw="${run_raw:-N}"
if [[ "$run_raw" =~ ^[Yy]$ ]]; then
  echo "Scanning block devices for the literal pattern '$MAGIC' (this can be slow)."
  # iterate block devices from lsblk
  for dev in $(lsblk -ndo NAME,TYPE | awk '$2=="disk" || $2=="part" {print "/dev/" $1}'); do
    echo "  Searching $dev ..."
    sudo strings -a "$dev" 2>/dev/null | grep --line-number --context=1 "$MAGIC" && echo "  -> hits in $dev" || echo "  -> no hits in $dev"
  done
fi

echo
echo "Scan finished. If you found hits, record the device and path and consider further incident response:"
echo " - Do not delete files prematurely. Prefer collecting a forensic copy: e.g. 'dd if=/dev/sdX of=/path/to/image.dd bs=4M conv=sync,noerror'."
echo " - Consider mounting the filesystem read-only in a trusted environment (live USB) and inspecting."
echo
echo "Cleanup: removing temporary files."
rm -rf "$TMPDIR"
