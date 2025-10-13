#!/usr/bin/env bash
# detect_brokepkg_active.sh
# Active (but safe) probe: build and load antitest module, check visibility.
set -euo pipefail

ANTIDIR="antitest_module"
if [ ! -d "$ANTIDIR" ]; then
  echo "Directory $ANTIDIR missing. Place antitest.c and Makefile there." >&2
  exit 1
fi

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUTDIR="scan_active_$TIMESTAMP"
mkdir -p "$OUTDIR"

# Build
pushd "$ANTIDIR" >/dev/null
if ! make -j >/dev/null; then
  echo "make failed; ensure kernel headers installed." | tee "../$OUTDIR/build_error.txt"
  popd >/dev/null
  exit 1
fi
popd >/dev/null

KO="$ANTIDIR/antitest.ko"
if [ ! -f "$KO" ]; then
  echo "antitest.ko not found after build" | tee "$OUTDIR/build_error.txt"
  exit 1
fi

# Load module
echo "Loading antitest module..."
sudo insmod "$KO"
sleep 1

# Check module visibility
lsmod | tee "$OUTDIR/lsmod_after_load.txt"
cat /proc/modules | tee "$OUTDIR/proc_modules_after_load.txt"
if [ -d /sys/module/antitest ]; then
  echo "antitest visible in /sys/module" | tee "$OUTDIR/sys_module_visible.txt"
  ls -al /sys/module/antitest > "$OUTDIR/sys_module_list.txt" 2>/dev/null || true
else
  echo "antitest NOT visible in /sys/module" | tee "$OUTDIR/sys_module_hidden.txt"
fi

# Check /proc/antitest content
if [ -r /proc/antitest ]; then
  cat /proc/antitest | tee "$OUTDIR/proc_antitest.txt"
else
  echo "/proc/antitest not readable or absent" | tee "$OUTDIR/proc_antitest_absent.txt"
fi

# Check kernel log for load message
dmesg | tail -n 50 > "$OUTDIR/dmesg_tail.txt"

# Unload module
sudo rmmod antitest || echo "rmmod failed" | tee -a "$OUTDIR/errors.txt"
sleep 1

# Record final state
lsmod | tee "$OUTDIR/lsmod_after_unload.txt"
cat /proc/modules | tee "$OUTDIR/proc_modules_after_unload.txt"

# Form verdict: if antitest loaded but wasn't visible in sysfs/proc -> suspicious
VERDICT="unknown"
EVIDENCE=""
if grep -q "^antitest" "$OUTDIR/proc_modules_after_load.txt" 2>/dev/null; then
  if [ -f "$OUTDIR/sys_module_hidden.txt" ]; then
    VERDICT="hidden_modules_behavior_detected"
    EVIDENCE="antitest loaded (showed in /proc/modules) but absent from /sys/module and /proc/antitest not readable"
  else
    VERDICT="active_probe_module_visible_normally"
    EVIDENCE="antitest behaved normally"
  fi
else
  VERDICT="active_probe_not_visible_in_procmodules"
  EVIDENCE="antitest not shown in /proc/modules after insmod; unusual"
fi

cat > "$OUTDIR/summary.txt" <<EOF
verdict: $VERDICT
evidence: $EVIDENCE
raw: $OUTDIR
EOF

echo "VERDICT: $VERDICT"
echo "EVIDENCE: $EVIDENCE"
echo "Outputs in $OUTDIR"
