#!/usr/bin/env bash
# detect_brokepkg_noninvasive_v2.sh
# Read-only, non-invasive checks for brokepkg-like rootkit (repo-specific signatures included).
# Usage:
#   ./detect_brokepkg_noninvasive_v2.sh [--repo PATH_TO_LOCAL_REPO] [--deep]
#   --repo: optional path to local brokepkg repo to strengthen signature matching
#   --deep: run an exhaustive root grep (can be slow)

set -euo pipefail
REPO=""
DEEP=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="$2"; shift 2;;
    --deep) DEEP=1; shift;;
    *) echo "Unknown arg $1"; exit 1;;
  esac
done

TS="$(date +%Y%m%d-%H%M%S)"
OUTDIR="scan_noninvasive_v2_${TS}"
mkdir -p "$OUTDIR"

echo "Non-invasive brokepkg scan (v2) - evidence -> $OUTDIR"

# Signatures (repo-derived)
SIG_STRINGS=(
  "brokepkg"
  "brokecli"
  "give_root"
  "module_hide"
  "backdoor"
  "getdents"
  "hooks"
  "Remove brokepkg invisibility to uninstall him"
)
SIG_FILENAMES=(
  "brokepkg.o"
  "src/backdoor.c"
  "src/getdents.c"
  "src/give_root.c"
  "src/hooks.c"
  "include/module_hide.h"
)

# Save system facts
uname -a > "$OUTDIR/uname.txt"
python3 --version > "$OUTDIR/python_version.txt" 2>&1 || true
lsmod | tee "$OUTDIR/lsmod.txt"
cat /proc/modules | tee "$OUTDIR/proc_modules.txt"

# sysfs module inspection
if [ -d /sys/module/brokepkg ]; then
  echo "sys_module_present" > "$OUTDIR/sys_module_present.txt"
  ls -al /sys/module/brokepkg > "$OUTDIR/sys_module_listing.txt" 2>/dev/null || true
else
  echo "sys_module_absent" > "$OUTDIR/sys_module_absent.txt"
fi

# modinfo attempt
modinfo brokepkg > "$OUTDIR/modinfo.txt" 2>&1 || true

# Search common module paths quickly for .ko / brokepkg-like files
echo "Searching common module directories (fast)..." | tee "$OUTDIR/search_paths_log.txt"
for d in /lib/modules /usr/lib/modules /opt /usr/local/lib /root /usr/local/src /usr/src; do
  if [ -d "$d" ]; then
    find "$d" -maxdepth 6 -type f -iname "*brokepkg*.ko" -print >> "$OUTDIR/search_paths_log.txt" 2>/dev/null || true
    find "$d" -maxdepth 6 -type f -iname "*brokepkg*" -print >> "$OUTDIR/search_paths_log.txt" 2>/dev/null || true
  fi
done

# Targeted grep for repository strings in likely locations (fast)
echo "Running targeted grep for known brokepkg strings..." | tee -a "$OUTDIR/search_paths_log.txt"
for s in "${SIG_STRINGS[@]}"; do
  # search in likely dirs only (faster than full root)
  grep -R --line-number -I --exclude-dir={proc,sys,dev,run,tmp,var/log} -e "$s" /etc /opt /usr /root /home /var 2>/dev/null | head -n 200 >> "$OUTDIR/search_paths_log.txt" || true
done

# If user supplied repo path, extract additional file names/strings and store
if [ -n "$REPO" ] && [ -d "$REPO" ]; then
  echo "Using local repo $REPO for extra signatures" > "$OUTDIR/repo_signatures.txt"
  # collect C file hints and strings (non-binary)
  grep -R --line-number -E "brokepkg|brokecli|give_root|module_hide|backdoor|getdents|hooks" "$REPO" 2>/dev/null | head -n 500 >> "$OUTDIR/repo_signatures.txt" || true
fi

# /proc/kallsyms scanning (memory symbols)
echo "Scanning /proc/kallsyms for known module symbols/strings (if readable)..." > "$OUTDIR/kallsyms_scan.txt"
if [ -r /proc/kallsyms ]; then
  for s in "${SIG_STRINGS[@]}"; do
    grep -i "$s" /proc/kallsyms >> "$OUTDIR/kallsyms_scan.txt" 2>/dev/null || true
  done
else
  echo "/proc/kallsyms not readable" >> "$OUTDIR/kallsyms_scan.txt"
fi

# Check for deleted .ko files referenced by processes (deleted symlinks)
echo "Looking for deleted .ko references in /proc/*/fd (fast)..." > "$OUTDIR/deleted_refs.txt"
for fd in /proc/*/fd/*; do
  if readlink "$fd" 2>/dev/null | grep -q -iE "brokepkg|.ko \(deleted\)|.ko$"; then
    readlink "$fd" 2>/dev/null >> "$OUTDIR/deleted_refs.txt" || true
  fi
done

# Optional deep search across root if --deep requested (can take long)
if [ "$DEEP" -eq 1 ]; then
  echo "DEEP MODE: running full-root grep for signatures (this can take a long time)..." | tee -a "$OUTDIR/search_paths_log.txt"
  for s in "${SIG_STRINGS[@]}"; do
    # skip large, binary dirs to reduce noise (still heavy)
    grep -R --line-number -I --exclude-dir={proc,sys,dev,tmp,run,var/log,boot} -e "$s" / 2>/dev/null | head -n 500 >> "$OUTDIR/search_paths_log.txt" || true
  done
fi

# Persistence/network checks (light)
systemctl list-unit-files --type=service --no-pager > "$OUTDIR/services_all.txt" 2>/dev/null || true
crontab -l > "$OUTDIR/crontab_root.txt" 2>/dev/null || true
ss -tunlp > "$OUTDIR/listening_ports.txt" 2>/dev/null || true

# Compose verdict logic (improved and explicit)
VERDICT="unknown"
EVIDENCE=()

# Memory presence: if /proc/modules or lsmod contains brokepkg
if grep -q -E "^brokepkg\b" "$OUTDIR/proc_modules.txt" 2>/dev/null || grep -q -i "brokepkg" "$OUTDIR/lsmod.txt" 2>/dev/null; then
  EVIDENCE+=("present_in_memory")
fi

# On-disk detection: did we find any brokepkg file in common dirs?
if grep -q -i "brokepkg" "$OUTDIR/search_paths_log.txt" 2>/dev/null; then
  EVIDENCE+=("on_disk_artifact_found")
fi

# modinfo success check
if grep -q -i "filename" "$OUTDIR/modinfo.txt" 2>/dev/null; then
  EVIDENCE+=("modinfo_found_on_disk")
else
  # modinfo failed - could be deleted after load
  if grep -q -i "ERROR: Module brokepkg not found" "$OUTDIR/modinfo.txt" 2>/dev/null || ! grep -q -i "filename" "$OUTDIR/modinfo.txt" 2>/dev/null; then
    EVIDENCE+=("modinfo_missing_or_failed")
  fi
fi

# kallsyms match adds strong evidence of in-memory symbols
if [ -s "$OUTDIR/kallsyms_scan.txt" ] && grep -q -i -E "brokepkg|brokecli|give_root|module_hide" "$OUTDIR/kallsyms_scan.txt" 2>/dev/null; then
  EVIDENCE+=("kallsyms_matches")
fi

# Deleted-file references
if [ -s "$OUTDIR/deleted_refs.txt" ]; then
  EVIDENCE+=("deleted_ko_references")
fi

# Determine verdict rules (explicit)
if printf "%s\n" "${EVIDENCE[@]}" | grep -q "present_in_memory"; then
  if printf "%s\n" "${EVIDENCE[@]}" | grep -q "on_disk_artifact_found"; then
    VERDICT="installed_on_disk_and_in_memory"
  elif printf "%s\n" "${EVIDENCE[@]}" | grep -q "modinfo_missing_or_failed"; then
    VERDICT="installed_in_memory_with_no_on-disk_metadata (likely_hidden)"
  else
    VERDICT="installed_in_memory"
  fi
else
  if printf "%s\n" "${EVIDENCE[@]}" | grep -q "on_disk_artifact_found"; then
    VERDICT="on_disk_artifact_found_but_not_loaded"
  else
    VERDICT="not_detected_by_noninvasive_checks"
  fi
fi

# Write summary & JSON (timestamped)
SUMMARY="$OUTDIR/summary.txt"
cat > "$SUMMARY" <<EOF
verdict: $VERDICT
evidence: $(IFS=,; echo "${EVIDENCE[*]}")
raw_outputs: $OUTDIR
EOF

# Also create a JSON result (timestamped, not overwriting previous)
JSONFN="scan_result_noninvasive_${TS}.json"
python3 - <<PY > "$OUTDIR/$JSONFN"
import json
report={
  "timestamp":"${TS}",
  "verdict":"${VERDICT}",
  "evidence":${(printf '%s\n' "${EVIDENCE[@]}" | python3 -c 'import sys,json; print(json.dumps([l.strip() for l in sys.stdin]))')},
}
print(json.dumps(report, indent=2))
PY

echo "VERDICT: $VERDICT"
echo "EVIDENCE: ${EVIDENCE[*]}"
echo "All raw output in $OUTDIR"
