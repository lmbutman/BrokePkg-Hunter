#!/usr/bin/env bash
# detect_brokepkg_noninvasive.sh (v2.3)
# Read-only, non-invasive checks for brokepkg with repo-specific signatures.
# Usage: ./detect_brokepkg_noninvasive.sh [--repo PATH_TO_LOCAL_REPO] [--deep]

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
OUTDIR="scan_noninvasive_${TS}"
mkdir -p "$OUTDIR"

echo "Non-invasive brokepkg scan -> $OUTDIR"

SIG_REGEX='brokepkg|brokecli|give_root|module_hide|backdoor|getdents|hooks|Remove brokepkg invisibility to uninstall him'

uname -a > "$OUTDIR/uname.txt" || true
python3 --version > "$OUTDIR/python_version.txt" 2>&1 || true
lsmod | tee "$OUTDIR/lsmod.txt" || true
cat /proc/modules | tee "$OUTDIR/proc_modules.txt" || true

if [ -d /sys/module/brokepkg ]; then
  echo "present" > "$OUTDIR/sys_module_present.txt"
  ls -al /sys/module/brokepkg > "$OUTDIR/sys_module_listing.txt" 2>/dev/null || true
else
  echo "absent" > "$OUTDIR/sys_module_present.txt"
fi

modinfo brokepkg > "$OUTDIR/modinfo.txt" 2>&1 || true

echo "Searching common module directories (fast)..." | tee "$OUTDIR/search_paths_log.txt"

search_dirs=(/lib/modules /usr/lib/modules /opt /usr/local/lib /root /usr/local/src /usr/src /etc /usr /home /var)

fast_grep_dirs() {
  local pattern="$1"; shift
  if command -v rg >/dev/null 2>&1; then
    rg -n -I -S -e "$pattern" --hidden --no-messages \
       --max-depth 6 \
       --glob '!proc/**' --glob '!sys/**' --glob '!dev/**' \
       --glob '!run/**'  --glob '!tmp/**' --glob '!var/log/**' \
       --glob '!boot/**' --glob '!.git/**' --glob '!node_modules/**' \
       "$@" 2>/dev/null || true      # <- DO NOT fail if no matches
  else
    for d in "$@"; do
      [ -d "$d" ] || continue
      # find can exit non-zero on perms/etc; don't let -e kill us
      find "$d" -maxdepth 6 \
        \( -path "$d/proc/*" -o -path "$d/sys/*" -o -path "$d/dev/*" -o -path "$d/run/*" -o -path "$d/tmp/*" -o -path "$d/var/log/*" -o -path "$d/boot/*" \) -prune -o \
        -type f -print0 2>/dev/null \
      | xargs -0 grep -n -I -E "$pattern" 2>/dev/null || true
    done
  fi
}

# 1) Explicit name/file hits (guard find with || true so -e doesn't abort)
for d in "${search_dirs[@]}"; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 6 -type f \( -iname "*brokepkg*.ko" -o -iname "*brokepkg*" \) -print 2>/dev/null || true
done >> "$OUTDIR/search_paths_log.txt"

# 2) One-pass content grep
fast_grep_dirs "$SIG_REGEX" "${search_dirs[@]}" | head -n 800 >> "$OUTDIR/search_paths_log.txt"

if [ -n "$REPO" ] && [ -d "$REPO" ]; then
  echo "Using local repo $REPO for extra signatures" > "$OUTDIR/repo_signatures.txt"
  if command -v rg >/dev/null 2>&1; then
    rg -n -I -S -e "$SIG_REGEX" --no-messages "$REPO" 2>/dev/null | head -n 1000 >> "$OUTDIR/repo_signatures.txt" || true
  else
    grep -R -n -I -E "$SIG_REGEX" "$REPO" 2>/dev/null | head -n 1000 >> "$OUTDIR/repo_signatures.txt" || true
  fi
fi

echo "Scanning /proc/kallsyms..." > "$OUTDIR/kallsyms_scan.txt"
if [ -r /proc/kallsyms ]; then
  grep -i -E "$SIG_REGEX" /proc/kallsyms 2>/dev/null >> "$OUTDIR/kallsyms_scan.txt" || true
else
  echo "/proc/kallsyms not readable" >> "$OUTDIR/kallsyms_scan.txt"
fi

echo "Looking for deleted .ko references..." > "$OUTDIR/deleted_refs.txt"
for fd in /proc/*/fd/*; do
  target="$(readlink "$fd" 2>/dev/null || true)"
  if [[ "$target" == *".ko (deleted)"* || "$target" == *"brokepkg"* ]]; then
    echo "$fd -> $target" >> "$OUTDIR/deleted_refs.txt"
  fi
done

if [ "$DEEP" -eq 1 ]; then
  echo "DEEP MODE: full-root grep (this can be slow)..." | tee -a "$OUTDIR/search_paths_log.txt"
  fast_grep_dirs "$SIG_REGEX" / | head -n 3000 >> "$OUTDIR/search_paths_log.txt" || true
fi

systemctl list-unit-files --type=service --no-pager > "$OUTDIR/services_all.txt" 2>/dev/null || true
crontab -l > "$OUTDIR/crontab_root.txt" 2>/dev/null || true
ss -tunlp > "$OUTDIR/listening_ports.txt" 2>/dev/null || true

VERDICT="unknown"
EVIDENCE=()

grep -q -E "^brokepkg\b" "$OUTDIR/proc_modules.txt" 2>/dev/null && EVIDENCE+=("present_in_memory")
grep -qi "brokepkg" "$OUTDIR/lsmod.txt" 2>/dev/null && [[ " ${EVIDENCE[*]} " != *" present_in_memory "* ]] && EVIDENCE+=("present_in_memory")
grep -qi "brokepkg" "$OUTDIR/search_paths_log.txt" 2>/dev/null && EVIDENCE+=("on_disk_artifact_found")

if grep -qi "filename" "$OUTDIR/modinfo.txt" 2>/dev/null; then
  EVIDENCE+=("modinfo_found_on_disk")
else
  grep -qi "ERROR: Module brokepkg not found" "$OUTDIR/modinfo.txt" 2>/dev/null && EVIDENCE+=("modinfo_missing_or_failed")
fi

grep -qi -E "$SIG_REGEX" "$OUTDIR/kallsyms_scan.txt" 2>/dev/null && EVIDENCE+=("kallsyms_matches")
[ -s "$OUTDIR/deleted_refs.txt" ] && EVIDENCE+=("deleted_ko_references")

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

printf "verdict: %s\nevidence: %s\nraw_outputs: %s\n" \
  "$VERDICT" "$(IFS=,; echo "${EVIDENCE[*]-}")" "$OUTDIR" > "$OUTDIR/summary.txt"

json_escape() {
  local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\t'/\\t}"; printf '%s' "$s"
}
evidence_json="["
for e in "${EVIDENCE[@]:-}"; do evidence_json="${evidence_json}\"$(json_escape "$e")\","; done
evidence_json="${evidence_json%,}]"

JSONFN="$OUTDIR/scan_result_noninvasive_${TS}.json"
{
  printf '{\n'
  printf '  "timestamp": "%s",\n' "$TS"
  printf '  "verdict": "%s",\n' "$(json_escape "$VERDICT")"
  printf '  "evidence": %s\n' "$evidence_json"
  printf '}\n'
} > "$JSONFN"

echo "VERDICT: $VERDICT"
echo "EVIDENCE: ${EVIDENCE[*]:-none}"
echo "JSON: $JSONFN"
