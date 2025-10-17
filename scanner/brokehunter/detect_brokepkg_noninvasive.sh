#!/usr/bin/env bash
# detect_brokepkg_noninvasive.sh (v2.4)
# Read-only, non-invasive checks for brokepkg with repo-specific signatures.
# Excludes the scanner's own directory by default to avoid self-hits.
# Usage:
#   ./detect_brokepkg_noninvasive.sh [--repo PATH] [--deep] [--exclude PATH]...

set -euo pipefail

# --- args ---
REPO=""
DEEP=0
EXCLUDES=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="${2:-}"; shift 2;;
    --deep) DEEP=1; shift;;
    --exclude) EXCLUDES+=("$(readlink -f "${2:-}")"); shift 2;;
    *) echo "Unknown arg $1"; exit 1;;
  esac
done

# --- paths & defaults ---
TS="$(date +%Y%m%d-%H%M%S)"
OUTDIR="scan_noninvasive_${TS}"
mkdir -p "$OUTDIR"

# Exclude the directory this script resides in (prevents self-matches)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
EXCLUDES+=("$SCRIPT_DIR")
# Also exclude the repo path if provided
if [[ -n "${REPO}" && -d "${REPO}" ]]; then
  EXCLUDES+=("$(readlink -f "$REPO")")
fi

echo "Non-invasive brokepkg scan -> $OUTDIR"
echo "Excluding: ${EXCLUDES[*]-<none>}"

SIG_REGEX='brokepkg|brokecli|give_root|module_hide|backdoor|getdents|hooks|Remove brokepkg invisibility to uninstall him'

# --- basics ---
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

# helper: is EXCLUDE under ROOT?
_under_root() { local root="$1" path="$2"; [[ "$path" == "$root"* ]]; }

# --- FAST grep over dirs with exclusion support ---
fast_grep_dirs() {
  local pattern="$1"; shift
  if command -v rg >/dev/null 2>&1; then
    # Run rg per root so we can add per-root relative ignore globs
    for d in "$@"; do
      [ -d "$d" ] || continue
      pushd "$d" >/dev/null
      # Base ripgrep args
      local -a RG_ARGS=( -n -I -S -e "$pattern" --hidden --no-messages --max-depth 6
                         --glob '!proc/**' --glob '!sys/**' --glob '!dev/**'
                         --glob '!run/**'  --glob '!tmp/**' --glob '!var/log/**'
                         --glob '!boot/**' --glob '!.git/**' --glob '!node_modules/**' )
      # Add per-root exclude globs
      local ex
      for ex in "${EXCLUDES[@]}"; do
        if _under_root "$d/" "$ex/"; then
          # relative path within this root
          rel="${ex#"$d"/}"
          [[ -n "$rel" && "$rel" != "$ex" ]] && RG_ARGS+=( --glob "!$rel/**" )
        fi
      done
      rg "${RG_ARGS[@]}" . 2>/dev/null || true
      popd >/dev/null
    done
  else
    # find+xargs+grep with prune for excludes
    for d in "$@"; do
      [ -d "$d" ] || continue
      # Build prune list
      local -a PRUNE=( -path "$d/proc/*" -o -path "$d/sys/*" -o -path "$d/dev/*" -o -path "$d/run/*" -o -path "$d/tmp/*" -o -path "$d/var/log/*" -o -path "$d/boot/*" )
      local ex
      for ex in "${EXCLUDES[@]}"; do
        if _under_root "$d/" "$ex/"; then
          PRUNE+=( -o -path "$ex/*" )
        fi
      done
      # shellcheck disable=SC2016
      find "$d" -maxdepth 6 \( "${PRUNE[@]}" \) -prune -o -type f -print0 2>/dev/null \
        | xargs -0 grep -n -I -E "$pattern" 2>/dev/null || true
    done
  fi
}

# --- 1) explicit name/file hits with excludes ---
for d in "${search_dirs[@]}"; do
  [ -d "$d" ] || continue
  # Build prune options for excludes
  PRUNE_OPTS=( -path "$d/proc/*" -o -path "$d/sys/*" -o -path "$d/dev/*" -o -path "$d/run/*" -o -path "$d/tmp/*" -o -path "$d/var/log/*" -o -path "$d/boot/*" )
  for ex in "${EXCLUDES[@]}"; do
    if _under_root "$d/" "$ex/"; then
      PRUNE_OPTS+=( -o -path "$ex/*" )
    fi
  done
  # Find files named like brokepkg (guard with || true for set -e)
  find "$d" -maxdepth 6 \( "${PRUNE_OPTS[@]}" \) -prune -o \
       -type f \( -iname "*brokepkg*.ko" -o -iname "*brokepkg*" \) -print 2>/dev/null || true
done >> "$OUTDIR/search_paths_log.txt"

# --- 2) one-pass content grep with excludes ---
fast_grep_dirs "$SIG_REGEX" "${search_dirs[@]}" | head -n 800 >> "$OUTDIR/search_paths_log.txt"

# --- repo-assisted signatures (just a reference log; we already excluded REPO from scans) ---
if [[ -n "$REPO" && -d "$REPO" ]]; then
  echo "Using local repo $REPO for extra signatures" > "$OUTDIR/repo_signatures.txt"
  if command -v rg >/dev/null 2>&1; then
    rg -n -I -S -e "$SIG_REGEX" --no-messages "$REPO" 2>/dev/null | head -n 1000 >> "$OUTDIR/repo_signatures.txt" || true
  else
    grep -R -n -I -E "$SIG_REGEX" "$REPO" 2>/dev/null | head -n 1000 >> "$OUTDIR/repo_signatures.txt" || true
  fi
fi

# --- kallsyms (memory) ---
echo "Scanning /proc/kallsyms..." > "$OUTDIR/kallsyms_scan.txt"
if [ -r /proc/kallsyms ]; then
  grep -i -E "$SIG_REGEX" /proc/kallsyms 2>/dev/null >> "$OUTDIR/kallsyms_scan.txt" || true
else
  echo "/proc/kallsyms not readable" >> "$OUTDIR/kallsyms_scan.txt"
fi

# --- source-driven signatures (unchanged; just logs) ---
echo "Running source-driven signature checks..." > "$OUTDIR/source_signatures.txt"
sig_strings=( "brokepkg now is runing" "R3tr074" "Rootkit" "give_root" "module_hide" "CONTAIN_HIDE_SEQUENCE" "NEED_HIDE_PROC" "switch_module_hide" "switch_pid_hide" "switch_port_hide" "port_is_hidden" "fh_install_hooks" "fh_remove_hooks" "hook_getdents" "hook_getdents64" "hook_kill" "hook_tcp4_seq_show" "hook_tcp6_seq_show" "hook_ip_rcv" "SIGHIDE" "SIGMODINVIS" "SIGROOT" "SIGPORT" )
if [ -r /proc/kallsyms ]; then
  for s in "${sig_strings[@]}"; do
    grep -i -E "$s" /proc/kallsyms 2>/dev/null && echo "kallsyms: $s" >> "$OUTDIR/source_signatures.txt" || true
  done
else
  echo "/proc/kallsyms not readable; skipping symbol checks" >> "$OUTDIR/source_signatures.txt"
fi

echo "Scanning module binaries for suspicious strings..." >> "$OUTDIR/source_signatures.txt"
find /lib/modules -type f -name '*.ko' 2>/dev/null | while read -r ko; do
  strings "$ko" 2>/dev/null | grep -E -n "brokepkg|hook_getdents|CONTAIN_HIDE_SEQUENCE|NEED_HIDE_PROC|give_root|SIGHIDE|SIGROOT|fh_install_hooks|fh_remove_hooks" 2>/dev/null \
    && echo "sus_strings_in: $ko" >> "$OUTDIR/source_signatures.txt" || true
done

grep -i -E "sys_getdents64|sys_getdents" /proc/kallsyms 2>/dev/null > "$OUTDIR/syscall_symbols.txt" || true
grep -i -E "hook_getdents|hook_getdents64" /proc/kallsyms 2>/dev/null >> "$OUTDIR/syscall_symbols.txt" || true

# If source-driven findings exist, mark in main log so verdict logic can notice
if grep -qi -E "brokepkg|hook_getdents|hook_getdents64|fh_install_hooks|fh_remove_hooks|give_root|CONTAIN_HIDE_SEQUENCE|NEED_HIDE_PROC" "$OUTDIR/source_signatures.txt" 2>/dev/null; then
  echo "source_signatures_found" >> "$OUTDIR/search_paths_log.txt"
fi

# --- deleted .ko references ---
echo "Looking for deleted .ko references..." > "$OUTDIR/deleted_refs.txt"
for fd in /proc/*/fd/*; do
  target="$(readlink "$fd" 2>/dev/null || true)"
  if [[ "$target" == *".ko (deleted)"* || "$target" == *"brokepkg"* ]]; then
    echo "$fd -> $target" >> "$OUTDIR/deleted_refs.txt"
  fi
done

# --- optional deep mode (also respects excludes) ---
if [ "$DEEP" -eq 1 ]; then
  echo "DEEP MODE: full-root grep (this can be slow)..." | tee -a "$OUTDIR/search_paths_log.txt"
  fast_grep_dirs "$SIG_REGEX" / | head -n 3000 >> "$OUTDIR/search_paths_log.txt" || true
fi

# --- persistence/network (light) ---
systemctl list-unit-files --type=service --no-pager > "$OUTDIR/services_all.txt" 2>/dev/null || true
crontab -l > "$OUTDIR/crontab_root.txt" 2>/dev/null || true
ss -tunlp > "$OUTDIR/listening_ports.txt" 2>/dev/null || true

# --- verdict ---
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

json_escape() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\t'/\\t}"; printf '%s' "$s"; }
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
