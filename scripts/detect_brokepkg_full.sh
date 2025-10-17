#!/usr/bin/env bash
# detect_brokepkg_full.sh
# Full brokepkg scanner implementing the user's workflow.
# Usage: sudo ./detect_brokepkg_full.sh [--repo PATH] [--deep] [--try-unhide] [--allow-pid1] [--remove-if-unhidden] [--force-rmmod]
# Example: sudo ./detect_brokepkg_full.sh --repo /path/to/brokepkg-master --try-unhide --remove-if-unhidden

set -euo pipefail

### ---------------------
### Config / CLI parsing
### ---------------------
REPO=""
DEEP=0
TRY_UNHIDE=0
ALLOW_PID1=0
REMOVE_IF_UNHIDDEN=0
FORCE_RMMOD=0
EXCLUDES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="$2"; shift 2;;
    --deep) DEEP=1; shift;;
    --try-unhide) TRY_UNHIDE=1; shift;;
    --allow-pid1) ALLOW_PID1=1; shift;;
    --remove-if-unhidden) REMOVE_IF_UNHIDDEN=1; shift;;
    --force-rmmod) FORCE_RMMOD=1; shift;;
    --exclude) EXCLUDES+=( "$(readlink -f "$2")" ); shift 2;;
    -h|--help) echo "Usage: $0 [--repo PATH] [--deep] [--try-unhide] [--allow-pid1] [--remove-if-unhidden] [--force-rmmod] [--exclude PATH]"; exit 0;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done

TS="$(date +%Y%m%d-%H%M%S)"
OUTDIR="scan_full_${TS}"
mkdir -p "$OUTDIR"
SUMMARY="$OUTDIR/summary.txt"
REPORT_JSON="$OUTDIR/report_${TS}.json"

# auto-exclude the script dir and the repo (if provided)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
EXCLUDES+=( "$SCRIPT_DIR" )
if [[ -n "$REPO" && -d "$REPO" ]]; then
  EXCLUDES+=( "$(readlink -f "$REPO")" )
fi

# helper to add entries to JSON arrays with minimal deps
json_escape() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\t'/\\t}"; printf '%s' "$s"; }

echo "Starting brokepkg full scan -> $OUTDIR"
echo "Excluding: ${EXCLUDES[*]-<none>}" > "$SUMMARY"

### ---------------------
### Helper functions
### ---------------------
log() { echo "$@" | tee -a "$SUMMARY"; }
save_raw() { local f="$1"; local dst="$OUTDIR/$(basename "$f").raw.txt"; cp -a "$f" "$dst" 2>/dev/null || true; }

# check module visible
is_visible() {
  if lsmod 2>/dev/null | grep -q '^brokepkg'; then return 0; fi
  if grep -q '^brokepkg' /proc/modules 2>/dev/null; then return 0; fi
  return 1
}

# fast grep helper respecting EXCLUDES; prefer rg if available
fast_grep_roots() {
  local pattern="$1"; shift
  local roots=( "$@" )
  if command -v rg >/dev/null 2>&1; then
    for d in "${roots[@]}"; do
      [ -d "$d" ] || continue
      pushd "$d" >/dev/null
      # build per-root exclude globs for rg
      local rgargs=( -n -I -S -e "$pattern" --hidden --no-messages --max-depth 6 )
      for ex in "${EXCLUDES[@]}"; do
        if [[ "$ex" == "$d"* ]]; then
          rel="${ex#$d/}"
          [[ -n "$rel" ]] && rgargs+=( --glob "!$rel/**" )
        fi
      done
      rg "${rgargs[@]}" . 2>/dev/null || true
      popd >/dev/null
    done
  else
    for d in "${roots[@]}"; do
      [ -d "$d" ] || continue
      for ex in "${EXCLUDES[@]}"; do
        if [[ "$ex" == "$d"* ]]; then
          PRUNE_ARGS+=( -path "$ex/*" -o )
        fi
      done
      # fallback find+grep (maxdepth 6)
      find "$d" -maxdepth 6 -type f -print0 2>/dev/null | xargs -0 grep -n -I -E "$pattern" 2>/dev/null || true
    done
  fi
}

# find files excluding EXCLUDES
find_excluding() {
  local root="$1"; local namepat="$2"
  if command -v rg >/dev/null 2>&1; then
    # use rg -g to exclude paths
    local rg_exclude=()
    for ex in "${EXCLUDES[@]}"; do
      if [[ "$ex" == "$root"* ]]; then
        rel="${ex#$root/}"; [[ -n "$rel" ]] && rg_exclude+=( --glob "!$rel/**" )
      fi
    done
    (cd "$root" 2>/dev/null && rg --files -g "$namepat" "${rg_exclude[@]}" 2>/dev/null) || true
  else
    # fallback: find and prune excludes
    local pruneargs=()
    for ex in "${EXCLUDES[@]}"; do
      if [[ "$ex" == "$root"* ]]; then pruneargs+=( -path "$ex/*" -o ); fi
    done
    # remove trailing -o if present
    # shellcheck disable=SC2016
    find "$root" -maxdepth 6 \( "${pruneargs[@]}" -false \) -prune -o -type f -iname "$namepat" -print 2>/dev/null || true
  fi
}

### ---------------------
### Step 1: simple hint checks
### ---------------------
log "STEP 1: Simple hint checks"

# 1.1 /sys/module
if [ -d /sys/module/brokepkg ]; then
  log "[1.1] /sys/module/brokepkg: PRESENT"
  echo "sys_module_present" > "$OUTDIR/sys_module_flag.txt"
else
  log "[1.1] /sys/module/brokepkg: absent"
fi

# 1.2 dmesg
dmesg | grep -i brokepkg > "$OUTDIR/dmesg_brokepkg.txt" 2>/dev/null || true
if [ -s "$OUTDIR/dmesg_brokepkg.txt" ]; then
  log "[1.2] dmesg contains brokepkg (see $OUTDIR/dmesg_brokepkg.txt)"
else
  log "[1.2] dmesg: no brokepkg hits"
fi

# 1.3 lsmod
lsmod | tee "$OUTDIR/lsmod.txt" >/dev/null
if lsmod | grep -q '^brokepkg'; then
  log "[1.3] lsmod: brokepkg present"
else
  log "[1.3] lsmod: brokepkg not listed"
fi

### ---------------------
### Step 2: ask user if no hint
### ---------------------
if ! is_visible && [ ! -s "$OUTDIR/dmesg_brokepkg.txt" ]; then
  echo
  read -rp "No hint of brokepkg found in basic checks. Continue with deeper checks? [y/N] " yn
  yn=${yn:-N}
  if [[ ! "$yn" =~ ^[Yy]$ ]]; then
    log "User aborted deeper checks."
    # still write minimal JSON
    cat > "$REPORT_JSON" <<JSON
{
  "timestamp":"$TS",
  "verdict":"no_basic_evidence",
  "notes":"user_aborted_deep_checks"
}
JSON
    log "Report: $REPORT_JSON"
    exit 0
  fi
fi

### ---------------------
### Step 3: brute-force unhide (optional)
### ---------------------
FOUND_UNHIDE_SIGNAL=""
if [ "$TRY_UNHIDE" -eq 1 ]; then
  log "STEP 3: Attempting brute-force unhide (signals 34..64 then 1..31) using disposable child"

  # spawn disposable child
  sleep 3000 &
  CHILD=$!
  echo "child_pid:$CHILD" > "$OUTDIR/unhide_child.txt"
  log "Spawned disposable child PID=$CHILD"

  # order: RT (34..64) then 1..31
  SIGS=()
  for ((s=34; s<=64; s++)); do SIGS+=($s); done
  for ((s=1; s<=31; s++)); do SIGS+=($s); done

  for sig in "${SIGS[@]}"; do
    kill -"$sig" "$CHILD" 2>/dev/null || true
    sleep 0.15
    if is_visible; then
      FOUND_UNHIDE_SIGNAL="$sig"
      log "Module became VISIBLE after sending signal $sig to child"
      break
    fi
  done

  # optional: try PID1 if allowed and not found (risky)
  if [[ -z "$FOUND_UNHIDE_SIGNAL" && "$ALLOW_PID1" -eq 1 ]]; then
    log "Trying signals to PID 1 as last resort (dangerous) ..."
    for ((s=34; s<=64; s++)); do
      if [ "$s" -eq 9 ] || [ "$s" -eq 19 ]; then continue; fi
      kill -"$s" 1 2>/dev/null || true
      sleep 0.15
      if is_visible; then
        FOUND_UNHIDE_SIGNAL="$s"
        log "Module visible after sending $s to PID 1"
        break
      fi
    done
  fi

  # cleanup child
  if kill -0 "$CHILD" 2>/dev/null; then kill -9 "$CHILD" 2>/dev/null || true; fi
  log "Unhide brute-force finished. found_signal: ${FOUND_UNHIDE_SIGNAL:-none}"
  echo "$FOUND_UNHIDE_SIGNAL" > "$OUTDIR/found_unhide_signal.txt" 2>/dev/null || true
fi

### ---------------------
### Step 4: attempt rmmod if unhidden or forced
### ---------------------
RMMOD_RESULT="not_attempted"
if is_visible || [ -n "$FOUND_UNHIDE_SIGNAL" ] || [ "$FORCE_RMMOD" -eq 1 ]; then
  # ask user to proceed unless --remove-if-unhidden provided
  if [ "$REMOVE_IF_UNHIDDEN" -eq 1 ] || [ "$FORCE_RMMOD" -eq 1 ]; then
    WANT_RMMOD=Y
  else
    read -rp "Attempt to remove brokepkg with rmmod now? [y/N] " want; want=${want:-N}
    WANT_RMMOD=$([[ "$want" =~ ^[Yy]$ ]] && echo Y || echo N)
  fi

  if [ "$WANT_RMMOD" = "Y" ]; then
    if sudo rmmod brokepkg 2> "$OUTDIR/rmmod_err.txt"; then
      RMMOD_RESULT="removed_ok"
      log "rmmod succeeded"
    else
      RMMOD_RESULT="rmmod_failed"
      log "rmmod failed — see $OUTDIR/rmmod_err.txt and dmesg"
    fi
  else
    log "User chose not to rmmod at this time"
  fi
else
  log "Skipping rmmod - module not visible and not forced"
fi

### ---------------------
### Step 5: search entire host for brokepkg.ko
### ---------------------
log "STEP 5: Searching for brokepkg.ko across common roots"
SEARCH_ROOTS=(/ /lib /usr /opt /root /home /var)
FOUND_KO_LIST=()
for r in "${SEARCH_ROOTS[@]}"; do
  # use find_excluding wrapper: this looks for name pattern recursively
  while IFS= read -r f; do
    FOUND_KO_LIST+=( "$f" )
  done < <(find_excluding "$r" "brokepkg*.ko")
done
printf "%s\n" "${FOUND_KO_LIST[@]}" > "$OUTDIR/ko_found_list.txt" 2>/dev/null || true
if [ "${#FOUND_KO_LIST[@]}" -gt 0 ]; then
  log "Found brokepkg .ko files:"
  printf "  %s\n" "${FOUND_KO_LIST[@]}" | sed 's/^/  /' | tee -a "$SUMMARY"
else
  log "No brokepkg .ko files found in the fast search"
fi

### ---------------------
### Step 5.1: find MAGIC_HIDE in include/config.h under each ko directory
### ---------------------
MAGIC_HIDE=""
if [ "${#FOUND_KO_LIST[@]}" -gt 0 ]; then
  for ko in "${FOUND_KO_LIST[@]}"; do
    basedir="$(dirname "$ko")"
    # look for include/config.h near the module source layout
    if [ -f "$basedir/include/config.h" ]; then
      val=$(grep -E '^[[:space:]]*#define[[:space:]]+MAGIC_HIDE[[:space:]]+[0-9A-Za-z_/-]+' "$basedir/include/config.h" 2>/dev/null | awk '{print $3}' | tr -d '"' | head -n1 || true)
      if [ -n "$val" ]; then
        MAGIC_HIDE="$val"
        log "MAGIC_HIDE found in $basedir/include/config.h : $MAGIC_HIDE"
        break
      fi
    fi
  done
fi

# fallback: find any config.h that defines MAGIC_HIDE anywhere in filesystem (respect excludes)
if [ -z "$MAGIC_HIDE" ]; then
  log "Attempting global search for MAGIC_HIDE macro in config.h files (may be slow)"
  while IFS= read -r f; do
    val=$(grep -E '^[[:space:]]*#define[[:space:]]+MAGIC_HIDE[[:space:]]+[0-9A-Za-z_/-]+' "$f" 2>/dev/null | awk '{print $3}' | tr -d '"' | head -n1 || true)
    if [ -n "$val" ]; then MAGIC_HIDE="$val"; log "MAGIC_HIDE discovered in $f : $MAGIC_HIDE"; break; fi
  done < <(find_excluding / "config.h")
fi

### ---------------------
### Step 6: search folders named {MAGIC_HIDE}
### ---------------------
MAGIC_DIRS=()
if [ -n "$MAGIC_HIDE" ]; then
  log "STEP 6: Searching for directories named $MAGIC_HIDE"
  # find top-level matches
  while IFS= read -r p; do MAGIC_DIRS+=( "$p" ); done < <(find / -type d -name "$MAGIC_HIDE" 2>/dev/null || true)
  if [ "${#MAGIC_DIRS[@]}" -gt 0 ]; then
    log "Found directories named $MAGIC_HIDE:"
    printf "%s\n" "${MAGIC_DIRS[@]}" | sed 's/^/  /' | tee -a "$SUMMARY"
  else
    log "No directories named $MAGIC_HIDE found"
  fi
else
  log "No MAGIC_HIDE value discovered; skipping folder-name search"
fi

### ---------------------
### Step 7: List open ports & owning process
### ---------------------
log "STEP 7: Listing open ports and owning processes"
ss -tunap 2>/dev/null | tee "$OUTDIR/open_ports.txt" >/dev/null || true
log "Open ports saved to $OUTDIR/open_ports.txt"

### ---------------------
### Step 8: Startup files & systemd checks
### ---------------------
log "STEP 8: Startup / autostart checks"

# ld.so.preload
if [ -f /etc/ld.so.preload ]; then
  log "/etc/ld.so.preload exists:"
  sed -n '1,200p' /etc/ld.so.preload | tee "$OUTDIR/ld_so_preload.txt"
else
  log "/etc/ld.so.preload absent"
fi

# systemd enabled units
systemctl list-unit-files --type=service --no-pager > "$OUTDIR/systemd_unit_files.txt" 2>/dev/null || true
systemctl list-units --type=service --state=enabled --no-pager > "$OUTDIR/systemd_enabled_services.txt" 2>/dev/null || true

# /etc/modules and modprobe.d
grep -R --line-number -I "brokepkg" /etc/modules /etc/modules-load.d /etc/modprobe.d 2>/dev/null > "$OUTDIR/modload_matches.txt" || true

# rc.local
[ -f /etc/rc.local ] && sed -n '1,300p' /etc/rc.local > "$OUTDIR/rc_local.txt" 2>/dev/null || true

# init.d
ls -l /etc/init.d 2>/dev/null > "$OUTDIR/initd_list.txt" || true

log "Startup checks completed (see $OUTDIR/* for raw outputs)"

### ---------------------
### Step 9: Cron checks
### ---------------------
log "STEP 9: Cron and at jobs"

crontab -l 2> "$OUTDIR/crontab_root_err.txt" > "$OUTDIR/crontab_root.txt" || true
grep -R --line-number -I "brokepkg|brokecli|MAGIC_HIDE" /etc/cron* /var/spool/cron /var/spool/cron/crontabs 2>/dev/null > "$OUTDIR/cron_matches.txt" || true
if command -v at >/dev/null 2>&1; then atq > "$OUTDIR/atq.txt" 2>/dev/null || true; fi

### ---------------------
### Additional persistence & integrity checks (recommended)
### ---------------------
log "ADDITIONAL: checking SUID files, SSH keys, iptables/nft, package-integrity hints"

# SUID/SGID
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -ls 2>/dev/null | head -n 200 > "$OUTDIR/suid_sgids.txt" || true

# SSH authorized_keys
grep -R --line-number -I "brokepkg|brokecli" /root/.ssh /home/*/.ssh /etc/ssh/sshd_config 2>/dev/null > "$OUTDIR/ssh_matches.txt" || true

# iptables/nft
iptables-save > "$OUTDIR/iptables_save.txt" 2>/dev/null || true
if command -v nft >/dev/null 2>&1; then nft list ruleset > "$OUTDIR/nft_rules.txt" 2>/dev/null || true; fi

# package integrity hint (debsums if present)
if command -v debsums >/dev/null 2>&1; then debsums -s > "$OUTDIR/debsums_failed.txt" 2>/dev/null || true; fi

# basic logs listing
ls -lt /var/log | head -n 40 > "$OUTDIR/varlog_listing.txt" 2>/dev/null || true

### ---------------------
### Step 10: Collate & produce JSON + human summary
### ---------------------
log "STEP 10: Collating results"

VERDICT="unknown"
EVIDENCE=()

# Determine verdict heuristics
if is_visible; then EVIDENCE+=("present_in_memory"); fi
if [ -s "$OUTDIR/dmesg_brokepkg.txt" ]; then EVIDENCE+=("dmesg_has_brokepkg"); fi
if grep -qi "brokepkg" "$OUTDIR/lsmod.txt" 2>/dev/null; then EVIDENCE+=("lsmod_listed"); fi
if [ "${#FOUND_KO_LIST[@]}" -gt 0 ]; then EVIDENCE+=("on_disk_ko_found"); fi
if [ -n "$FOUND_UNHIDE_SIGNAL" ]; then EVIDENCE+=("unhide_signal_found:$FOUND_UNHIDE_SIGNAL"); fi
if [ "$RMMOD_RESULT" = "removed_ok" ]; then EVIDENCE+=("removed_via_rmmod"); fi
if [ -s "$OUTDIR/ld_so_preload.txt" ]; then EVIDENCE+=("ld_so_preload_present"); fi
if [ -s "$OUTDIR/modload_matches.txt" ]; then EVIDENCE+=("modprobe_or_modules_conf_matches"); fi
if [ -s "$OUTDIR/cron_matches.txt" ]; then EVIDENCE+=("cron_matches"); fi
if [ -s "$OUTDIR/open_ports.txt" ]; then EVIDENCE+=("open_ports_listed"); fi

# simple verdict mapping
if printf "%s\n" "${EVIDENCE[@]}" | grep -q "present_in_memory"; then
  if printf "%s\n" "${EVIDENCE[@]}" | grep -q "on_disk_ko_found"; then
    VERDICT="installed_on_disk_and_in_memory"
  else
    VERDICT="installed_in_memory_possibly_hidden"
  fi
else
  if printf "%s\n" "${EVIDENCE[@]}" | grep -q "on_disk_ko_found"; then
    VERDICT="on_disk_artifact_found_but_not_loaded"
  else
    VERDICT="not_detected_by_this_scan"
  fi
fi

# write human-readable summary
{
  echo "timestamp: $TS"
  echo "verdict: $VERDICT"
  echo "evidence: ${EVIDENCE[*]-none}"
  echo "repo: ${REPO:-none}"
  echo "found_kos:"
  printf "%s\n" "${FOUND_KO_LIST[@]:-none}" | sed 's/^/  /'
  echo "magic_hide: ${MAGIC_HIDE:-none}"
  echo "magic_dirs:"
  printf "%s\n" "${MAGIC_DIRS[@]:-none}" | sed 's/^/  /'
  echo "rmmod_result: $RMMOD_RESULT"
} | tee -a "$SUMMARY"

# write JSON report (minimal, safe)
{
  echo "{"
  echo "  \"timestamp\": \"$(json_escape "$TS")\","
  echo "  \"verdict\": \"$(json_escape "$VERDICT")\","
  echo "  \"repo\": \"$(json_escape "${REPO:-}")\","
  echo "  \"evidence\": ["
  sep=""
  for e in "${EVIDENCE[@]:-}"; do
    printf '%s    "%s"\n' "$sep" "$(json_escape "$e")"
    sep=","
  done
  echo "  ],"
  echo "  \"found_kos\": ["
  sep=""
  for k in "${FOUND_KO_LIST[@]:-}"; do
    printf '%s    \"%s\"\n' "$sep" "$(json_escape "$k")"
    sep=","
  done
  echo "  ],"
  echo "  \"magic_hide\": \"$(json_escape "${MAGIC_HIDE:-}")\","
  echo "  \"magic_dirs\": ["
  sep=""
  for m in "${MAGIC_DIRS[@]:-}"; do
    printf '%s    \"%s\"\n' "$sep" "$(json_escape "$m")"
    sep=","
  done
  echo "  ]"
  echo "}"
} > "$REPORT_JSON"

log "Scan complete. Human summary: $SUMMARY"
log "Full JSON report: $REPORT_JSON"
log "Raw outputs in $OUTDIR (do not commit these to git)".

exit 0
