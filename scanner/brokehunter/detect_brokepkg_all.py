#!/usr/bin/env python3
# detect_brokepkg_all.py
# Orchestrator: runs noninvasive and active scripts and collects a JSON report.
import subprocess, json, datetime, os, sys

TIMESTAMP = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%SZ")
OUTJSON = f"scan_result-{TIMESTAMP}.json"

def run_cmd(cmd, capture=False):
    print("RUN:", " ".join(cmd))
    if capture:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return res.returncode, res.stdout
    else:
        return subprocess.call(cmd), None

report = {
    "timestamp": TIMESTAMP,
    "host_uname": None,
    "noninvasive": {},
    "active": {},
}

# Basic uname
rc, out = run_cmd(["uname", "-a"], capture=True)
report["host_uname"] = out.strip() if rc == 0 else ""

# Run non-invasive
nv_script = "./detect_brokepkg_noninvasive.sh"
if os.path.exists(nv_script):
    rc, out = run_cmd([nv_script], capture=True)
    report["noninvasive"]["exit_code"] = rc
    report["noninvasive"]["stdout"] = out
else:
    report["noninvasive"]["error"] = "script missing"

# Ask user if they want the active probe (it will build and insert a kernel module)
do_active = True
if len(sys.argv) > 1 and sys.argv[1] == "--no-active":
    do_active = False

if do_active:
    act_script = "./detect_brokepkg_active.sh"
    if os.path.exists(act_script):
        rc, out = run_cmd([act_script], capture=True)
        report["active"]["exit_code"] = rc
        report["active"]["stdout"] = out
    else:
        report["active"]["error"] = "script missing"
else:
    report["active"]["skipped"] = True

# Save JSON report (timestamped; does not overwrite older scans)
with open(OUTJSON, "w") as f:
    json.dump(report, f, indent=2)

print("Saved JSON report to", OUTJSON)
