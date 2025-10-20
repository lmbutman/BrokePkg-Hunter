# BrokePkg-Hunter - Submission

## 1. Problem statement
This project provides a robust, portable Bash scanner that detects and helps remediate traces of the real-world kernel rootkit **brokepkg**. The tool performs layered checks (memory, filesystem, logs and persistence mechanisms), optionally attempts to “unhide” modules by sending signals to a disposable process, and can attempt controlled removal (`rmmod`) when allowed. The scanner produces a timestamped directory with raw evidence and a machine-readable JSON report so investigators can triage, reproduce and archive findings.

## 2. Reference
* brokepkg
* Linux manpages: lsmod, ps, systemctl, ss, find, grep, rmmod, dmesg

## 3. Documentation of project
## Test environment
All tests (artifact-only, clean VM, and live brokepkg sample) were executed on:
- OS: Kali Linux 2021.1 (kernel 5.10.0-kali3-amd64)
- Architecture: x86_64
- VM platform: VirtualBox

## Detection and Visibility Checks
The scanner first determines if the brokepkg kernel module is present in memory.
Features:
* Checks /sys/module, lsmod, and dmesg for traces of brokepkg.
* Uses is_visible() to confirm if the module is loaded.
* Optionally attempts to unhide hidden modules by sending signals to a disposable process (or PID 1 if allowed).
* Can remove the module with rmmod automatically if unhidden or manually with user approval.
* Tracks changes in running processes to detect any newly unhidden PIDs.
* This phase focuses on runtime detection and control of potentially hidden modules.

## Filesystem, Persistence, and Configuration Analysis
After visibility checks, the scanner performs system-wide static analysis.
Features:
* Searches for brokepkg.ko binaries and related files using an exclusion-aware recursive scan.
* Locates MAGIC_HIDE macro definitions and scans for directories/files named after it.
* Checks for persistence mechanisms in /etc/ld.so.preload, modules configs, systemd, rc.local, init.d, cron, and at jobs.
* Lists open ports and owning processes, enumerates SUID/SGID files, and inspects SSH keys and firewall rules.
* Optionally validates package integrity using debsums.
* This phase ensures comprehensive coverage of disk artifacts, configuration, and persistence mechanisms.

## 4. Documentation of testing
The scanner was tested on Kali Linux VMs under multiple scenarios: a clean VM to confirm no false positives, an infected VM with brokepkg loaded to verify memory and disk detection, and a VM with only the .ko file present to test artifact discovery. Various options (--try-unhide, --remove-if-unhidden, --force-rmmod) were exercised to validate unhide and removal logic. All detections, including module visibility, filesystem artifacts, persistence mechanisms, and unhidden processes, were correctly logged and reported in both human-readable summaries and JSON format, confirming reliable detection and minimal false positives.

### Contributions by André Tisljarec 
I contributed to the initial version of the brokepkg scanner by developing a source-driven detection module. This version performed exact string searches in kernel symbols, filesystem paths, and module binaries to identify the presence of the rootkit and generate a preliminary evidence log. Although this early approach using sig_strings was later refined and integrated into a more comprehensive scanning workflow—including visibility checks, unhide attempts, persistence analysis, and JSON reporting—my initial work laid the groundwork together with my classmates for automated evidence collection and structured reporting. I also participated in testing the scanner across multiple Kali Linux VMs during different versions of the scanner, verifying its behavior on clean systems, VMs with the rootkit loaded, and VMs containing only disk artifacts. These tests confirmed the scanner’s ability to detect active modules, uncover hidden processes, and produce summary reports of the scan.

### Contributions by Karl Walfridson
I contributed with a lot of trial and error into finding a reliable and consistent way to locating hidden directories and files that had been carefully hidden by the rootkit. Unfortunately, that ended up being not so valuable towards the end product of our program, but the initial research and experimentation were made and used to narrow down what was actually possible in the resulting product, leading to us, in close collaboration, finding a better and more efficient way to detect hidden files that ended up working quite good. I also contributed with listing and verifying previously hidden processes after the active rootkit module had been successfully removed, thus clearly revealing the hidden processes and confirming our results. I also contributed with some small but important debugging tasks and finding a few minor flaws in our program and quickly fixing those issues to ensure overall reliability and smoother performance.

### Contributions by David Schalin
I contributed with the initial code for the scanner module before we pivoted to the second version. I also designed the process that the new version of the scanner uses. After that I wrote the first version of the new scanner module, that had some errors but still was working mostly as intended. In close collaboration with André and Karl I also designed many of the tests to run to make sure that the scanner works as intended. 
