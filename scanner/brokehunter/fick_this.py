import os
import getpass
import re

# --- Configuration ---
# The target prefix (or full name) used by the rootkit to hide files and directories.
# This value is based on the user's updated observation.
MAGIC_PREFIX = "br0k3_n0w_h1dd3n"

# A list of critical directories to check directly.
# This check attempts to bypass readdir hooks by checking for the *exact* hidden name.
CRITICAL_INSTALL_PATHS = [
    "/lib/",
    "/usr/lib/",
    "/usr/local/lib/",
    "/etc/",
    "/dev/shm/",
    "/tmp/"
]

def find_artifacts_direct_check(critical_paths, magic_prefix):
    """
    Performs a direct check (equivalent to trying to 'cd' into a known hidden directory).
    This exploits rootkits that only hook readdir (directory listing) but not open/stat.
    """
    found_artifacts = set()
    print(f"[INFO] Running direct CD-Bypass check for artifact: '{magic_prefix}'...")

    for root_dir in critical_paths:
        full_path = os.path.join(root_dir, magic_prefix)
        
        try:
            # Check if the full, known path exists, even if it's hidden from 'ls'
            if os.path.exists(full_path):
                # Now check if it's actually hidden (optional but good confirmation)
                # Note: os.listdir is highly likely hooked, so this check is only for confirmation
                if not magic_prefix in os.listdir(root_dir):
                    # We found the file directly, AND it's not visible via normal listing!
                    found_artifacts.add(f"(DIRECT-HIT) {full_path}")
                else:
                    # Found it, but it's not hidden (normal file starting with the prefix)
                    pass
        except PermissionError:
            pass
        except Exception as e:
            print(f"[ERROR] Direct check error in {full_path}: {e}")

    return found_artifacts


def find_hidden_artifacts_signature(scan_paths, magic_prefix):
    """
    Performs a standard recursive directory scan for files/dirs with the magic prefix.
    NOTE: This method may be defeated by rootkit hooks (like readdir hooking).
    It is useful for finding non-executed artifacts in critical paths.
    """
    found_artifacts = set()
    print(f"[INFO] Running signature scan for artifacts starting with: '{magic_prefix}'...")

    # Add user's home directory dynamically
    try:
        scan_paths.append(os.path.expanduser("~"))
    except Exception:
        pass

    for root_path in scan_paths:
        if not os.path.isdir(root_path):
            continue

        try:
            for root, dirs, files in os.walk(root_path, topdown=True, followlinks=False):
                # Check directories
                for dname in dirs:
                    if dname.startswith(magic_prefix):
                        found_artifacts.add(os.path.join(root, dname))

                # Check files
                for fname in files:
                    if fname.startswith(magic_prefix):
                        found_artifacts.add(os.path.join(root, fname))

        except PermissionError:
            pass
        except Exception as e:
            print(f"[ERROR] Signature scan error in {root_path}: {e}")

    return found_artifacts

def find_open_artifacts_proc(magic_prefix):
    """
    Bypasses userland hooks by iterating through the /proc filesystem's
    process file descriptors (fd) and executables (exe). These links often
    point to the real, un-hooked path of a hidden file if it is currently open or running.
    """
    found_artifacts = set()
    print(f"[INFO] Running /proc bypass scan for open/executing files...")

    # Regex to match PID directories in /proc
    pid_dirs = [d for d in os.listdir("/proc") if re.match(r'^\d+$', d)]

    for pid_dir in pid_dirs:
        proc_path = os.path.join("/proc", pid_dir)
        
        # 1. Check /proc/<PID>/exe (the running executable)
        exe_path = os.path.join(proc_path, "exe")
        if os.path.exists(exe_path):
            try:
                # Read the symlink target path
                target_path = os.readlink(exe_path)
                if magic_prefix in target_path:
                    found_artifacts.add(f"(EXE) {target_path}")
            except Exception:
                pass # Ignore processes we can't read (e.g., permission denied)

        # 2. Check /proc/<PID>/fd/* (open file descriptors)
        fd_path = os.path.join(proc_path, "fd")
        if os.path.isdir(fd_path):
            try:
                for fd_link in os.listdir(fd_path):
                    full_fd_link = os.path.join(fd_path, fd_link)
                    try:
                        # Read the symlink target path
                        target_path = os.readlink(full_fd_link)
                        # Filter out common pseudo-paths (pipes, sockets, deleted files)
                        if (magic_prefix in target_path and
                            not target_path.startswith("pipe:") and
                            not target_path.startswith("socket:") and
                            not target_path.endswith(" (deleted)")):
                            found_artifacts.add(f"(FD) {target_path} (PID: {pid_dir})")
                    except Exception:
                        pass
            except Exception:
                pass # Ignore directories we can't read (e.g., permission denied)

    return found_artifacts


if __name__ == "__main__":
    signature_artifacts = find_hidden_artifacts_signature(CRITICAL_INSTALL_PATHS, MAGIC_PREFIX)
    open_artifacts = find_open_artifacts_proc(MAGIC_PREFIX)
    direct_artifacts = find_artifacts_direct_check(CRITICAL_INSTALL_PATHS, MAGIC_PREFIX)

    # Combine and clean up artifact lists for presentation
    all_artifacts = signature_artifacts.union({a.split(') ')[1].split(' (PID:')[0] for a in open_artifacts})
    all_artifacts = all_artifacts.union({a.split(') ')[1] for a in direct_artifacts if a.startswith('(DIRECT-HIT)')})

    print("\n" + "="*50)
    print("      BROKEPKG ROOTKIT ARTIFACT SCAN RESULTS")
    print(f"       Magic String Used: '{MAGIC_PREFIX}'")
    print("="*50)

    if all_artifacts:
        print(f"\n[!!! DANGER !!!] {len(all_artifacts)} Potential Rootkit Artifact(s) Found:\n")

        # Print direct check findings first, as these are high-confidence hits based on user observation
        if direct_artifacts:
            print("--- DIRECT ACCESS BYPASS FINDINGS (Very High Suspicion) ---")
            for artifact in sorted(direct_artifacts):
                print(f"  - {artifact}")
            print("----------------------------------------------------------")


        # Print /proc findings next, as these are reliable indicators of running evasion
        if open_artifacts:
            print("\n--- /proc BYPASS FINDINGS (Highly Suspicious) ---")
            for artifact in sorted(open_artifacts):
                print(f"  - {artifact}")
            print("-----------------------------------------------")

        # Print signature scan findings
        if signature_artifacts:
            print("\n--- STANDARD SIGNATURE FINDINGS ---")
            # Filter out results already covered by the more reliable checks
            cleaned_signature_artifacts = sorted([
                a for a in signature_artifacts
                if a not in {item.split(') ')[1] for item in open_artifacts}.union({item.split(') ')[1] for item in direct_artifacts})
            ])
            if cleaned_signature_artifacts:
                for artifact in cleaned_signature_artifacts:
                    print(f"  - {artifact}")
            else:
                print("  (All signature findings were confirmed by bypass methods.)")
            print("-----------------------------------")


        print("\nACTION REQUIRED:")
        print("1. If an 'ls' command does NOT show these files, the system is highly likely compromised.")
        print("2. The rootkit may also be loaded via /etc/ld.so.preload. Check this file!")
        print("3. Always boot into a rescue environment for secure removal.")
    else:
        print("\n[SUCCESS] No files or directories matching the 'br0k3_n0w_h1dd3n' signature were found.")
        print("This does not guarantee your system is clean, but the specific rootkit")
        print("artifacts were not detected by any of the three detection methods.")
