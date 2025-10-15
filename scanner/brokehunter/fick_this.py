import os
import getpass
import re

# --- Configuration ---
# The target prefix used by the brokepkg rootkit to hide files and directories.
# This value is based on analyzing the source code on the provided GitHub repository.
MAGIC_PREFIX = "br0k3n_n0w_h1dd3n"

# Directories to scan for unexecuted hidden files (Signature Scan - will be fooled by hooks)
SCAN_PATHS = [
    "/tmp",
    "/dev/shm",
    "/etc",
]

def find_hidden_artifacts_signature(scan_paths, magic_prefix):
    """
    Performs a standard recursive directory scan for files/dirs with the magic prefix.
    NOTE: This method may be defeated by rootkit hooks (like readdir hooking).
    It is useful for finding non-executed artifacts in critical paths.
    """
    found_artifacts = set()
    print(f"[INFO] Running standard signature scan on: {scan_paths}")

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
            # We expect permission errors in paths like /etc or other restricted areas
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
    signature_artifacts = find_hidden_artifacts_signature(SCAN_PATHS, MAGIC_PREFIX)
    open_artifacts = find_open_artifacts_proc(MAGIC_PREFIX)

    all_artifacts = signature_artifacts.union({a.split(') ')[1].split(' (PID:')[0] for a in open_artifacts})

    print("\n" + "="*50)
    print("      BROKEPKG ROOTKIT ARTIFACT SCAN RESULTS")
    print("="*50)

    if all_artifacts:
        print(f"\n[!!! DANGER !!!] {len(all_artifacts)} Potential Rootkit Artifact(s) Found:\n")

        # Print /proc findings first, as these are the most reliable indicators of evasion
        if open_artifacts:
            print("--- /proc BYPASS FINDINGS (Highly Suspicious) ---")
            for artifact in sorted(open_artifacts):
                print(f"  - {artifact}")
            print("-----------------------------------------------")

        # Print signature scan findings
        if signature_artifacts:
            print("\n--- STANDARD SIGNATURE FINDINGS ---")
            for artifact in sorted(signature_artifacts):
                # Only print signature findings that weren't already found by /proc (to avoid duplicates)
                if artifact not in {a.split(') ')[1].split(' (PID:')[0] for a in open_artifacts}:
                    print(f"  - {artifact}")
            print("-----------------------------------")


        print("\nACTION REQUIRED:")
        print("1. If an 'ls' command does NOT show these files, the system is highly likely compromised.")
        print("2. The rootkit may also be loaded via /etc/ld.so.preload. Check this file!")
        print("3. Always boot into a rescue environment for secure removal.")
    else:
        print("\n[SUCCESS] No files or directories matching the 'broken_' signature were found.")
        print("This does not guarantee your system is clean, but the specific rootkit")
        print("artifacts (files starting with 'broken_') were not detected by either the")
        print("signature scan or the /proc bypass check.")
