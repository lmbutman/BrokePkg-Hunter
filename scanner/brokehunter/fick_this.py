import os
import getpass

# --- Configuration ---
# The target prefix used by the brokepkg rootkit to hide files and directories.
# This value is based on analyzing the source code on the provided GitHub repository.
MAGIC_PREFIX = "br0k3n_n0w_h1dd3n"

# Directories to scan for hidden files.
# We focus on common temporary and configuration paths where rootkits often hide their files.
SCAN_PATHS = [
    "/tmp",
    "/dev/shm",
    "/etc",
    f"/home/{getpass.getuser()}"  # User's home directory
]

def find_hidden_artifacts(scan_paths, magic_prefix):
    """
    Scans specified directories recursively to find files or directories
    whose names start with the rootkit's known hiding prefix.

    Args:
        scan_paths (list): List of directory paths to begin scanning.
        magic_prefix (str): The string prefix used by the rootkit to hide files.

    Returns:
        list: A list of full paths of potential rootkit artifacts found.
    """
    found_artifacts = []
    print(f"[INFO] Starting scan for artifacts with prefix: '{magic_prefix}'...")

    for root_path in scan_paths:
        if not os.path.isdir(root_path):
            print(f"[WARN] Path not found, skipping: {root_path}")
            continue

        try:
            # os.walk is used to iterate recursively through the directory tree.
            for root, dirs, files in os.walk(root_path, topdown=True, followlinks=False):
                # Check directories (rootkit can hide entire directories)
                for dname in dirs:
                    if dname.startswith(magic_prefix):
                        full_path = os.path.join(root, dname)
                        found_artifacts.append(full_path)

                # Check files
                for fname in files:
                    if fname.startswith(magic_prefix):
                        full_path = os.path.join(root, fname)
                        found_artifacts.append(full_path)

        except PermissionError:
            print(f"[ERROR] Permission denied for path: {root_path}")
        except Exception as e:
            print(f"[ERROR] An unexpected error occurred in {root_path}: {e}")

    return found_artifacts

if __name__ == "__main__":
    # Ensure the home directory path is set correctly
    try:
        current_user_home = os.path.expanduser("~")
        if current_user_home not in SCAN_PATHS:
             SCAN_PATHS.append(current_user_home)
    except Exception:
        pass # If we can't find the home dir, we proceed with the other paths.

    artifacts = find_hidden_artifacts(SCAN_PATHS, MAGIC_PREFIX)

    print("\n" + "="*50)
    print("      BROKEPKG ROOTKIT ARTIFACT SCAN RESULTS")
    print("="*50)

    if artifacts:
        print(f"\n[!!! DANGER !!!] {len(artifacts)} Potential Hidden Artifact(s) Found:\n")
        for artifact in artifacts:
            print(f"  - {artifact}")
        print("\nACTION REQUIRED:")
        print("1. If a normal 'ls' command does NOT show these files, they are likely hidden.")
        print("2. The rootkit may also be loaded via /etc/ld.so.preload. Check this file!")
        print("3. Always boot into a rescue environment for secure removal.")
    else:
        print("\n[SUCCESS] No files or directories matching the 'broken_' signature found.")
        print("This does not guarantee your system is clean, but the specific rootkit")
        print("artifacts (files starting with 'broken_') were not detected in the scanned paths.")
