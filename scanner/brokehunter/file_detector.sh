#!/bin/bash

# Brokepkg Rootkit Hidden Files Detector
# Detects files/directories hidden by brokepkg rootkit
# The rootkit hides ANY path containing "brokepkg" anywhere in it

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

MAGIC_STRING="br0k3_n0w_h1dd3n"
LOG_FILE="./brokepkg_scan_$(date +%Y%m%d_%H%M%S).log"
FOUND_FILES=()

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}  Brokepkg Rootkit Detector${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] This script must be run as root${NC}"
    exit 1
fi

# Check if rootkit is loaded
check_rootkit() {
    echo -e "${BLUE}[*] Checking for brokepkg module...${NC}"
    if lsmod | grep -q "brokepkg"; then
        echo -e "${RED}[!] WARNING: brokepkg module is LOADED and VISIBLE${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] Module not visible (may be hidden)${NC}"
        return 1
    fi
}

# Create a C program that directly uses getdents64 syscall
create_bypass_tool() {
    echo -e "${BLUE}[*] Creating syscall bypass tool...${NC}"
    
    cat > /tmp/scan_raw.c << 'CEOF'
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <string.h>

#define BUF_SIZE 4096

struct linux_dirent64 {
    unsigned long long d_ino;
    unsigned long long d_off;
    unsigned short     d_reclen;
    unsigned char      d_type;
    char               d_name[];
};

void scan_directory(const char *path, int depth) {
    int fd, nread;
    char buf[BUF_SIZE];
    struct linux_dirent64 *d;
    int bpos;
    char fullpath[4096];
    struct stat st;
    
    if (depth > 10) return;  // Limit recursion
    
    fd = open(path, O_RDONLY | O_DIRECTORY);
    if (fd == -1) {
        return;
    }
    
    while (1) {
        nread = syscall(SYS_getdents64, fd, buf, BUF_SIZE);
        if (nread == -1) {
            break;
        }
        if (nread == 0) {
            break;
        }
        
        for (bpos = 0; bpos < nread;) {
            d = (struct linux_dirent64 *) (buf + bpos);
            
            // Skip . and ..
            if (strcmp(d->d_name, ".") != 0 && strcmp(d->d_name, "..") != 0) {
                snprintf(fullpath, sizeof(fullpath), "%s/%s", path, d->d_name);
                printf("%s\n", fullpath);
                
                // Recursively scan subdirectories
                if (d->d_type == DT_DIR) {
                    scan_directory(fullpath, depth + 1);
                }
            }
            
            bpos += d->d_reclen;
        }
    }
    
    close(fd);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <directory>\n", argv[0]);
        return 1;
    }
    
    scan_directory(argv[1], 0);
    return 0;
}
CEOF

    if gcc -o /tmp/scan_raw /tmp/scan_raw.c 2>/dev/null; then
        echo -e "${GREEN}[+] Bypass tool created successfully${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] Failed to compile bypass tool (gcc not installed)${NC}"
        return 1
    fi
}

# Method 1: Unhide the rootkit temporarily
method_unhide() {
    echo ""
    echo -e "${YELLOW}[*] METHOD 1: Unhiding rootkit temporarily${NC}"
    echo -e "${BLUE}[*] Sending signal 31 to toggle visibility...${NC}"
    
    kill -31 0 2>/dev/null || true
    sleep 1
    
    if lsmod | grep -q "brokepkg"; then
        echo -e "${GREEN}[+] Module is now visible${NC}"
    fi
    
    echo -e "${BLUE}[*] Scanning for hidden files...${NC}"
    
    # Search in common locations
    for search_path in /home /tmp /var /root /opt /usr; do
        if [ -d "$search_path" ]; then
            echo -e "${BLUE}[*] Searching: $search_path${NC}"
            
            while IFS= read -r -d '' file; do
                echo -e "${RED}[!] FOUND: $file${NC}"
                echo "[FOUND] $file" >> "$LOG_FILE"
                FOUND_FILES+=("$file")
                
                # Get file info
                ls -lah "$file" >> "$LOG_FILE" 2>&1 || true
                file "$file" >> "$LOG_FILE" 2>&1 || true
            done < <(find "$search_path" -iname "*${MAGIC_STRING}*" -print0 2>/dev/null)
        fi
    done
    
    # Re-hide the module
    echo -e "${BLUE}[*] Re-hiding module...${NC}"
    kill -31 0 2>/dev/null || true
    sleep 1
}

# Method 2: Use bypass tool with raw syscalls
method_bypass_tool() {
    echo ""
    echo -e "${YELLOW}[*] METHOD 2: Using raw syscall bypass${NC}"
    
    if [ ! -f /tmp/scan_raw ]; then
        echo -e "${YELLOW}[!] Bypass tool not available${NC}"
        return 1
    fi
    
    for search_path in /home /tmp /var /root; do
        if [ -d "$search_path" ]; then
            echo -e "${BLUE}[*] Scanning with bypass tool: $search_path${NC}"
            
            /tmp/scan_raw "$search_path" 2>/dev/null | while IFS= read -r file; do
                if [[ "$file" == *"$MAGIC_STRING"* ]]; then
                    echo -e "${RED}[!] FOUND (raw): $file${NC}"
                    echo "[FOUND-RAW] $file" >> "$LOG_FILE"
                    
                    # Try to stat the file
                    if stat "$file" >/dev/null 2>&1; then
                        echo -e "${GREEN}    (file is accessible)${NC}"
                    else
                        echo -e "${YELLOW}    (file is hidden from stat)${NC}"
                    fi
                fi
            done
        fi
    done
}

# Method 3: Compare directory listings
method_compare_listings() {
    echo ""
    echo -e "${YELLOW}[*] METHOD 3: Comparing directory entry counts${NC}"
    
    for dir in /home/*/; do
        if [ -d "$dir" ]; then
            # Count with ls
            ls_count=$(ls -1A "$dir" 2>/dev/null | wc -l)
            
            # Count with bypass tool if available
            if [ -f /tmp/scan_raw ]; then
                raw_count=$(/tmp/scan_raw "$dir" 2>/dev/null | grep -c "^${dir}" || echo 0)
                
                if [ "$ls_count" -ne "$raw_count" ]; then
                    echo -e "${RED}[!] Discrepancy in $dir${NC}"
                    echo -e "    ls count: $ls_count, raw count: $raw_count"
                    echo "[DISCREPANCY] $dir - ls:$ls_count raw:$raw_count" >> "$LOG_FILE"
                fi
            fi
        fi
    done
}

# Method 4: Check open file descriptors
method_check_fds() {
    echo ""
    echo -e "${YELLOW}[*] METHOD 4: Checking process file descriptors${NC}"
    
    for proc_dir in /proc/[0-9]*; do
        if [ -d "$proc_dir/fd" ]; then
            pid=$(basename "$proc_dir")
            
            for fd in "$proc_dir/fd"/*; do
                if [ -L "$fd" ]; then
                    target=$(readlink "$fd" 2>/dev/null || echo "")
                    
                    if [[ "$target" == *"$MAGIC_STRING"* ]]; then
                        echo -e "${RED}[!] PID $pid has open FD to: $target${NC}"
                        echo "[FD] PID $pid: $target" >> "$LOG_FILE"
                        FOUND_FILES+=("$target (via PID $pid)")
                        
                        if [ -f "$proc_dir/cmdline" ]; then
                            cmdline=$(tr '\0' ' ' < "$proc_dir/cmdline" 2>/dev/null)
                            echo -e "    Command: $cmdline"
                        fi
                    fi
                fi
            done 2>/dev/null
        fi
    done
}

# Method 5: Search with Python (different syscall path)
method_python_search() {
    echo ""
    echo -e "${YELLOW}[*] METHOD 5: Using Python os.walk${NC}"
    
    python3 << 'PYEOF'
import os
import sys

magic = "br0k3_n0w_h1dd3n"
search_paths = ["/home", "/tmp", "/var", "/root"]

for base_path in search_paths:
    if not os.path.exists(base_path):
        continue
    
    try:
        for root, dirs, files in os.walk(base_path):
            # Check if path contains magic string
            if magic in root:
                print(f"[PYTHON] Found directory: {root}")
            
            # Check files
            for f in files:
                full_path = os.path.join(root, f)
                if magic in full_path:
                    print(f"[PYTHON] Found file: {full_path}")
    except Exception as e:
        pass
PYEOF
}

# Generate report
generate_report() {
    echo ""
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}       Detection Complete${NC}"
    echo -e "${BLUE}======================================${NC}"
    echo ""
    
    if [ ${#FOUND_FILES[@]} -eq 0 ]; then
        echo -e "${YELLOW}[!] No files detected by automated methods${NC}"
        echo ""
        echo -e "${YELLOW}Manual verification steps:${NC}"
        echo -e "  1. Unhide module:  ${GREEN}sudo kill -31 0${NC}"
        echo -e "  2. List files:     ${GREEN}find /home -name '*br0k3_n0w_h1dd3n*'${NC}"
        echo -e "  3. Verify in dir:  ${GREEN}ls -la /home/*/br0k3_n0w_h1dd3n*${NC}"
        echo -e "  4. Re-hide:        ${GREEN}sudo kill -31 0${NC}"
    else
        echo -e "${RED}[!] Detected ${#FOUND_FILES[@]} hidden file(s)/directory(ies):${NC}"
        echo ""
        printf '  %s\n' "${FOUND_FILES[@]}"
        echo ""
        echo -e "${GREEN}[+] Files have been logged to: $LOG_FILE${NC}"
    fi
    
    echo ""
    echo -e "${YELLOW}To remove the rootkit:${NC}"
    echo -e "  sudo kill -31 0  # Unhide"
    echo -e "  sudo rmmod brokepkg"
    echo -e "  rm -rf /path/to/brokepkg/directory"
    echo ""
}

# Main execution
main() {
    check_rootkit
    
    # Try to create bypass tool
    create_bypass_tool
    
    # Run all detection methods
    method_unhide
    method_bypass_tool
    method_compare_listings
    method_check_fds
    method_python_search
    
    # Generate report
    generate_report
    
    # Cleanup
    rm -f /tmp/scan_raw.c /tmp/scan_raw 2>/dev/null || true
}

main "$@"
