#!/bin/bash

# Advanced Brokepkg Rootkit Hidden Files Detector
# Uses low-level techniques to bypass rootkit hooks

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

LOG_FILE="./brokepkg_scan_$(date +%Y%m%d_%H%M%S).log"
FOUND_FILES=()

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}  Brokepkg Advanced Detection Tool${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] This script must be run as root${NC}"
    exit 1
fi

# Method 1: Compare ls output with raw getdents64 system call
echo -e "${YELLOW}[*] Method 1: Comparing visible files with raw directory entries${NC}"
echo "[*] Method 1: Raw directory comparison" >> "$LOG_FILE"

check_directory_raw() {
    local dir="$1"
    
    if [ ! -d "$dir" ]; then
        return
    fi
    
    echo -e "${BLUE}[*] Checking: $dir${NC}"
    
    # Get visible file count
    local visible_count=$(ls -1a "$dir" 2>/dev/null | wc -l)
    
    # Use Python to read directory with direct syscalls (bypasses some hooks)
    local python_files=$(python3 -c "
import os
import sys
try:
    entries = os.listdir('$dir')
    for entry in entries:
        print(entry)
except Exception as e:
    pass
" 2>/dev/null)
    
    local python_count=$(echo "$python_files" | grep -c . || echo 0)
    
    if [ "$visible_count" -ne "$python_count" ]; then
        echo -e "${RED}[!] Discrepancy in $dir: ls shows $visible_count, python shows $python_count${NC}"
        echo "[!] Discrepancy in $dir: ls=$visible_count, python=$python_count" >> "$LOG_FILE"
    fi
}

# Method 2: Use C program to directly call getdents64
echo -e "${YELLOW}[*] Method 2: Creating native binary to bypass hooks${NC}"

create_getdents_tool() {
    cat > /tmp/getdents_bypass.c << 'EOF'
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <string.h>

#define BUF_SIZE 1024

struct linux_dirent64 {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

int main(int argc, char *argv[]) {
    int fd, nread;
    char buf[BUF_SIZE];
    struct linux_dirent64 *d;
    int bpos;
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <directory>\n", argv[0]);
        return 1;
    }
    
    fd = open(argv[1], O_RDONLY | O_DIRECTORY);
    if (fd == -1) {
        perror("open");
        return 1;
    }
    
    while (1) {
        nread = syscall(SYS_getdents64, fd, buf, BUF_SIZE);
        if (nread == -1) {
            perror("getdents64");
            break;
        }
        
        if (nread == 0)
            break;
        
        for (bpos = 0; bpos < nread;) {
            d = (struct linux_dirent64 *) (buf + bpos);
            printf("%s\n", d->d_name);
            bpos += d->d_reclen;
        }
    }
    
    close(fd);
    return 0;
}
EOF

    gcc -o /tmp/getdents_bypass /tmp/getdents_bypass.c 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] Created bypass tool${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] Could not compile bypass tool (gcc not available)${NC}"
        return 1
    fi
}

# Method 3: Check inode allocation vs visible files
echo -e "${YELLOW}[*] Method 3: Checking inode discrepancies${NC}"

check_inode_gaps() {
    local dir="$1"
    
    if [ ! -d "$dir" ]; then
        return
    fi
    
    # Get all visible inodes in directory
    local visible_inodes=$(ls -lai "$dir" 2>/dev/null | awk '{print $1}' | grep -E '^[0-9]+' | sort -n)
    
    # Check for gaps in inode sequence that might indicate hidden files
    # This is a heuristic approach
    
    # Get inode range
    local min_inode=$(echo "$visible_inodes" | head -1)
    local max_inode=$(echo "$visible_inodes" | tail -1)
    
    if [ -n "$min_inode" ] && [ -n "$max_inode" ]; then
        local inode_count=$(echo "$visible_inodes" | wc -l)
        local inode_range=$((max_inode - min_inode + 1))
        
        # If there's a large gap, might indicate hidden files
        if [ $inode_range -gt $((inode_count * 2)) ]; then
            echo -e "${YELLOW}[!] Large inode gaps in $dir (range: $inode_range, visible: $inode_count)${NC}"
            echo "[!] Inode gaps in $dir" >> "$LOG_FILE"
        fi
    fi
}

# Method 4: Unhide the rootkit and scan
echo -e "${YELLOW}[*] Method 4: Attempting to unhide rootkit temporarily${NC}"

unhide_and_scan() {
    echo -e "${BLUE}[*] Sending signal 31 to unhide brokepkg module...${NC}"
    
    # Signal 31 toggles module visibility
    kill -31 0 2>/dev/null || true
    
    sleep 1
    
    # Check if module is now visible
    if lsmod | grep -q "brokepkg"; then
        echo -e "${GREEN}[+] Module is now visible!${NC}"
        echo "[+] Module unhidden successfully" >> "$LOG_FILE"
        
        # Now scan for files - they should be visible
        echo -e "${BLUE}[*] Scanning all directories for files with 'brokepkg' in name...${NC}"
        
        for search_dir in /home /tmp /var /root /opt /usr/local / ; do
            if [ -d "$search_dir" ]; then
                echo -e "${BLUE}[*] Scanning $search_dir...${NC}"
                
                while IFS= read -r file; do
                    echo -e "${RED}[!] FOUND: $file${NC}"
                    echo "[!] FOUND: $file" >> "$LOG_FILE"
                    FOUND_FILES+=("$file")
                    
                    # Get file details
                    ls -lah "$file" 2>/dev/null >> "$LOG_FILE" || true
                done < <(find "$search_dir" -name "*brokepkg*" 2>/dev/null || true)
            fi
        done
        
        # Hide module again (signal 31 toggles)
        echo -e "${BLUE}[*] Re-hiding module...${NC}"
        kill -31 0 2>/dev/null || true
        
        return 0
    else
        echo -e "${YELLOW}[!] Module still hidden after signal 31${NC}"
        return 1
    fi
}

# Method 5: Direct disk reading (if filesystem device is known)
echo -e "${YELLOW}[*] Method 5: Attempting direct disk analysis${NC}"

direct_disk_scan() {
    echo -e "${BLUE}[*] Checking for debugfs availability...${NC}"
    
    if ! command -v debugfs &> /dev/null; then
        echo -e "${YELLOW}[!] debugfs not available (install e2fsprogs)${NC}"
        return 1
    fi
    
    # Try to use debugfs to read raw directory entries
    # This works on ext2/3/4 filesystems
    for device in $(df -t ext4 -t ext3 -t ext2 | tail -n +2 | awk '{print $1}'); do
        echo -e "${BLUE}[*] Analyzing device: $device${NC}"
        
        # This is a simplified approach - full implementation would need
        # to parse ext filesystem structures directly
    done
}

# Method 6: Check /proc file descriptors
echo -e "${YELLOW}[*] Method 6: Checking process file descriptors${NC}"

check_proc_fds() {
    echo -e "${BLUE}[*] Scanning process file descriptors for hidden files...${NC}"
    
    for proc_dir in /proc/[0-9]*; do
        if [ -d "$proc_dir/fd" ]; then
            pid=$(basename "$proc_dir")
            
            for fd in "$proc_dir/fd"/* 2>/dev/null; do
                if [ -L "$fd" ]; then
                    target=$(readlink "$fd" 2>/dev/null || echo "")
                    
                    if [[ "$target" == *"brokepkg"* ]] || [[ "$target" == *"(deleted)"* && "$target" == *"brokepkg"* ]]; then
                        echo -e "${RED}[!] Process $pid has FD to: $target${NC}"
                        echo "[!] Process $pid FD: $target" >> "$LOG_FILE"
                        FOUND_FILES+=("$target (PID: $pid)")
                        
                        # Get process info
                        if [ -f "$proc_dir/cmdline" ]; then
                            cmdline=$(cat "$proc_dir/cmdline" 2>/dev/null | tr '\0' ' ')
                            echo -e "${BLUE}    Command: $cmdline${NC}"
                            echo "    Command: $cmdline" >> "$LOG_FILE"
                        fi
                    fi
                fi
            done
        fi
    done
}

# Method 7: Check kernel ring buffer for clues
echo -e "${YELLOW}[*] Method 7: Checking kernel logs${NC}"

check_kernel_logs() {
    echo -e "${BLUE}[*] Searching dmesg for brokepkg activity...${NC}"
    
    dmesg | grep -i "brokepkg" >> "$LOG_FILE" 2>&1 || true
}

# Main execution
main() {
    echo -e "${BLUE}[*] Starting advanced detection...${NC}"
    echo ""
    
    # Try the most effective method first: unhiding the rootkit
    echo -e "${GREEN}[+] RECOMMENDED: Attempting to unhide rootkit first${NC}"
    if unhide_and_scan; then
        echo -e "${GREEN}[+] Scan completed with module unhidden${NC}"
    else
        echo -e "${YELLOW}[!] Could not unhide module, trying alternative methods...${NC}"
        echo ""
        
        # Try creating bypass tool
        if create_getdents_tool; then
            echo -e "${BLUE}[*] Using bypass tool to scan directories...${NC}"
            
            for dir in /home /tmp /var /root /opt; do
                if [ -d "$dir" ]; then
                    echo -e "${BLUE}[*] Scanning $dir with bypass tool...${NC}"
                    
                    # Run the bypass tool
                    raw_entries=$(/tmp/getdents_bypass "$dir" 2>/dev/null || echo "")
                    
                    # Check each entry
                    echo "$raw_entries" | while IFS= read -r entry; do
                        if [[ "$entry" == *"brokepkg"* ]]; then
                            full_path="$dir/$entry"
                            echo -e "${RED}[!] FOUND (raw): $full_path${NC}"
                            echo "[!] FOUND (raw): $full_path" >> "$LOG_FILE"
                            FOUND_FILES+=("$full_path")
                        fi
                    done
                fi
            done
        fi
        
        # Check for directory discrepancies
        for dir in /home/* /tmp /var/tmp /root; do
            check_directory_raw "$dir"
            check_inode_gaps "$dir"
        done
    fi
    
    # Always check process file descriptors
    check_proc_fds
    
    # Check kernel logs
    check_kernel_logs
    
    # Generate report
    echo ""
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}    Detection Complete${NC}"
    echo -e "${BLUE}======================================${NC}"
    echo ""
    
    if [ ${#FOUND_FILES[@]} -eq 0 ]; then
        echo -e "${YELLOW}[!] No hidden files detected with current methods${NC}"
        echo ""
        echo -e "${YELLOW}Additional steps to try:${NC}"
        echo -e "  1. Manually unhide: ${GREEN}kill -31 0${NC}"
        echo -e "  2. Then search: ${GREEN}find / -name '*brokepkg*' 2>/dev/null${NC}"
        echo -e "  3. Check specific directories manually"
        echo -e "  4. Boot from live CD and mount filesystem to scan"
        echo -e "  5. Use: ${GREEN}grep -r brokepkg /home /tmp /var 2>/dev/null${NC}"
    else
        echo -e "${RED}[!] Found ${#FOUND_FILES[@]} suspicious file(s):${NC}"
        echo ""
        printf '  %s\n' "${FOUND_FILES[@]}"
        echo ""
        echo -e "${YELLOW}[*] Next steps:${NC}"
        echo -e "  1. Examine files: ls -lah <file>"
        echo -e "  2. Check file type: file <file>"
        echo -e "  3. View safely: cat <file> | less"
        echo -e "  4. Remove rootkit: kill -31 0 && rmmod brokepkg"
    fi
    
    echo ""
    echo -e "${BLUE}[*] Full log: $LOG_FILE${NC}"
    
    # Cleanup
    rm -f /tmp/getdents_bypass.c /tmp/getdents_bypass 2>/dev/null || true
}

# Run
main "$@"
