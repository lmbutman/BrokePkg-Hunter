#!/bin/bash

# Advanced Brokepkg Rootkit Hidden Files Detector
# Uses direct inode enumeration and raw block device access to bypass rootkit hooks

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

MAGIC_STRING="br0k3_n0w_h1dd3n"
LOG_FILE="./brokepkg_scan_$(date +%Y%m%d_%H%M%S).log"
FOUND_FILES=()

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}  Advanced Brokepkg Detection Tool${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] This script must be run as root${NC}"
    exit 1
fi

# Method 1: Direct inode enumeration using debugfs
scan_with_debugfs() {
    local mount_point="$1"
    local device=$(df "$mount_point" | tail -1 | awk '{print $1}')
    
    echo -e "${BLUE}[*] Using debugfs on $device for $mount_point${NC}"
    
    if ! command -v debugfs &> /dev/null; then
        echo -e "${YELLOW}[!] debugfs not found, skipping this method${NC}"
        return
    fi
    
    
    # Method 4: Process file descriptors
    echo ""
    scan_proc_fds
    
    # Method 5: Alternate strings
    echo ""
    check_alternate_strings
    
    # Generate report
    echo ""
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}    Scan Complete${NC}"
    echo -e "${BLUE}======================================${NC}"
    echo ""
    
    if [ ${#FOUND_FILES[@]} -eq 0 ]; then
        echo -e "${YELLOW}[!] No hidden files detected with these methods${NC}"
        echo ""
        echo -e "${YELLOW}Suggestions:${NC}"
        echo -e "  1. Make rootkit visible first: ${GREEN}kill -31 0${NC}"
        echo -e "  2. Try scanning from a live CD/USB"
        echo -e "  3. Mount filesystem on another system"
        echo -e "  4. Check if magic string is different than 'brokepkg'"
        echo -e "  5. Look in /proc/*/fd for processes with suspicious file handles"
    else
        echo -e "${RED}[!] Found ${#FOUND_FILES[@]} suspicious file(s):${NC}"
        printf '%s\n' "${FOUND_FILES[@]}" | sort -u
    fi
    
    echo ""
    echo -e "${BLUE}[*] Log saved to: $LOG_FILE${NC}"
    echo ""
    echo -e "${YELLOW}To unhide rootkit and remove:${NC}"
    echo -e "  ${GREEN}kill -31 0${NC}         # Make module visible"
    echo -e "  ${GREEN}lsmod | grep broke${NC}  # Verify it's visible"
    echo -e "  ${GREEN}rmmod brokepkg${NC}      # Remove module"
}

main "$@" Get filesystem type
    local fs_type=$(df -T "$mount_point" | tail -1 | awk '{print $2}')
    
    if [[ "$fs_type" != "ext"* ]]; then
        echo -e "${YELLOW}[!] debugfs only works with ext filesystems, skipping${NC}"
        return
    fi
    
    echo -e "${BLUE}[*] Enumerating all inodes (this bypasses readdir hooks)...${NC}"
    
    # List all inodes in filesystem
    debugfs -R "ls -l -r /" "$device" 2>/dev/null | while read -r line; do
        if [[ "$line" == *"$MAGIC_STRING"* ]]; then
            echo -e "${RED}[!] FOUND (via debugfs): $line${NC}"
            echo "[!] FOUND (via debugfs): $line" >> "$LOG_FILE"
        fi
    done
}

# Method 2: Compare stat results with readdir results
find_stat_discrepancies() {
    local dir="$1"
    local max_depth="${2:-3}"
    
    echo -e "${BLUE}[*] Checking for stat/readdir discrepancies in: $dir${NC}"
    
    # Build a list of inodes that stat says exist
    local -A stat_inodes
    local -A readdir_inodes
    
    # Get all inodes by iterating inode numbers
    # This is slow but thorough
    for inode in $(seq 1 1000000); do
        local path=$(find "$dir" -inum "$inode" -print -quit 2>/dev/null)
        if [ -n "$path" ]; then
            stat_inodes[$inode]="$path"
        fi
    done
    
    # Compare with readdir results
    while IFS= read -r -d '' file; do
        local inode=$(stat -c '%i' "$file" 2>/dev/null)
        if [ -n "$inode" ]; then
            readdir_inodes[$inode]="$file"
        fi
    done < <(find "$dir" -maxdepth "$max_depth" -print0 2>/dev/null)
    
    # Find discrepancies
    for inode in "${!stat_inodes[@]}"; do
        if [ -z "${readdir_inodes[$inode]:-}" ]; then
            echo -e "${RED}[!] HIDDEN FILE FOUND: ${stat_inodes[$inode]} (inode: $inode)${NC}"
            echo "[!] HIDDEN FILE: ${stat_inodes[$inode]} (inode: $inode)" >> "$LOG_FILE"
            FOUND_FILES+=("${stat_inodes[$inode]}")
        fi
    done
}

# Method 3: Use getdents64 syscall directly via C program
create_getdents_binary() {
    local tmpdir=$(mktemp -d)
    local src="$tmpdir/getdents.c"
    local bin="$tmpdir/getdents"
    
    cat > "$src" << 'EOF'
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
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <directory>\n", argv[0]);
        return 1;
    }
    
    int fd = open(argv[1], O_RDONLY | O_DIRECTORY);
    if (fd == -1) {
        perror("open");
        return 1;
    }
    
    char buf[BUF_SIZE];
    int nread;
    
    while (1) {
        nread = syscall(SYS_getdents64, fd, buf, BUF_SIZE);
        if (nread == -1) {
            perror("getdents64");
            break;
        }
        if (nread == 0)
            break;
            
        for (int pos = 0; pos < nread;) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + pos);
            printf("%s\n", d->d_name);
            pos += d->d_reclen;
        }
    }
    
    close(fd);
    return 0;
}
EOF
    
    if command -v gcc &> /dev/null; then
        gcc -o "$bin" "$src" 2>/dev/null
        if [ -f "$bin" ]; then
            echo "$bin"
            return 0
        fi
    fi
    
    rm -rf "$tmpdir"
    return 1
}

scan_with_raw_getdents() {
    local dir="$1"
    
    echo -e "${BLUE}[*] Using raw getdents64 syscall to bypass hooks in: $dir${NC}"
    
    local getdents_bin=$(create_getdents_binary)
    if [ -z "$getdents_bin" ]; then
        echo -e "${YELLOW}[!] Could not compile getdents tool, skipping${NC}"
        return
    fi
    
    "$getdents_bin" "$dir" 2>/dev/null | while read -r filename; do
        if [[ "$filename" == *"$MAGIC_STRING"* ]]; then
            echo -e "${RED}[!] FOUND (via raw syscall): $dir/$filename${NC}"
            echo "[!] FOUND (via raw syscall): $dir/$filename" >> "$LOG_FILE"
            FOUND_FILES+=("$dir/$filename")
        fi
    done
    
    rm -rf "$(dirname "$getdents_bin")"
}

# Method 4: Check all open file descriptors in /proc
scan_proc_fds() {
    echo -e "${BLUE}[*] Scanning all process file descriptors...${NC}"
    
    for pid in /proc/[0-9]*; do
        if [ -d "$pid/fd" ]; then
            for fd in "$pid/fd"/* 2>/dev/null; do
                if [ -L "$fd" ]; then
                    local target=$(readlink "$fd" 2>/dev/null || true)
                    if [ -n "$target" ] && [[ "$target" == *"$MAGIC_STRING"* ]] && [[ "$target" != "/dev/"* ]]; then
                        echo -e "${RED}[!] Process $(basename $pid) has open FD to: $target${NC}"
                        echo "[!] Process $(basename $pid) has FD: $target" >> "$LOG_FILE"
                        FOUND_FILES+=("$target (via pid $(basename $pid))")
                    fi
                fi
            done
        fi
        
        # Check memory maps
        if [ -f "$pid/maps" ]; then
            while read -r line; do
                if [[ "$line" == *"$MAGIC_STRING"* ]]; then
                    local file=$(echo "$line" | awk '{print $NF}')
                    if [ -n "$file" ] && [[ "$file" != "["* ]]; then
                        echo -e "${RED}[!] Process $(basename $pid) has mapped: $file${NC}"
                        echo "[!] Process $(basename $pid) has mapped: $file" >> "$LOG_FILE"
                        FOUND_FILES+=("$file (mapped by pid $(basename $pid))")
                    fi
                fi
            done < "$pid/maps" 2>/dev/null
        fi
    done
}

# Method 5: Brute force inode numbers
bruteforce_inodes() {
    local mount_point="$1"
    local max_inode="${2:-100000}"
    
    echo -e "${BLUE}[*] Brute-forcing inode numbers on $mount_point (1-$max_inode)...${NC}"
    echo -e "${YELLOW}[*] This may take a while...${NC}"
    
    for inode in $(seq 1 "$max_inode"); do
        # Show progress every 10000 inodes
        if (( inode % 10000 == 0 )); then
            echo -ne "\r${BLUE}[*] Progress: $inode/$max_inode${NC}"
        fi
        
        # Try to find file by inode
        local file=$(find "$mount_point" -xdev -inum "$inode" -print -quit 2>/dev/null)
        if [ -n "$file" ]; then
            local basename=$(basename "$file")
            if [[ "$basename" == *"$MAGIC_STRING"* ]]; then
                echo -e "\n${RED}[!] FOUND (via inode $inode): $file${NC}"
                echo "[!] FOUND (via inode $inode): $file" >> "$LOG_FILE"
                FOUND_FILES+=("$file")
            fi
        fi
    done
    echo ""
}

# Method 6: Use alternate magic strings
check_alternate_strings() {
    echo -e "${BLUE}[*] Checking for alternate magic strings...${NC}"
    
    local alt_strings=("brokepkg" "BROKEPKG" ".brokepkg" "broke" "pkg" "rootkit")
    
    for magic in "${alt_strings[@]}"; do
        echo -e "${BLUE}[*] Searching for: $magic${NC}"
        scan_proc_fds_for_string "$magic"
    done
}

scan_proc_fds_for_string() {
    local search_str="$1"
    
    for pid in /proc/[0-9]*; do
        if [ -d "$pid/fd" ]; then
            for fd in "$pid/fd"/* 2>/dev/null; do
                if [ -L "$fd" ]; then
                    local target=$(readlink "$fd" 2>/dev/null || true)
                    if [ -n "$target" ] && [[ "$target" == *"$search_str"* ]] && [[ "$target" != "/dev/"* ]]; then
                        echo -e "${RED}[!] Found '$search_str' in: $target (PID: $(basename $pid))${NC}"
                        echo "[!] Found '$search_str' in: $target" >> "$LOG_FILE"
                        FOUND_FILES+=("$target")
                    fi
                fi
            done
        fi
    done
}

# Main execution
main() {
    echo -e "${YELLOW}[*] Target magic string: '$MAGIC_STRING'${NC}"
    echo -e "${YELLOW}[*] Specify directories to scan (space-separated, or press Enter for /tmp /home):${NC}"
    read -r -p "Directories: " input_dirs
    
    if [ -z "$input_dirs" ]; then
        SCAN_DIRS=("/tmp" "/home")
    else
        IFS=' ' read -r -a SCAN_DIRS <<< "$input_dirs"
    fi
    
    echo ""
    echo -e "${BLUE}[*] Starting multi-method scan...${NC}"
    echo ""
    
    # Run all detection methods
    for dir in "${SCAN_DIRS[@]}"; do
        if [ ! -d "$dir" ]; then
            echo -e "${YELLOW}[!] Directory does not exist: $dir${NC}"
            continue
        fi
        
        echo -e "${GREEN}[+] Scanning: $dir${NC}"
        
        # Method 1: debugfs
        scan_with_debugfs "$dir"
        
        # Method 2: Raw syscall
        scan_with_raw_getdents "$dir"
        
        # Method 3: Inode bruteforce (limited range for speed)
        read -r -p "Brute force inodes in $dir? This is slow (y/N): " -n 1
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            bruteforce_inodes "$dir" 50000
        fi
    done
    
    #
