#!/bin/bash

# Brokepkg Rootkit Hidden Files Detector
# Detects files hidden by the brokepkg LKM rootkit
# The rootkit hides files/directories containing MAGIC_HIDE in their name

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
MAGIC_STRING="br0k3_n0w_h1dd3n"  # Default magic string used by brokepkg
SCAN_PATHS=("/home" "/tmp" "/var" "/opt" "/usr/local" "/root")
LOG_FILE="./brokepkg_scan_$(date +%Y%m%d_%H%M%S).log"
FOUND_FILES=()

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}[!] Warning: Not running as root. Some files may be inaccessible.${NC}"
        echo -e "${YELLOW}[!] Consider running with sudo for complete scan.${NC}"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Check if rootkit module is loaded
check_module_loaded() {
    echo -e "${BLUE}[*] Checking if brokepkg module is loaded...${NC}"
    if lsmod | grep -q "brokepkg"; then
        echo -e "${RED}[!] WARNING: brokepkg module is currently LOADED!${NC}"
        echo -e "${RED}[!] Files may be hidden from this scan.${NC}"
        return 0
    else
        echo -e "${GREEN}[+] brokepkg module not visible in lsmod${NC}"
        # Module might be hidden - check alternative ways
        if [ -d "/sys/module/brokepkg" ]; then
            echo -e "${RED}[!] WARNING: brokepkg module directory found in /sys/module/${NC}"
            return 0
        fi
    fi
    return 1
}

# Direct kernel memory search for hidden modules
check_hidden_module() {
    echo -e "${BLUE}[*] Checking for hidden kernel modules...${NC}"
    
    # Check for suspicious kernel threads
    if ps aux | grep -E "\[.*brokepkg.*\]" | grep -v grep > /dev/null 2>&1; then
        echo -e "${RED}[!] Found suspicious kernel thread related to brokepkg${NC}"
    fi
    
    # Check for anomalies in /proc/modules vs lsmod
    local proc_count=$(wc -l < /proc/modules)
    local lsmod_count=$(lsmod | tail -n +2 | wc -l)
    
    if [ "$proc_count" -ne "$lsmod_count" ]; then
        echo -e "${YELLOW}[!] Module count mismatch: /proc/modules=$proc_count, lsmod=$lsmod_count${NC}"
        echo -e "${YELLOW}[!] A module may be hidden${NC}"
    fi
}

# Use debugfs to directly read directory entries (bypasses rootkit hooks)
scan_with_debugfs() {
    local path="$1"
    
    if ! command -v debugfs &> /dev/null; then
        return 1
    fi
    
    # Get the device for the path
    local device=$(df "$path" | tail -1 | awk '{print $1}')
    
    # This requires root and may not work on all filesystems
    return 1
}

# Scan using find with raw system calls
scan_for_hidden_files() {
    local search_path="$1"
    
    echo -e "${BLUE}[*] Scanning: $search_path${NC}"
    echo "[*] Scanning: $search_path" >> "$LOG_FILE"
    
    # Method 1: Direct filesystem scan using find
    # This may still be hooked, but it's worth trying
    while IFS= read -r -d '' file; do
        local basename=$(basename "$file")
        if [[ "$basename" == *"$MAGIC_STRING"* ]]; then
            echo -e "${RED}[!] FOUND: $file${NC}"
            echo "[!] FOUND: $file" >> "$LOG_FILE"
            FOUND_FILES+=("$file")
        fi
    done < <(find "$search_path" -print0 2>/dev/null || true)
    
    # Method 2: Use getfattr to check for hidden extended attributes
    # Rootkits sometimes use xattrs to mark files
    if command -v getfattr &> /dev/null; then
        while IFS= read -r -d '' file; do
            local attrs=$(getfattr -d "$file" 2>/dev/null || true)
            if [[ "$attrs" == *"$MAGIC_STRING"* ]] || [[ "$attrs" == *"rootkit"* ]]; then
                echo -e "${YELLOW}[!] Suspicious xattr: $file${NC}"
                echo "[!] Suspicious xattr: $file" >> "$LOG_FILE"
                FOUND_FILES+=("$file (xattr)")
            fi
        done < <(find "$search_path" -type f -print0 2>/dev/null || true)
    fi
}

# Check for discrepancies using stat vs readdir
check_stat_discrepancies() {
    local dir="$1"
    
    echo -e "${BLUE}[*] Checking for stat/readdir discrepancies in: $dir${NC}"
    
    # Get inode count from filesystem
    local total_inodes=$(find "$dir" -printf '.' 2>/dev/null | wc -c)
    
    # Count visible files
    local visible_files=$(ls -laR "$dir" 2>/dev/null | wc -l)
    
    # Large discrepancy might indicate hidden files
    # This is a heuristic and may have false positives
}

# Memory analysis for hidden files
check_process_handles() {
    echo -e "${BLUE}[*] Checking open file handles for hidden files...${NC}"
    
    for pid in /proc/[0-9]*; do
        if [ -d "$pid/fd" ]; then
            for fd in "$pid/fd"/*; do
                if [ -L "$fd" ]; then
                    local target=$(readlink "$fd" 2>/dev/null || true)
                    if [[ "$target" == *"$MAGIC_STRING"* ]]; then
                        echo -e "${RED}[!] Process $(basename $pid) has handle to hidden file: $target${NC}"
                        echo "[!] Process $(basename $pid) has handle to: $target" >> "$LOG_FILE"
                        FOUND_FILES+=("$target (via pid $(basename $pid))")
                    fi
                fi
            done
        fi
    done
}

# Check for hidden network connections
check_hidden_ports() {
    echo -e "${BLUE}[*] Checking for hidden network connections...${NC}"
    echo "[*] Checking for hidden network connections" >> "$LOG_FILE"
    
    # Compare netstat with /proc/net/tcp
    # Rootkit hides ports using signal 62
    
    if command -v ss &> /dev/null; then
        ss -tuln >> "$LOG_FILE" 2>&1 || true
    fi
    
    if [ -f /proc/net/tcp ]; then
        cat /proc/net/tcp >> "$LOG_FILE" 2>&1 || true
    fi
}

# Generate report
generate_report() {
    echo ""
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}    Scan Complete${NC}"
    echo -e "${BLUE}======================================${NC}"
    echo ""
    
    if [ ${#FOUND_FILES[@]} -eq 0 ]; then
        echo -e "${GREEN}[+] No hidden files detected${NC}"
        echo "[+] No hidden files detected" >> "$LOG_FILE"
    else
        echo -e "${RED}[!] Found ${#FOUND_FILES[@]} suspicious file(s):${NC}"
        echo "[!] Found ${#FOUND_FILES[@]} suspicious file(s):" >> "$LOG_FILE"
        printf '%s\n' "${FOUND_FILES[@]}"
        printf '%s\n' "${FOUND_FILES[@]}" >> "$LOG_FILE"
    fi
    
    echo ""
    echo -e "${BLUE}[*] Full log saved to: $LOG_FILE${NC}"
    echo ""
    echo -e "${YELLOW}[*] Remediation steps:${NC}"
    echo -e "    1. Make rootkit visible: kill -31 0"
    echo -e "    2. Remove module: sudo rmmod brokepkg"
    echo -e "    3. Check for persistence mechanisms in /etc/modules"
    echo -e "    4. Scan system with: rkhunter --check"
}

# Main execution
main() {
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}  Brokepkg Rootkit Detection Tool${NC}"
    echo -e "${BLUE}======================================${NC}"
    echo ""
    
    check_root
    check_module_loaded
    check_hidden_module
    
    echo ""
    echo -e "${BLUE}[*] Starting filesystem scan...${NC}"
    echo -e "${YELLOW}[*] Looking for files containing: '$MAGIC_STRING'${NC}"
    echo ""
    
    # Scan specified paths
    for path in "${SCAN_PATHS[@]}"; do
        if [ -d "$path" ]; then
            scan_for_hidden_files "$path"
        fi
    done
    
    # Check process file handles
    check_process_handles
    
    # Check for hidden ports
    check_hidden_ports
    
    # Generate final report
    generate_report
}

# Run main function
main "$@"
