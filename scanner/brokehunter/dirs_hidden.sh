#!/bin/bash
TARGET_DIR="/"

find "$TARGET_DIR" -maxdepth 5 -type d 2>/dev/null | while read DIR_PATH; do
    STAT_LINKS=$(stat -c "%h" "$DIR_PATH" 2>/dev/null)

    LS_COUNT=$(ls -A1 "$DIR_PATH" 2>/dev/null | wc -l)
    VISIBLE_DIRS=$(ls -d */ "$DIR_PATH" 2>/dev/null | wc -l)
    
    EXPECTED_LINKS=$((VISIBLE_DIRS + 2))

    if [ "$STAT_LINKS" -gt "$EXPECTED_LINKS" ]; then
        echo -e "\n‼️ POTENTIAL HIDDEN DIRECTORIES FOUND!"
        echo -e "Directory: \033[1;31m$DIR_PATH\033[0m"
        echo "STAT Link Count (Actual FS): $STAT_LINKS"
        echo "Visible Subdirectories (LS Count): $VISIBLE_DIRS"
        echo "Expected Link Count: $EXPECTED_LINKS"
        echo "Discrepancy: $((STAT_LINKS - EXPECTED_LINKS)) hidden links/directories."
        echo "------------------------------------------------------------------------"
    fi

done
