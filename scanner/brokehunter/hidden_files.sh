#!/bin/bash

MAX_DEPTH=5
TARGET_DIR="/"
EXCLUDE_DIRS="/proc /sys /dev /run /tmp /var/run /var/tmp"
SUSPICIOUS_DIRS_FILE=$(mktemp) 
SEARCH_COMMANDS="mkdir|mv|cp|touch|wget|curl|tar|ln|rm"


EXCLUDE_FIND=""
for dir in $EXCLUDE_DIRS; do
    EXCLUDE_FIND+=" -path $dir -prune -o"
done

find "$TARGET_DIR" $EXCLUDE_FIND -type d -maxdepth "$MAX_DEPTH" 2>/dev/null | while read DIR_PATH; do
    
    STAT_LINKS=$(stat -c "%h" "$DIR_PATH" 2>/dev/null)
    if [ -z "$STAT_LINKS" ]; then continue; fi

    VISIBLE_SUBDIRS=$(ls -AFL "$DIR_PATH" 2>/dev/null | grep -c '/')
    EXPECTED_LINKS=$((VISIBLE_SUBDIRS + 2))

    if [ "$STAT_LINKS" -gt "$EXPECTED_LINKS" ]; then
        echo "$DIR_PATH" >> "$SUSPICIOUS_DIRS_FILE"
        echo -e "\033[1;31m[FLAGGED]\033[0m Discrepancy found in: $DIR_PATH"
    fi
done



if [ ! -s "$SUSPICIOUS_DIRS_FILE" ]; then
    echo "No suspicious directories were found to search history against."
else
    find /home /root -name ".*_history" 2>/dev/null | while read HISTORY_FILE; do
        USERNAME=$(echo "$HISTORY_FILE" | awk -F'/' '{print $3}')
        
        while read SUSPICIOUS_PATH; do
            grep -E "($SEARCH_COMMANDS).+($SUSPICIOUS_PATH)" "$HISTORY_FILE" 2>/dev/null | while read MATCHED_COMMAND; do
                echo -e "\n\033[1;31m[HISTORY MATCH]\033[0m"
                echo -e "  User: \033[1;33m$USERNAME\033[0m"
                echo -e "  Suspicious Dir: \033[1;36m$SUSPICIOUS_PATH\033[0m"
                echo -e "  Command: $MATCHED_COMMAND"
            done
        done < "$SUSPICIOUS_DIRS_FILE"
    done
fi


rm "$SUSPICIOUS_DIRS_FILE"
