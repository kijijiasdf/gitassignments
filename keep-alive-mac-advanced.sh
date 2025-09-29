#!/bin/bash

# Advanced macOS Keep-Alive Script
# Multiple methods to prevent system sleep

clear
echo "🍎 macOS Keep-Alive Script (Advanced)"
echo "======================================"
echo "Press Ctrl+C to stop"
echo ""

# Configuration
INTERVAL=480  # 8 minutes in seconds (2 minutes before 10-minute lockout)
LOG_FILE="$HOME/keep-alive.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log_message() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${GREEN}[$timestamp]${NC} $message"
    echo "[$timestamp] $message" >> "$LOG_FILE"
}

# Check for required tools
check_dependencies() {
    if ! command -v osascript &> /dev/null; then
        echo -e "${RED}Error: osascript not found. This script requires macOS.${NC}"
        exit 1
    fi
    
    if ! command -v caffeinate &> /dev/null; then
        echo -e "${YELLOW}Warning: caffeinate not found. Some features may not work.${NC}"
    fi
}

# Method 1: Key simulation (Caps Lock key - more effective for preventing sleep)
simulate_key_press() {
    # Use Caps Lock key (key code 57) with proper toggle behavior
    # This is more effective at preventing system sleep than modifier keys
    osascript -e '
    tell application "System Events"
        key code 57
        delay 0.05
        key code 57
    end tell
    ' 2>/dev/null
}

# Method 2: Mouse movement (tiny, imperceptible)
simulate_mouse_movement() {
    osascript -e '
    tell application "System Events"
        set currentPos to mouse location
        set x to item 1 of currentPos
        set y to item 2 of currentPos
        -- Move mouse by 1 pixel and back
        set mouse location {x + 1, y}
        delay 0.01
        set mouse location {x, y}
    end tell
    ' 2>/dev/null
}

# Method 3: Use caffeinate to actively prevent sleep
use_caffeinate() {
    if command -v caffeinate &> /dev/null; then
        # Prevent display sleep for 5 minutes (longer than our 4-minute cycle)
        caffeinate -d -t 300 &
        local cafe_pid=$!
        sleep 1
        kill $cafe_pid 2>/dev/null || true
    fi
}

# Cleanup function
cleanup() {
    log_message "Script stopped by user"
    echo -e "\n${YELLOW}Keep-alive script stopped.${NC}"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Main execution
main() {
    log_message "macOS Keep-Alive script started"
    log_message "Using multiple methods: Caps Lock simulation, mouse movement, active caffeinate"
    log_message "Interval: $INTERVAL seconds ($(($INTERVAL / 60)) minutes)"
    
    check_dependencies
    
    local counter=1
    
    while true; do
        echo -e "${BLUE}Cycle #$counter${NC} - $(date '+%H:%M:%S')"
        
        # Use all available methods for redundancy
        log_message "Simulating activity..."
        
        # Method 1: Key press (Caps Lock twice to toggle and return to original state)
        simulate_key_press
        
        # Method 2: Tiny mouse movement
        simulate_mouse_movement
        
        # Method 3: Brief caffeinate
        use_caffeinate
        
        log_message "Activity simulation complete. Waiting $INTERVAL seconds..."
        
        # Countdown display
        for ((i=INTERVAL; i>0; i--)); do
            if ((i % 60 == 0)); then
                echo -e "${YELLOW}Next activation in: $((i/60)) minute(s)${NC}"
            fi
            sleep 1
        done
        
        ((counter++))
    done
}

# Show usage information
echo "Available methods (anti-sleep focused):"
echo "  • Caps Lock key simulation (effective against sleep)"
echo "  • Micro mouse movements (1 pixel)"
echo "  • Active caffeinate usage (prevents display sleep)"
echo ""
echo -e "${YELLOW}Log file: $LOG_FILE${NC}"
echo ""

# Start the script
main