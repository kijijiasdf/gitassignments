#!/bin/bash

# Strong macOS Keep-Alive Script
# Uses the most effective methods to prevent system sleep and lock

clear
echo "🔒 Strong macOS Keep-Alive Script (10-min lockout optimized)"
echo "=========================================================="
echo "Configured for 10-minute system lockout - Activity every 8 minutes"
echo "Press Ctrl+C to stop"
echo ""

# Configuration
INTERVAL=480  # 8 minutes in seconds (2 minutes before 10-minute lockout)
LOG_FILE="$HOME/keep-alive-strong.log"

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

# Check for required tools and permissions
check_dependencies() {
    if ! command -v osascript &> /dev/null; then
        echo -e "${RED}Error: osascript not found. This script requires macOS.${NC}"
        exit 1
    fi
    
    # Test if we can control System Events
    if ! osascript -e 'tell application "System Events" to key code 57' 2>/dev/null; then
        echo -e "${RED}Error: Cannot control System Events. Please grant Accessibility permissions:${NC}"
        echo "1. Go to System Preferences → Security & Privacy → Privacy"
        echo "2. Select 'Accessibility' from the left panel"
        echo "3. Add Terminal and grant permissions"
        exit 1
    fi
}

# Method 1: Multiple key combinations to ensure activity registration
simulate_activity_keys() {
    osascript -e '
    tell application "System Events"
        -- Press Caps Lock twice (toggles on/off, returns to original state)
        key code 57
        delay 0.1
        key code 57
        
        delay 0.2
        
        -- Press and release Control key (safe modifier)
        key down 59
        delay 0.05
        key up 59
    end tell
    ' 2>/dev/null
}

# Method 2: Active mouse wiggle (more noticeable to system)
simulate_mouse_activity() {
    osascript -e '
    tell application "System Events"
        set currentPos to mouse location
        set x to item 1 of currentPos
        set y to item 2 of currentPos
        
        -- Create a small circle movement pattern
        set mouse location {x + 2, y}
        delay 0.05
        set mouse location {x + 2, y + 2}
        delay 0.05
        set mouse location {x, y + 2}
        delay 0.05
        set mouse location {x, y}
        delay 0.05
    end tell
    ' 2>/dev/null
}

# Method 3: Aggressive caffeinate usage
use_aggressive_caffeinate() {
    if command -v caffeinate &> /dev/null; then
        # Prevent system sleep, display sleep, and disk sleep for our interval + buffer
        local duration=$((INTERVAL + 60))
        caffeinate -dims -t $duration &
        local cafe_pid=$!
        
        # Let it run for a few seconds, then background it
        sleep 3
        
        log_message "Caffeinate active (PID: $cafe_pid) for $duration seconds"
        
        # Store PID for cleanup if needed
        echo $cafe_pid > /tmp/keep-alive-cafe.pid
    fi
}

# Method 4: Simulate app activity (open/close invisible window)
simulate_app_activity() {
    osascript -e '
    tell application "System Events"
        -- Simulate Command+Space (Spotlight) and immediately cancel
        key down 55  -- Command key
        key code 49  -- Space
        delay 0.05
        key up 55    -- Release Command
        delay 0.1
        key code 53  -- Escape to cancel Spotlight
    end tell
    ' 2>/dev/null
}

# Cleanup function
cleanup() {
    log_message "Cleaning up and stopping script..."
    
    # Kill any caffeinate processes we started
    if [ -f /tmp/keep-alive-cafe.pid ]; then
        local cafe_pid=$(cat /tmp/keep-alive-cafe.pid)
        kill $cafe_pid 2>/dev/null || true
        rm -f /tmp/keep-alive-cafe.pid
    fi
    
    # Kill any lingering caffeinate processes started by this script
    pkill -f "caffeinate.*dims" 2>/dev/null || true
    
    log_message "Script stopped by user"
    echo -e "\n${YELLOW}Strong keep-alive script stopped.${NC}"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM EXIT

# Main execution
main() {
    log_message "Strong macOS Keep-Alive script started (10-minute lockout optimization)"
    log_message "System lockout: 10 minutes | Activity interval: 8 minutes | Safety margin: 2 minutes"
    log_message "Interval: $INTERVAL seconds ($(($INTERVAL / 60)) minutes)"
    
    check_dependencies
    
    local counter=1
    
    while true; do
        echo -e "${BLUE}Activity Cycle #$counter${NC} - $(date '+%H:%M:%S')"
        
        log_message "Executing aggressive keep-alive sequence..."
        
        # Use all methods for maximum effectiveness
        simulate_activity_keys
        sleep 0.5
        
        simulate_mouse_activity
        sleep 0.5
        
        use_aggressive_caffeinate
        sleep 0.5
        
        simulate_app_activity
        
        log_message "Keep-alive sequence complete. System should remain unlocked."
        log_message "Waiting $INTERVAL seconds before next cycle..."
        
        # Enhanced countdown with lock-prevention awareness
        for ((i=INTERVAL; i>0; i--)); do
            if ((i % 60 == 0)); then
                local minutes=$((i/60))
                echo -e "${YELLOW}Next activity cycle in: $minutes minute(s) - Lock prevention active${NC}"
            elif ((i == 120)); then
                echo -e "${GREEN}✓ 2 minutes until next cycle - Well before 10-minute lockout${NC}"
            fi
            sleep 1
        done
        
        ((counter++))
    done
}

# Show enhanced information
echo -e "${GREEN}Enhanced methods being used:${NC}"
echo "  🔑 Multiple key combinations (Caps Lock + Control)"
echo "  🖱️  Active mouse movement patterns"
echo "  ☕ Aggressive caffeinate (system + display + disk)"
echo "  📱 Simulated app activity"
echo ""
echo -e "${GREEN}Timing (optimized for 10-min lockout):${NC}"
echo "  ⏱️  Every $INTERVAL seconds ($(($INTERVAL / 60)) minutes)"
echo "  🔒 2-minute safety margin before 10-minute lockout"
echo "  🔄 Ensures system never reaches lock threshold"
echo ""
echo -e "${YELLOW}Log file: $LOG_FILE${NC}"
echo -e "${YELLOW}Permissions: Accessibility must be granted to Terminal${NC}"
echo ""

# Start the script
main