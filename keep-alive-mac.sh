#!/bin/bash

# macOS Keep-Alive Script
# Prevents system from going to sleep by simulating key presses

clear
echo "Starting macOS Keep-Alive Script"
echo "Press Ctrl+C to stop"
echo "Using Right Shift key simulation every 8 minutes..."
echo "(Optimized for 10-minute system lockout)"
echo "(Compatible with built-in and external keyboards)"
echo ""

# Check if we have the necessary tools
if ! command -v osascript &> /dev/null; then
    echo "Error: osascript not found. This script requires macOS."
    exit 1
fi

# Function to simulate key press (compatible with all keyboard types)
simulate_key_press() {
    # Use Right Shift key (key code 60) - universally available on all keyboards
    # We'll press and release it quickly to register activity without side effects
    osascript -e 'tell application "System Events"
        key down 60
        delay 0.01
        key up 60
    end tell'
}

# Main loop
while true; do
    echo "$(date): Simulating key press..."
    
    # Press Right Shift twice with a brief pause (similar to original script)
    simulate_key_press
    sleep 0.1
    simulate_key_press
    
    echo "Waiting 8 minutes before next activation (10-min lockout optimization)..."
    
    # Wait 480 seconds (8 minutes - optimal for 10-minute lockout)
    sleep 480
done