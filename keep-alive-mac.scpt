#!/usr/bin/osascript

-- macOS Keep-Alive Script (AppleScript version)
-- Prevents system from going to sleep by simulating key presses

-- Clear terminal and show startup message
do shell script "clear"
display notification "Starting Keep-Alive Script" with title "macOS Keep-Alive"

-- Log startup
log "macOS Keep-Alive Script started at " & (current date)

-- Function to simulate key press (compatible with all keyboard types)
on simulateKeyPress()
    tell application "System Events"
        -- Use Right Shift key (key code 60) - universally available
        key down 60
        delay 0.01
        key up 60
        delay 0.1
        -- Press again to maintain the double-press pattern
        key down 60
        delay 0.01
        key up 60
    end tell
end simulateKeyPress

-- Main loop
repeat
    try
        log "Simulating key press at " & (current date)
        
        -- Simulate the key press twice
        simulateKeyPress()
        
        log "Waiting 4 minutes before next activation..."
        
        -- Wait 240 seconds (4 minutes)
        delay 240
        
    on error errorMessage
        log "Error occurred: " & errorMessage
        delay 10 -- Wait 10 seconds before retrying
    end try
end repeat