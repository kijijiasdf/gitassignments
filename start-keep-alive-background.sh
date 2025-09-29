#!/bin/bash

# Background Keep-Alive Launcher Script
# Multiple methods to run keep-alive script in background

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEEP_ALIVE_SCRIPT="$SCRIPT_DIR/keep-alive-mac-strong.sh"
LOG_FILE="$HOME/keep-alive-background.log"
PID_FILE="$HOME/.keep-alive.pid"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "🔄 Keep-Alive Background Launcher"
echo "================================="
echo ""

# Check if script exists
if [ ! -f "$KEEP_ALIVE_SCRIPT" ]; then
    echo -e "${RED}Error: Keep-alive script not found at $KEEP_ALIVE_SCRIPT${NC}"
    exit 1
fi

# Make sure the script is executable
chmod +x "$KEEP_ALIVE_SCRIPT"

# Function to check if script is already running
check_running() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if ps -p $pid > /dev/null 2>&1; then
            return 0  # Running
        else
            rm -f "$PID_FILE"  # Clean up stale PID file
            return 1  # Not running
        fi
    fi
    return 1  # Not running
}

# Function to start in background
start_background() {
    if check_running; then
        echo -e "${YELLOW}Keep-alive script is already running (PID: $(cat $PID_FILE))${NC}"
        return
    fi
    
    echo -e "${GREEN}Starting keep-alive script in background...${NC}"
    
    # Start the script in background and capture PID
    nohup "$KEEP_ALIVE_SCRIPT" > "$LOG_FILE" 2>&1 &
    local pid=$!
    
    # Save PID for later management
    echo $pid > "$PID_FILE"
    
    # Give it a moment to start
    sleep 2
    
    if ps -p $pid > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Keep-alive script started successfully${NC}"
        echo -e "${BLUE}PID: $pid${NC}"
        echo -e "${BLUE}Log file: $LOG_FILE${NC}"
        echo -e "${BLUE}To stop: $0 stop${NC}"
    else
        echo -e "${RED}✗ Failed to start keep-alive script${NC}"
        rm -f "$PID_FILE"
    fi
}

# Function to stop background script
stop_background() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if ps -p $pid > /dev/null 2>&1; then
            echo -e "${YELLOW}Stopping keep-alive script (PID: $pid)...${NC}"
            kill $pid
            
            # Wait for graceful shutdown
            sleep 2
            
            # Force kill if still running
            if ps -p $pid > /dev/null 2>&1; then
                echo -e "${YELLOW}Force stopping...${NC}"
                kill -9 $pid
            fi
            
            echo -e "${GREEN}✓ Keep-alive script stopped${NC}"
        else
            echo -e "${YELLOW}Keep-alive script was not running${NC}"
        fi
        rm -f "$PID_FILE"
    else
        echo -e "${YELLOW}No PID file found. Script may not be running.${NC}"
    fi
}

# Function to show status
show_status() {
    if check_running; then
        local pid=$(cat "$PID_FILE")
        echo -e "${GREEN}✓ Keep-alive script is running${NC}"
        echo -e "${BLUE}PID: $pid${NC}"
        echo -e "${BLUE}Log file: $LOG_FILE${NC}"
        
        # Show recent log entries
        if [ -f "$LOG_FILE" ]; then
            echo ""
            echo -e "${YELLOW}Recent activity (last 5 lines):${NC}"
            tail -5 "$LOG_FILE"
        fi
    else
        echo -e "${RED}✗ Keep-alive script is not running${NC}"
    fi
}

# Function to show logs
show_logs() {
    if [ -f "$LOG_FILE" ]; then
        echo -e "${YELLOW}Keep-alive logs:${NC}"
        echo "=================="
        tail -20 "$LOG_FILE"
    else
        echo -e "${RED}No log file found${NC}"
    fi
}

# Main menu
case "$1" in
    "start")
        start_background
        ;;
    "stop")
        stop_background
        ;;
    "restart")
        stop_background
        sleep 1
        start_background
        ;;
    "status")
        show_status
        ;;
    "logs")
        show_logs
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        echo ""
        echo "Commands:"
        echo "  start   - Start keep-alive script in background"
        echo "  stop    - Stop background keep-alive script"
        echo "  restart - Restart the script"
        echo "  status  - Show current status"
        echo "  logs    - Show recent log entries"
        echo ""
        echo "Examples:"
        echo "  $0 start     # Start in background"
        echo "  $0 status    # Check if running"
        echo "  $0 stop      # Stop the script"
        exit 1
        ;;
esac