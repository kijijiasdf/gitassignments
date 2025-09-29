#!/bin/bash

# LaunchAgent Setup Script for Keep-Alive
# Sets up the keep-alive script to run automatically at login

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEEP_ALIVE_SCRIPT="$SCRIPT_DIR/keep-alive-mac-strong.sh"
PLIST_TEMPLATE="$SCRIPT_DIR/com.user.keepalive.plist"
PLIST_DEST="$HOME/Library/LaunchAgents/com.user.keepalive.plist"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "🚀 Keep-Alive LaunchAgent Setup"
echo "==============================="
echo ""

# Check if files exist
if [ ! -f "$KEEP_ALIVE_SCRIPT" ]; then
    echo -e "${RED}Error: Keep-alive script not found at $KEEP_ALIVE_SCRIPT${NC}"
    exit 1
fi

if [ ! -f "$PLIST_TEMPLATE" ]; then
    echo -e "${RED}Error: LaunchAgent template not found at $PLIST_TEMPLATE${NC}"
    exit 1
fi

# Function to install LaunchAgent
install_launchagent() {
    echo -e "${YELLOW}Installing LaunchAgent for automatic startup...${NC}"
    
    # Create LaunchAgents directory if it doesn't exist
    mkdir -p "$HOME/Library/LaunchAgents"
    
    # Replace placeholders in the plist file
    local username=$(whoami)
    sed "s|SCRIPT_PATH_PLACEHOLDER|$KEEP_ALIVE_SCRIPT|g; s|USERNAME_PLACEHOLDER|$username|g" "$PLIST_TEMPLATE" > "$PLIST_DEST"
    
    # Make the script executable
    chmod +x "$KEEP_ALIVE_SCRIPT"
    
    # Load the LaunchAgent
    launchctl load "$PLIST_DEST"
    
    echo -e "${GREEN}✓ LaunchAgent installed and loaded${NC}"
    echo -e "${BLUE}The keep-alive script will now start automatically at login${NC}"
    echo -e "${BLUE}Location: $PLIST_DEST${NC}"
}

# Function to uninstall LaunchAgent
uninstall_launchagent() {
    echo -e "${YELLOW}Uninstalling LaunchAgent...${NC}"
    
    if [ -f "$PLIST_DEST" ]; then
        # Unload the LaunchAgent
        launchctl unload "$PLIST_DEST" 2>/dev/null || true
        
        # Remove the plist file
        rm -f "$PLIST_DEST"
        
        echo -e "${GREEN}✓ LaunchAgent uninstalled${NC}"
        echo -e "${BLUE}Keep-alive script will no longer start automatically${NC}"
    else
        echo -e "${YELLOW}LaunchAgent was not installed${NC}"
    fi
}

# Function to check status
check_status() {
    if [ -f "$PLIST_DEST" ]; then
        echo -e "${GREEN}✓ LaunchAgent is installed${NC}"
        echo -e "${BLUE}Location: $PLIST_DEST${NC}"
        
        # Check if it's loaded
        if launchctl list | grep -q "com.user.keepalive"; then
            echo -e "${GREEN}✓ LaunchAgent is currently loaded and running${NC}"
        else
            echo -e "${YELLOW}⚠ LaunchAgent is installed but not loaded${NC}"
            echo -e "${BLUE}Run: launchctl load $PLIST_DEST${NC}"
        fi
    else
        echo -e "${RED}✗ LaunchAgent is not installed${NC}"
    fi
}

# Function to start/stop manually
start_service() {
    if [ -f "$PLIST_DEST" ]; then
        echo -e "${YELLOW}Starting LaunchAgent...${NC}"
        launchctl load "$PLIST_DEST"
        echo -e "${GREEN}✓ LaunchAgent started${NC}"
    else
        echo -e "${RED}LaunchAgent not installed. Run: $0 install${NC}"
    fi
}

stop_service() {
    echo -e "${YELLOW}Stopping LaunchAgent...${NC}"
    launchctl unload "$PLIST_DEST" 2>/dev/null || true
    echo -e "${GREEN}✓ LaunchAgent stopped${NC}"
}

# Main menu
case "$1" in
    "install")
        install_launchagent
        ;;
    "uninstall")
        uninstall_launchagent
        ;;
    "status")
        check_status
        ;;
    "start")
        start_service
        ;;
    "stop")
        stop_service
        ;;
    "restart")
        stop_service
        sleep 1
        start_service
        ;;
    *)
        echo "Usage: $0 {install|uninstall|start|stop|restart|status}"
        echo ""
        echo "Commands:"
        echo "  install   - Install LaunchAgent for automatic startup"
        echo "  uninstall - Remove LaunchAgent"
        echo "  start     - Start the LaunchAgent service"
        echo "  stop      - Stop the LaunchAgent service"
        echo "  restart   - Restart the service"
        echo "  status    - Check installation and running status"
        echo ""
        echo "LaunchAgent will automatically start the keep-alive script at login."
        exit 1
        ;;
esac