#!/bin/bash

# XDP Firewall Rate Limiting Demo Script

set -e

echo "=== XDP Firewall Rate Limiting Demo ==="
echo ""

# Configuration
INTERFACE="enp0s8"
BIN="./bin/bgo"

echo "1. Checking if firewall server is running..."
if pgrep -f "bgo firewall-server" > /dev/null; then
    echo "   ✓ Firewall server is running"
else
    echo "   ✗ Firewall server is not running"
    echo "   Starting firewall server..."
    sudo $BIN firewall-server start --interface $INTERFACE > /tmp/firewall-server.log 2>&1 &
    sleep 2
    echo "   ✓ Firewall server started"
fi

echo ""
echo "2. Showing current rate limit configuration..."
sudo $BIN firewall-ratelimit --show-config || echo "   (No configuration yet - this is normal on first run)"

echo ""
echo "3. Enabling rate limiting (1000 pps, 1 MB/s)..."
sudo $BIN firewall-ratelimit --enable --pps 1000 --bps 1048576

echo ""
echo "4. Showing updated configuration..."
sudo $BIN firewall-ratelimit --show-config

echo ""
echo "5. Showing current statistics..."
sudo $BIN firewall-ratelimit --show-stats

echo ""
echo "=== Test Traffic Generation ==="
echo "You can generate test traffic with commands like:"
echo "  ping -f <target_ip>           # Flood ping (requires root)"
echo "  hping3 --flood <target_ip>    # TCP flood"
echo ""
echo "Monitor statistics with:"
echo "  watch -n 1 'sudo $BIN firewall-ratelimit --show-stats'"
echo ""

echo "=== Available Commands ==="
echo "Show config:        sudo $BIN firewall-ratelimit --show-config"
echo "Show stats:         sudo $BIN firewall-ratelimit --show-stats"
echo "Reset stats:        sudo $BIN firewall-ratelimit --reset-stats"
echo "Disable limiting:   sudo $BIN firewall-ratelimit --disable"
echo "Enable with limits: sudo $BIN firewall-ratelimit --enable --pps 10000 --bps 10485760"
echo ""

echo "=== Demo Complete ==="
