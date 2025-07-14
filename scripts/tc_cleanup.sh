#!/bin/bash

# TC Cleanup Utility for BGO Firewall
# This script helps diagnose and clean up TC firewall filters

INTERFACE="${1:-eth0}"

echo "TC Firewall Cleanup Utility"
echo "Interface: $INTERFACE"
echo "=========================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root to manage TC filters"
    exit 1
fi

echo "Current TC configuration:"
echo "-------------------------"

echo "Qdiscs:"
tc qdisc show dev $INTERFACE

echo ""
echo "Ingress filters:"
tc filter show dev $INTERFACE ingress

echo ""
echo "Egress filters:"
tc filter show dev $INTERFACE egress

echo ""
echo "Looking for BGO firewall filters..."

# Check for BGO firewall filters
INGRESS_FILTERS=$(tc filter show dev $INTERFACE ingress | grep "tc_ingress_firewall" || true)
EGRESS_FILTERS=$(tc filter show dev $INTERFACE egress | grep "tc_egress_firewall" || true)

if [ -n "$INGRESS_FILTERS" ]; then
    echo "Found BGO ingress filters:"
    echo "$INGRESS_FILTERS"
else
    echo "No BGO ingress filters found"
fi

if [ -n "$EGRESS_FILTERS" ]; then
    echo "Found BGO egress filters:"
    echo "$EGRESS_FILTERS"
else
    echo "No BGO egress filters found"
fi

echo ""
echo "Manual cleanup commands (if needed):"
echo "======================================"

if [ -n "$INGRESS_FILTERS" ] || [ -n "$EGRESS_FILTERS" ]; then
    echo "# Remove specific BGO filters:"
    
    if [ -n "$INGRESS_FILTERS" ]; then
        # Extract handle numbers for ingress filters
        INGRESS_HANDLES=$(echo "$INGRESS_FILTERS" | grep -o 'handle [0-9]*' | awk '{print $2}')
        for handle in $INGRESS_HANDLES; do
            echo "tc filter del dev $INTERFACE ingress handle $handle"
        done
    fi
    
    if [ -n "$EGRESS_FILTERS" ]; then
        # Extract handle numbers for egress filters
        EGRESS_HANDLES=$(echo "$EGRESS_FILTERS" | grep -o 'handle [0-9]*' | awk '{print $2}')
        for handle in $EGRESS_HANDLES; do
            echo "tc filter del dev $INTERFACE egress handle $handle"
        done
    fi
    
    echo ""
    echo "# Or remove all filters (nuclear option):"
    echo "tc filter del dev $INTERFACE ingress"
    echo "tc filter del dev $INTERFACE egress"
    echo ""
    echo "# Remove clsact qdisc (removes all filters):"
    echo "tc qdisc del dev $INTERFACE clsact"
else
    echo "No BGO firewall filters found - cleanup not needed"
fi

# Offer to perform automatic cleanup
if [ -n "$INGRESS_FILTERS" ] || [ -n "$EGRESS_FILTERS" ]; then
    echo ""
    read -p "Perform automatic cleanup? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Performing automatic cleanup..."
        
        # Remove BGO firewall filters specifically
        if [ -n "$INGRESS_FILTERS" ]; then
            echo "Removing ingress filters..."
            INGRESS_HANDLES=$(echo "$INGRESS_FILTERS" | grep -o 'handle [0-9]*' | awk '{print $2}')
            for handle in $INGRESS_HANDLES; do
                echo "  Removing ingress filter handle $handle..."
                tc filter del dev $INTERFACE ingress handle $handle || echo "    Failed to remove handle $handle"
            done
        fi
        
        if [ -n "$EGRESS_FILTERS" ]; then
            echo "Removing egress filters..."
            EGRESS_HANDLES=$(echo "$EGRESS_FILTERS" | grep -o 'handle [0-9]*' | awk '{print $2}')
            for handle in $EGRESS_HANDLES; do
                echo "  Removing egress filter handle $handle..."
                tc filter del dev $INTERFACE egress handle $handle || echo "    Failed to remove handle $handle"
            done
        fi
        
        echo "Cleanup completed!"
        
        echo ""
        echo "Post-cleanup status:"
        echo "-------------------"
        tc filter show dev $INTERFACE ingress | grep "tc_ingress_firewall" && echo "WARNING: Some ingress filters still present" || echo "All ingress filters cleaned up"
        tc filter show dev $INTERFACE egress | grep "tc_egress_firewall" && echo "WARNING: Some egress filters still present" || echo "All egress filters cleaned up"
    fi
fi
