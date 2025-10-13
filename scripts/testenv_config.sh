#!/bin/bash
# Configuration file for BGO test environment

# Default configuration values - can be overridden by environment variables

# Network configuration
IP6_SUBNET="${BGO_TEST_IP6_SUBNET:-fc00:dead:cafe}"
IP6_PREFIX_SIZE="${BGO_TEST_IP6_PREFIX_SIZE:-64}"
IP6_FULL_PREFIX_SIZE="${BGO_TEST_IP6_FULL_PREFIX_SIZE:-48}"

IP4_SUBNET="${BGO_TEST_IP4_SUBNET:-10.11}"
IP4_PREFIX_SIZE="${BGO_TEST_IP4_PREFIX_SIZE:-24}"
IP4_FULL_PREFIX_SIZE="${BGO_TEST_IP4_FULL_PREFIX_SIZE:-16}"

# VLAN configuration
VLAN_IDS=(10 20)

# Test environment naming
GENERATED_NAME_PREFIX="${BGO_TEST_NAME_PREFIX:-bgo-test}"

# State directory
STATEDIR="${BGO_TEST_STATEDIR:-/tmp/bgo-testenv}"

# BGO specific configuration
BGO_API_PORT="${BGO_TEST_API_PORT:-8080}"

# Default firewall rules for testing
DEFAULT_WHITELIST_RULES=(
    "127.0.0.0/8:0:any"      # localhost
    "10.0.0.0/8:22:tcp"      # SSH from private networks
    "172.16.0.0/12:22:tcp"   # SSH from private networks  
    "192.168.0.0/16:22:tcp"  # SSH from private networks
    ":0:icmp"                # Allow all ICMP for testing
)

DEFAULT_BLACKLIST_RULES=(
    # Add any default deny rules here
)

# LVS test configuration
LVS_VIP_PREFIX="${BGO_TEST_LVS_VIP_PREFIX:-192.168.100}"
LVS_BACKEND_PREFIX="${BGO_TEST_LVS_BACKEND_PREFIX:-192.168.200}"
