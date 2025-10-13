#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Script to setup and manage test environment for BGO XDP/TC firewall and LVS.
# See README.md for instructions on how to use.
#
# Based on xdp-tutorial testenv.sh
# Author: BGO Project
# Date: July 15, 2025

set -o errexit
set -o nounset
umask 077

# Get script directory
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Source configuration
source "$SCRIPT_DIR/testenv_config.sh"

NEEDED_TOOLS="ethtool ip tc ping curl bpftool"
MAX_NAMELEN=15

# Global state variables
GENERATE_NEW=0
CLEANUP_FUNC=
STATEFILE=
CMD=
NS=
BGO_BIN="$PROJECT_ROOT/bin/bgo"
LEGACY_IP=0
USE_VLAN=0
RUN_ON_INNER=0
SETUP_LVS=0

# State variables that are written to and read from statefile
STATEVARS=(IP6_PREFIX IP4_PREFIX
           INSIDE_IP6 INSIDE_IP4 INSIDE_MAC
           OUTSIDE_IP6 OUTSIDE_IP4 OUTSIDE_MAC
           ENABLE_IPV4 ENABLE_VLAN)
IP6_PREFIX=
IP4_PREFIX=
INSIDE_IP6=
INSIDE_IP4=
INSIDE_MAC=
OUTSIDE_IP6=
OUTSIDE_IP4=
OUTSIDE_MAC=
ENABLE_IPV4=0
ENABLE_VLAN=0

die()
{
    echo "$1" >&2
    exit 1
}

check_prereq()
{
    local max_locked_mem=$(ulimit -l)

    for t in $NEEDED_TOOLS; do
        which "$t" > /dev/null || die "Missing required tools: $t"
    done

    if [ "$EUID" -ne "0" ]; then
        die "This script needs root permissions to run."
    fi

    [ -d "$STATEDIR" ] || mkdir -p "$STATEDIR" || die "Unable to create state dir $STATEDIR"

    if [ "$max_locked_mem" != "unlimited" ]; then
        ulimit -l unlimited || die "Unable to set ulimit"
    fi

    # Check if BGO binary exists
    if [ ! -x "$BGO_BIN" ]; then
        echo "Warning: BGO binary not found at $BGO_BIN"
        echo "Please run 'make' in $PROJECT_ROOT to build the project"
    fi
}

get_nsname()
{
    local GENERATE=${1:-0}

    if [ -z "$NS" ]; then
        [ -f "$STATEDIR/current" ] && NS=$(<"$STATEDIR/current")

        if [ "$GENERATE" -eq "1" ] && [ -z "$NS" -o "$GENERATE_NEW" -eq "1" ]; then
            NS=$(printf "%s-%04x" "$GENERATED_NAME_PREFIX" $RANDOM)
        fi
    fi

    if [ "${#NS}" -gt "$MAX_NAMELEN" ]; then
        die "Environment name '$NS' is too long (max $MAX_NAMELEN)"
    fi

    STATEFILE="$STATEDIR/${NS}.state"
}

ensure_nsname()
{
    [ -z "$NS" ] && die "No environment selected; use --name to select one or 'setup' to create one"
    [ -e "$STATEFILE" ] || die "Environment for $NS doesn't seem to exist"

    echo "$NS" > "$STATEDIR/current"
    read_statefile
}

get_num()
{
    local num=1
    if [ -f "$STATEDIR/highest_num" ]; then
        num=$(( 1 + $(< "$STATEDIR/highest_num" )))
    fi

    echo $num > "$STATEDIR/highest_num"
    printf "%x" $num
}

write_statefile()
{
    [ -z "$STATEFILE" ] && return 1
    echo > "$STATEFILE"
    for var in "${STATEVARS[@]}"; do
        echo "${var}='$(eval echo '$'$var)'" >> "$STATEFILE"
    done
}

read_statefile()
{
    local value
    for var in "${STATEVARS[@]}"; do
        value=$(source "$STATEFILE"; eval echo '$'$var)
        eval "$var=\"$value\""
    done
}

cleanup_setup()
{
    echo "Error during setup, removing partially-configured environment '$NS'" >&2
    set +o errexit
    ip netns del "$NS" 2>/dev/null
    ip link del dev "$NS" 2>/dev/null
    rm -f "$STATEFILE"
}

cleanup_teardown()
{
    echo "Warning: Errors during teardown, partial environment may be left" >&2
}

cleanup()
{
    [ -n "$CLEANUP_FUNC" ] && $CLEANUP_FUNC

    [ -d "$STATEDIR" ] || return 0

    local statefiles=("$STATEDIR"/*.state)
    if [ "${#statefiles[*]}" -eq 1 ] && [ ! -e "${statefiles[0]}" ]; then
        rm -f "${STATEDIR}/highest_num" "${STATEDIR}/current"
        rmdir "$STATEDIR"
    fi
}

iface_macaddr()
{
    local iface="$1"
    local ns="${2:-}"
    local output

    if [ -n "$ns" ]; then
        output=$(ip -br -n "$ns" link show dev "$iface")
    else
        output=$(ip -br link show dev "$iface")
    fi
    echo "$output" | awk '{print $3}'
}

set_sysctls()
{
    local iface="$1"
    local in_ns="${2:-}"
    local nscmd=

    [ -n "$in_ns" ] && nscmd="ip netns exec $in_ns"
    local sysctls=(accept_dad
                   accept_ra
                   mldv1_unsolicited_report_interval
                   mldv2_unsolicited_report_interval)

    for s in ${sysctls[*]}; do
        $nscmd sysctl -w net.ipv6.conf.$iface.${s}=0 >/dev/null
    done
}

wait_for_dev()
{
    local iface="$1"
    local in_ns="${2:-}"
    local retries=5
    local nscmd=

    [ -n "$in_ns" ] && nscmd="ip netns exec $in_ns"
    while [ "$retries" -gt "0" ]; do
        if ! $nscmd ip addr show dev $iface | grep -q tentative; then return 0; fi
        sleep 0.5
        retries=$((retries -1))
    done
}

setup()
{
    get_nsname 1

    echo "Setting up new BGO test environment '$NS'"

    [ -e "$STATEFILE" ] && die "Environment for '$NS' already exists"

    local NUM=$(get_num "$NS")
    local NUM_DEC=$((0x$NUM))
    # 确保NUM_DEC在有效范围内 (1-254)
    NUM_DEC=$(((NUM_DEC % 254) + 1))
    local PEERNAME="bgo-test-$NUM"
    [ -z "$IP6_PREFIX" ] && IP6_PREFIX="${IP6_SUBNET}:${NUM}::"
    # 为每个环境创建独立的第三个八位字节
    [ -z "$IP4_PREFIX" ] && IP4_PREFIX="${IP4_SUBNET}.$NUM_DEC"

    INSIDE_IP6="${IP6_PREFIX}2"
    INSIDE_IP4="${IP4_PREFIX}.2"
    OUTSIDE_IP6="${IP6_PREFIX}1"
    OUTSIDE_IP4="${IP4_PREFIX}.1"

    CLEANUP_FUNC=cleanup_setup

    # Mount BPF filesystem if not already mounted
    if ! mount | grep -q /sys/fs/bpf; then
        mount -t bpf bpf /sys/fs/bpf/
    fi

    # Create namespace and veth pair
    ip netns add "$NS"
    ip link add dev "$NS" type veth peer name veth0 netns "$NS"

    # Configure outside interface
    set_sysctls $NS
    ip link set dev "$NS" up
    ip addr add dev "$NS" "${OUTSIDE_IP6}/${IP6_PREFIX_SIZE}"
    ethtool -K "$NS" rxvlan off txvlan off

    # Prevent neighbour queries on the link
    INSIDE_MAC=$(iface_macaddr veth0 "$NS")
    ip neigh add "$INSIDE_IP6" lladdr "$INSIDE_MAC" dev "$NS" nud permanent

    # Configure inside interface (in namespace)
    set_sysctls veth0 "$NS"
    ip -n "$NS" link set dev lo up
    ip -n "$NS" link set dev veth0 up
    ip -n "$NS" addr add dev veth0 "${INSIDE_IP6}/${IP6_PREFIX_SIZE}"
    ip netns exec "$NS" ethtool -K veth0 rxvlan off txvlan off

    # Prevent neighbour queries on the link
    OUTSIDE_MAC=$(iface_macaddr "$NS")
    ip -n "$NS" neigh add "$OUTSIDE_IP6" lladdr "$OUTSIDE_MAC" dev veth0 nud permanent

    # Add route for whole test subnet
    ip -n "$NS" route add "${IP6_SUBNET}::/$IP6_FULL_PREFIX_SIZE" via "$OUTSIDE_IP6" dev veth0
    
    # Add default IPv6 route pointing to the outside peer
    ip -n "$NS" route add default via "$OUTSIDE_IP6" dev veth0

    # IPv4 configuration if requested
    if [ "$LEGACY_IP" -eq "1" ]; then
        ip addr add dev "$NS" "${OUTSIDE_IP4}/${IP4_PREFIX_SIZE}"
        ip -n "$NS" addr add dev veth0 "${INSIDE_IP4}/${IP4_PREFIX_SIZE}"
        ip neigh add "$INSIDE_IP4" lladdr "$INSIDE_MAC" dev "$NS" nud permanent
        ip -n "$NS" neigh add "$OUTSIDE_IP4" lladdr "$OUTSIDE_MAC" dev veth0 nud permanent
        ip -n "$NS" route add "${IP4_SUBNET}/${IP4_FULL_PREFIX_SIZE}" via "$OUTSIDE_IP4" dev veth0
        
        # Add default IPv4 route pointing to the outside peer
        ip -n "$NS" route add default via "$OUTSIDE_IP4" dev veth0
        ENABLE_IPV4=1
    else
        ENABLE_IPV4=0
    fi

    # VLAN configuration if requested
    if [ "$USE_VLAN" -eq "1" ]; then
        ENABLE_VLAN=1
        for vid in "${VLAN_IDS[@]}"; do
            local vlpx="$(get_vlan_prefix "$IP6_PREFIX" "$vid")"
            local inside_ip="${vlpx}2"
            local outside_ip="${vlpx}1"

            # Outside VLAN interface
            ip link add dev "${NS}.$vid" link "$NS" type vlan id "$vid"
            ip link set dev "${NS}.$vid" up
            ip addr add dev "${NS}.$vid" "${outside_ip}/${IP6_PREFIX_SIZE}"
            ip neigh add "$inside_ip" lladdr "$INSIDE_MAC" dev "${NS}.$vid" nud permanent
            set_sysctls "${NS}/$vid"

            # Inside VLAN interface
            ip -n "$NS" link add dev "veth0.$vid" link "veth0" type vlan id "$vid"
            ip -n "$NS" link set dev "veth0.$vid" up
            ip -n "$NS" addr add dev "veth0.$vid" "${inside_ip}/${IP6_PREFIX_SIZE}"
            ip -n "$NS" neigh add "$outside_ip" lladdr "$OUTSIDE_MAC" dev "veth0.$vid" nud permanent
            set_sysctls "veth0/$vid" "$NS"
        done
    else
        ENABLE_VLAN=0
    fi

    write_statefile

    CLEANUP_FUNC=

    echo -n "Setup environment '$NS' with peer ip ${INSIDE_IP6}"
    [ "$ENABLE_IPV4" -eq "1" ] && echo " and ${INSIDE_IP4}." || echo "."
    echo "Waiting for interface configuration to settle..."
    echo ""
    wait_for_dev "$NS" && wait_for_dev veth0 "$NS"

    # Test connectivity
    LEGACY_IP=0 USE_VLAN=0 run_ping -c 1

    echo "$NS" > "$STATEDIR/current"

    # Setup BGO firewall if binary exists
    if [ -x "$BGO_BIN" ]; then
        echo "Starting BGO firewall on interface $NS..."
        setup_bgo_firewall
    fi
}

get_vlan_prefix()
{
    local prefix="$1"
    local vid="$2"
    (IFS=:; set -- $prefix; printf "%s:%s:%s:%x::" "$1" "$2" "$3" $(($4 + $vid * 4096)))
}

setup_bgo_firewall()
{
    echo "Setting up BGO firewall and LVS for test environment..."
    
    # Start firewall daemon in background
    nohup "$BGO_BIN" firewall-server start --interface "$NS" --listen ":$BGO_API_PORT" > /tmp/bgo-firewall-$NS.log 2>&1 &
    local firewall_pid=$!
    echo "$firewall_pid" > "$STATEDIR/firewall-$NS.pid"
    
    # Wait a moment for the firewall to start
    sleep 2
    
    # Check if firewall started successfully
    if ! kill -0 "$firewall_pid" 2>/dev/null; then
        echo "Warning: BGO firewall failed to start"
        cat /tmp/bgo-firewall-$NS.log
        return 1
    fi
    
    echo "BGO firewall started with PID $firewall_pid"
    echo "API available at http://localhost:$BGO_API_PORT"
    echo "Logs at /tmp/bgo-firewall-$NS.log"
    
    # Setup basic firewall rules for testing
    echo "Adding basic firewall rules..."
    
    # Allow SSH from test network
    "$BGO_BIN" firewall-update --action add --type whitelist \
        --ip "${IP4_SUBNET}.0.0/${IP4_FULL_PREFIX_SIZE}" --port 22 --protocol tcp || true
    
    # Allow ICMP for ping tests
    "$BGO_BIN" firewall-update --action add --type whitelist \
        --ip "${IP4_SUBNET}.0.0/${IP4_FULL_PREFIX_SIZE}" --protocol icmp || true
    
    # Setup LVS if requested
    if [ "$SETUP_LVS" -eq "1" ]; then
        echo "Enabling LVS functionality..."
        "$BGO_BIN" firewall-lvs enable || true
    fi
}

teardown()
{
    get_nsname && ensure_nsname "$NS"

    echo "Tearing down environment '$NS'"

    CLEANUP_FUNC=cleanup_teardown

    # Stop BGO firewall if running
    if [ -f "$STATEDIR/firewall-$NS.pid" ]; then
        local firewall_pid=$(<"$STATEDIR/firewall-$NS.pid")
        if kill -0 "$firewall_pid" 2>/dev/null; then
            echo "Stopping BGO firewall (PID: $firewall_pid)..."
            kill "$firewall_pid" 2>/dev/null || true
            sleep 1
            kill -9 "$firewall_pid" 2>/dev/null || true
        fi
        rm -f "$STATEDIR/firewall-$NS.pid"
    fi

    # Clean up BPF maps
    echo "Cleaning up BPF maps..."
    "$BGO_BIN" firewall-server cleanup-maps --force || true

    # Remove network interfaces
    ip link del dev "$NS" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    
    # Clean up BPF pin directory
    [ -d "/sys/fs/bpf/firewall" ] && rm -rf "/sys/fs/bpf/firewall" || true
    
    # Remove log file
    rm -f "/tmp/bgo-firewall-$NS.log"
    
    rm -f "$STATEFILE"
    
    if [ -f "$STATEDIR/current" ]; then
        local CUR=$(<"$STATEDIR/current")
        [[ "$CUR" == "$NS" ]] && rm -f "$STATEDIR/current"
    fi

    CLEANUP_FUNC=
}

reset()
{
    teardown && setup
}

ns_exec()
{
    get_nsname && ensure_nsname "$NS"
    ip netns exec "$NS" env TESTENV_NAME="$NS" "$@"
}

enter()
{
    ns_exec "${SHELL:-bash}"
}

run_ping()
{
    local PING
    local IP

    get_nsname && ensure_nsname "$NS"

    echo "Running ping from inside test environment:"
    echo ""

    if [ "$LEGACY_IP" -eq "1" ]; then
        PING=$(which ping)
        IP="${OUTSIDE_IP4}"
        [ "$ENABLE_IPV4" -eq "1" ] || die "No legacy IP addresses configured in environment."
    else
        PING=$(which ping6 2>/dev/null || which ping)
        if [ "$USE_VLAN" -eq "0" ]; then
            IP="${OUTSIDE_IP6}"
        else
            [ "$ENABLE_VLAN" -eq "1" ] || die "No VLANs configured in environment."
            IP="$(get_vlan_prefix "$IP6_PREFIX" "${VLAN_IDS[0]}")1"
        fi
    fi

    ns_exec "$PING" "$IP" "$@"
}

run_tcpdump()
{
    get_nsname && ensure_nsname "$NS"

    if [ "$RUN_ON_INNER" -eq "1" ]; then
        ns_exec tcpdump -nei veth0 "$@"
    else
        tcpdump -nei "$NS" "$@"
    fi
}

run_curl()
{
    get_nsname && ensure_nsname "$NS"
    
    echo "Testing BGO firewall API:"
    echo ""
    
    # Test API connectivity
    if ! curl -s "http://localhost:$BGO_API_PORT/api/status" > /dev/null; then
        echo "Warning: BGO API not accessible at http://localhost:$BGO_API_PORT"
        return 1
    fi
    
    echo "BGO API is accessible at http://localhost:$BGO_API_PORT"
    echo ""
    
    # Show available endpoints
    echo "Available API endpoints:"
    echo "  GET  /api/status"
    echo "  GET  /api/stats"
    echo "  GET  /api/rules/whitelist"
    echo "  GET  /api/rules/blacklist"
    echo "  POST /api/rules/whitelist"
    echo "  POST /api/rules/blacklist"
    echo ""
    
    # Execute user command if provided
    if [ "$#" -gt 0 ]; then
        ns_exec curl "$@"
    fi
}

bgo_cmd()
{
    get_nsname && ensure_nsname "$NS"
    
    if [ ! -x "$BGO_BIN" ]; then
        die "BGO binary not found at $BGO_BIN"
    fi
    
    "$BGO_BIN" "$@"
}

status()
{
    get_nsname

    echo "Currently selected environment: ${NS:-None}"
    if [ -n "$NS" ] && [ -e "$STATEFILE" ]; then
        read_statefile
        echo -n "  Namespace:      "; ip netns | grep "^$NS" || echo "Not found"
        echo    "  Prefix:         ${IP6_PREFIX}/${IP6_PREFIX_SIZE}"
        [ "$ENABLE_IPV4" -eq "1" ] && echo    "  Legacy prefix:  ${IP4_PREFIX}.0/${IP4_PREFIX_SIZE}"
        echo -n "  Interface:      "; ip -br a show dev "$NS" 2>/dev/null | sed 's/\s\+/ /g' || echo "Not found"
        
        # Check BGO firewall status
        if [ -f "$STATEDIR/firewall-$NS.pid" ]; then
            local firewall_pid=$(<"$STATEDIR/firewall-$NS.pid")
            if kill -0 "$firewall_pid" 2>/dev/null; then
                echo "  BGO Firewall:   Running (PID: $firewall_pid, API: http://localhost:$BGO_API_PORT)"
            else
                echo "  BGO Firewall:   Stopped (stale PID file)"
            fi
        else
            echo "  BGO Firewall:   Not started"
        fi
    fi
    echo ""

    echo "All existing environments:"
    for f in "$STATEDIR"/*.state; do
        if [ ! -e "$f" ]; then
            echo "  No environments exist"
            break
        fi
        NAME=$(basename "$f" .state)
        echo "  $NAME"
    done
}

print_alias()
{
    local scriptname="$(readlink -e "$0")"
    local sudo=

    [ -t 1 ] && echo "Eval this with \`eval \$($0 alias)\` to create shell alias" >&2

    if [ "$EUID" -ne "0" ]; then
        sudo="sudo "
        echo "WARNING: Creating sudo alias; be careful, this script WILL execute arbitrary programs" >&2
    fi

    echo "" >&2
    echo "alias bgo-test='$sudo$scriptname'"
}

usage()
{
    local FULL=${1:-}

    echo "Usage: $0 [options] <command> [param]"
    echo ""
    echo "Commands:"
    echo "  setup                   Setup and initialise new BGO test environment"
    echo "  teardown                Tear down existing environment"
    echo "  reset                   Reset environment to original state"
    echo "  exec <command>          Exec <command> inside test environment"
    echo "  enter                   Execute shell inside test environment"
    echo "  ping                    Run ping inside test environment"
    echo "  tcpdump                 Run tcpdump on outer interface (or inner with --inner)"
    echo "  curl                    Test BGO API or run curl inside environment"
    echo "  bgo <args>              Run BGO command with environment context"
    echo "  alias                   Print shell alias for easy access to this script"
    echo "  status (or st)          Show status of test environment"
    echo ""

    if [ -z "$FULL" ] ; then
        echo "Use --help to see the list of options."
        exit 1
    fi

    echo "Options:"
    echo "  -h, --help              Show this usage text"
    echo ""
    echo "  -n, --name <n>          Set name of test environment. If not set, the last used"
    echo "                          name will be used, or a new one generated."
    echo ""
    echo "  -g, --gen-new           Generate a new test environment name even though an existing"
    echo "                          environment is selected as the current one."
    echo ""
    echo "      --legacy-ip         Enable legacy IP (IPv4) support."
    echo "                          For setup and reset commands this enables configuration of legacy"
    echo "                          IP addresses on the interface, for the ping command it switches to"
    echo "                          legacy ping."
    echo ""
    echo "      --vlan              Enable VLAN support."
    echo "                          When used with the setup and reset commands, these VLAN IDs will"
    echo "                          be configured: ${VLAN_IDS[*]}. The VLAN interfaces are named as"
    echo "                          <ifname>.<vlid>."
    echo "                          When used with the ping command, the pings will be sent on the"
    echo "                          first VLAN ID (${VLAN_IDS[0]})."
    echo ""
    echo "      --inner             Use with tcpdump command to run on inner interface."
    echo ""
    echo "      --lvs               Setup LVS functionality during environment creation."
    echo ""
    exit 1
}

OPTS="hn:g"
LONGOPTS="help,name:,gen-new,legacy-ip,vlan,inner,lvs"

# Special handling for commands that take their own arguments
SPECIAL_COMMANDS="bgo ping tcpdump curl exec"
COMMAND_FOUND=false
COMMAND_NAME=""
ARGS_BEFORE_COMMAND=()
ARGS_AFTER_COMMAND=()

# Find if any special command is used and separate arguments
for arg in "$@"; do
    if [[ " $SPECIAL_COMMANDS " =~ " $arg " ]]; then
        COMMAND_FOUND=true
        COMMAND_NAME="$arg"
        ARGS_BEFORE_COMMAND+=("$arg")
        break
    else
        ARGS_BEFORE_COMMAND+=("$arg")
    fi
done

# If we found a special command, collect remaining arguments
if [ "$COMMAND_FOUND" = "true" ]; then
    FOUND_COMMAND=false
    for arg in "$@"; do
        if [ "$arg" = "$COMMAND_NAME" ]; then
            FOUND_COMMAND=true
            continue
        elif [ "$FOUND_COMMAND" = "true" ]; then
            ARGS_AFTER_COMMAND+=("$arg")
        fi
    done
    
    OPTIONS=$(getopt -o "$OPTS" --long "$LONGOPTS" -- "${ARGS_BEFORE_COMMAND[@]}")
    [ "$?" -ne "0" ] && usage >&2 || true
    eval set -- "$OPTIONS"
    
    # Store command arguments for later use
    REMAINING_COMMAND_ARGS=("${ARGS_AFTER_COMMAND[@]}")
else
    OPTIONS=$(getopt -o "$OPTS" --long "$LONGOPTS" -- "$@")
    [ "$?" -ne "0" ] && usage >&2 || true
    eval set -- "$OPTIONS"
    REMAINING_COMMAND_ARGS=()
fi

while true; do
    arg="$1"
    shift

    case "$arg" in
        -h | --help)
            usage full >&2
            ;;
        -n | --name)
            NS="$1"
            shift
            ;;
        -g | --gen-new)
            GENERATE_NEW=1
            ;;
        --legacy-ip)
            LEGACY_IP=1
            ;;
        --vlan)
            USE_VLAN=1
            ;;
        --inner)
            RUN_ON_INNER=1
            ;;
        --lvs)
            SETUP_LVS=1
            ;;
        -- )
            break
            ;;
    esac
done

[ "$#" -eq 0 ] && usage >&2

case "$1" in
    st|sta|status)
        CMD=status
        ;;
    setup|teardown|reset|enter)
        CMD="$1"
        ;;
    "exec")
        CMD=ns_exec
        ;;
    ping|tcpdump|curl)
        CMD="run_$1"
        ;;
    bgo)
        CMD=bgo_cmd
        ;;
    "alias")
        print_alias
        exit 0
        ;;
    "help")
        usage full >&2
        ;;
    *)
        usage >&2
        ;;
esac

shift
trap cleanup EXIT
check_prereq

# Special handling for commands with their own arguments
if [ "$COMMAND_FOUND" = "true" ] && [ ${#REMAINING_COMMAND_ARGS[@]} -gt 0 ]; then
    $CMD "${REMAINING_COMMAND_ARGS[@]}"
else
    $CMD "$@"
fi
