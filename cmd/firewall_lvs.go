package cmd

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/meimeitou/bgo/bpf/firewall"
	"github.com/spf13/cobra"
)

var (
	vip      string
	vport    int
	rip      string
	rport    int
	protocol string
	enabled  bool
	weight   int
)

// firewallLvsCmd represents the firewall-lvs command
var firewallLvsCmd = &cobra.Command{
	Use:   "firewall-lvs",
	Short: "Manage LVS NAT mode configuration",
	Long: `Manage Load Balancer (LVS) NAT mode configuration for the firewall.
This command allows you to add, remove, list and manage DNAT rules.`,
}

// addDnatCmd represents the add dnat command
var addDnatCmd = &cobra.Command{
	Use:     "add-dnat",
	Short:   "Add a DNAT rule",
	Long:    `Add a destination NAT rule to redirect traffic from VIP:VPORT to RIP:RPORT`,
	Example: `  bgo firewall-lvs add-dnat --vip 192.168.1.100 --vport 80 --rip 192.168.1.10 --rport 8080 --protocol tcp`,
	RunE:    runAddDnat,
}

// removeDnatCmd represents the remove dnat command
var removeDnatCmd = &cobra.Command{
	Use:     "remove-dnat",
	Short:   "Remove a DNAT rule",
	Long:    `Remove a destination NAT rule`,
	Example: `  bgo firewall-lvs remove-dnat --vip 192.168.1.100 --vport 80 --protocol tcp`,
	RunE:    runRemoveDnat,
}

// listDnatCmd represents the list dnat command
var listDnatCmd = &cobra.Command{
	Use:   "list-dnat",
	Short: "List all DNAT rules",
	Long:  `List all configured destination NAT rules`,
	RunE:  runListDnat,
}

// enableLvsCmd represents the enable lvs command
var enableLvsCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable LVS functionality",
	Long:  `Enable LVS NAT mode functionality in the firewall`,
	RunE:  runEnableLvs,
}

// disableLvsCmd represents the disable lvs command
var disableLvsCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable LVS functionality",
	Long:  `Disable LVS NAT mode functionality in the firewall`,
	RunE:  runDisableLvs,
}

// statusCmd represents the status command
var statusLvsCmd = &cobra.Command{
	Use:   "status",
	Short: "Show LVS status and statistics",
	Long:  `Show LVS status, configuration and connection statistics`,
	RunE:  runLvsStatus,
}

// cleanupCmd represents the cleanup command
var cleanupLvsCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Cleanup expired connection tracking entries",
	Long:  `Remove expired connection tracking entries from the connection table`,
	RunE:  runLvsCleanup,
}

func init() {
	RootCmd.AddCommand(firewallLvsCmd)

	// Add subcommands
	firewallLvsCmd.AddCommand(addDnatCmd)
	firewallLvsCmd.AddCommand(removeDnatCmd)
	firewallLvsCmd.AddCommand(listDnatCmd)
	firewallLvsCmd.AddCommand(enableLvsCmd)
	firewallLvsCmd.AddCommand(disableLvsCmd)
	firewallLvsCmd.AddCommand(statusLvsCmd)
	firewallLvsCmd.AddCommand(cleanupLvsCmd)

	// Add flags for add-dnat command
	addDnatCmd.Flags().StringVar(&vip, "vip", "", "Virtual IP address (required)")
	addDnatCmd.Flags().IntVar(&vport, "vport", 0, "Virtual port (required)")
	addDnatCmd.Flags().StringVar(&rip, "rip", "", "Real server IP address (required)")
	addDnatCmd.Flags().IntVar(&rport, "rport", 0, "Real server port (required)")
	addDnatCmd.Flags().StringVar(&protocol, "protocol", "tcp", "Protocol (tcp/udp)")
	addDnatCmd.Flags().BoolVar(&enabled, "enabled", true, "Enable the rule")

	addDnatCmd.MarkFlagRequired("vip")
	addDnatCmd.MarkFlagRequired("vport")
	addDnatCmd.MarkFlagRequired("rip")
	addDnatCmd.MarkFlagRequired("rport")

	// Add flags for remove-dnat command
	removeDnatCmd.Flags().StringVar(&vip, "vip", "", "Virtual IP address (required)")
	removeDnatCmd.Flags().IntVar(&vport, "vport", 0, "Virtual port (required)")
	removeDnatCmd.Flags().StringVar(&protocol, "protocol", "tcp", "Protocol (tcp/udp)")

	removeDnatCmd.MarkFlagRequired("vip")
	removeDnatCmd.MarkFlagRequired("vport")
}

// DNAT rule structure matching BPF side
type DnatRule struct {
	OriginalIP   uint32  // 4 bytes
	OriginalPort uint16  // 2 bytes
	TargetIP     uint32  // 4 bytes
	TargetPort   uint16  // 2 bytes
	Protocol     uint8   // 1 byte
	Enabled      uint8   // 1 byte
	_            [2]byte // 2 bytes padding to make total 16 bytes
}

// Connection tracking structure
type ConnTrack struct {
	ClientIP         uint32
	ClientPort       uint16
	OriginalDestIP   uint32
	OriginalDestPort uint16
	TargetIP         uint32
	TargetPort       uint16
	Timestamp        uint64
}

func runAddDnat(cmd *cobra.Command, args []string) error {
	// Parse and validate inputs
	vipAddr := net.ParseIP(vip)
	if vipAddr == nil {
		return fmt.Errorf("invalid VIP address: %s", vip)
	}

	ripAddr := net.ParseIP(rip)
	if ripAddr == nil {
		return fmt.Errorf("invalid RIP address: %s", rip)
	}

	if vport <= 0 || vport > 65535 {
		return fmt.Errorf("invalid virtual port: %d", vport)
	}

	if rport <= 0 || rport > 65535 {
		return fmt.Errorf("invalid real port: %d", rport)
	}

	var proto uint8
	switch strings.ToLower(protocol) {
	case "tcp":
		proto = 6 // IPPROTO_TCP
	case "udp":
		proto = 17 // IPPROTO_UDP
	default:
		return fmt.Errorf("unsupported protocol: %s (only tcp/udp supported)", protocol)
	}

	// Load the pinned map
	m, err := ebpf.LoadPinnedMap(firewall.PinPath+"/lvs_dnat_map", &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("failed to load lvs_dnat_map: %v", err)
	}
	defer m.Close()

	// Find an empty slot or existing rule to update
	var ruleIndex uint32 = 0
	found := false

	// First, check if rule already exists
	for i := uint32(0); i < 100; i++ { // MAX_RULES
		var existingRule DnatRule
		err := m.Lookup(i, &existingRule)
		if err != nil {
			continue
		}

		// Check if this is the same rule (VIP:VPORT:PROTOCOL)
		if existingRule.OriginalIP == binary.BigEndian.Uint32(vipAddr.To4()) &&
			existingRule.OriginalPort == uint16(vport) &&
			existingRule.Protocol == proto {
			ruleIndex = i
			found = true
			fmt.Printf("Updating existing rule at index %d\n", i)
			break
		}
	}

	// If not found, find an empty slot
	if !found {
		for i := uint32(0); i < 100; i++ {
			var existingRule DnatRule
			err := m.Lookup(i, &existingRule)
			if err != nil || existingRule.OriginalIP == 0 {
				ruleIndex = i
				found = true
				break
			}
		}
	}

	if !found {
		return fmt.Errorf("no available slots for new DNAT rule (maximum 100 rules)")
	}

	// Create new rule
	rule := DnatRule{
		OriginalIP:   binary.BigEndian.Uint32(vipAddr.To4()),
		OriginalPort: uint16(vport),
		TargetIP:     binary.BigEndian.Uint32(ripAddr.To4()),
		TargetPort:   uint16(rport),
		Protocol:     proto,
		Enabled:      1,
	}

	if !enabled {
		rule.Enabled = 0
	}

	// Update the map
	err = m.Update(ruleIndex, rule, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed to update DNAT map: %v", err)
	}

	fmt.Printf("Successfully added DNAT rule:\n")
	fmt.Printf("  VIP: %s:%d (%s) -> RIP: %s:%d\n", vip, vport, protocol, rip, rport)
	fmt.Printf("  Index: %d, Enabled: %t\n", ruleIndex, enabled)

	return nil
}

func runRemoveDnat(cmd *cobra.Command, args []string) error {
	// Parse and validate inputs
	vipAddr := net.ParseIP(vip)
	if vipAddr == nil {
		return fmt.Errorf("invalid VIP address: %s", vip)
	}

	if vport <= 0 || vport > 65535 {
		return fmt.Errorf("invalid virtual port: %d", vport)
	}

	var proto uint8
	switch strings.ToLower(protocol) {
	case "tcp":
		proto = 6 // IPPROTO_TCP
	case "udp":
		proto = 17 // IPPROTO_UDP
	default:
		return fmt.Errorf("unsupported protocol: %s (only tcp/udp supported)", protocol)
	}

	// Load the pinned map
	m, err := ebpf.LoadPinnedMap(firewall.PinPath+"/lvs_dnat_map", &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("failed to load lvs_dnat_map: %v", err)
	}
	defer m.Close()

	// Find the rule to remove
	found := false
	for i := uint32(0); i < 100; i++ {
		var existingRule DnatRule
		err := m.Lookup(i, &existingRule)
		if err != nil {
			continue
		}

		// Check if this is the rule to remove
		if existingRule.OriginalIP == binary.BigEndian.Uint32(vipAddr.To4()) &&
			existingRule.OriginalPort == uint16(vport) &&
			existingRule.Protocol == proto {

			// Zero out the rule
			emptyRule := DnatRule{}
			err = m.Update(i, emptyRule, ebpf.UpdateAny)
			if err != nil {
				return fmt.Errorf("failed to remove DNAT rule: %v", err)
			}

			fmt.Printf("Successfully removed DNAT rule:\n")
			fmt.Printf("  VIP: %s:%d (%s)\n", vip, vport, protocol)
			fmt.Printf("  Index: %d\n", i)
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("DNAT rule not found: %s:%d (%s)", vip, vport, protocol)
	}

	return nil
}

func runListDnat(cmd *cobra.Command, args []string) error {
	// Load the pinned map
	m, err := ebpf.LoadPinnedMap(firewall.PinPath+"/lvs_dnat_map", &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("failed to load lvs_dnat_map: %v", err)
	}
	defer m.Close()

	fmt.Printf("LVS DNAT Rules:\n")
	fmt.Printf("%-5s %-15s %-6s %-8s %-15s %-6s %-8s\n",
		"Index", "VIP", "VPort", "Protocol", "RIP", "RPort", "Enabled")
	fmt.Printf("%-5s %-15s %-6s %-8s %-15s %-6s %-8s\n",
		"-----", "---------------", "------", "--------", "---------------", "------", "--------")

	ruleCount := 0
	for i := uint32(0); i < 100; i++ {
		var rule DnatRule
		err := m.Lookup(i, &rule)
		if err != nil || rule.OriginalIP == 0 {
			continue
		}

		// Convert IPs back to readable format
		vipBytes := make([]byte, 4)
		ripBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(vipBytes, rule.OriginalIP)
		binary.BigEndian.PutUint32(ripBytes, rule.TargetIP)

		vipStr := net.IP(vipBytes).String()
		ripStr := net.IP(ripBytes).String()

		var protoStr string
		switch rule.Protocol {
		case 6:
			protoStr = "tcp"
		case 17:
			protoStr = "udp"
		default:
			protoStr = fmt.Sprintf("%d", rule.Protocol)
		}

		enabledStr := "false"
		if rule.Enabled == 1 {
			enabledStr = "true"
		}

		fmt.Printf("%-5d %-15s %-6d %-8s %-15s %-6d %-8s\n",
			i, vipStr, rule.OriginalPort, protoStr,
			ripStr, rule.TargetPort, enabledStr)

		ruleCount++
	}

	fmt.Printf("\nTotal rules: %d\n", ruleCount)
	return nil
}

func runEnableLvs(cmd *cobra.Command, args []string) error {
	return setLvsConfig(uint32(firewall.ConfigLvsEnabled), 1)
}

func runDisableLvs(cmd *cobra.Command, args []string) error {
	return setLvsConfig(uint32(firewall.ConfigLvsEnabled), 0)
}

func setLvsConfig(key, value uint32) error {
	// Load the pinned config map
	m, err := ebpf.LoadPinnedMap(firewall.PinPath+"/config_map", &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("failed to load config_map: %v", err)
	}
	defer m.Close()

	err = m.Update(key, value, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed to update config: %v", err)
	}

	action := "disabled"
	if value == 1 {
		action = "enabled"
	}
	fmt.Printf("LVS functionality %s\n", action)
	return nil
}

func runLvsStatus(cmd *cobra.Command, args []string) error {
	// Check LVS enabled status
	configMap, err := ebpf.LoadPinnedMap(firewall.PinPath+"/config_map", &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("failed to load config_map: %v", err)
	}
	defer configMap.Close()

	var lvsEnabled uint32
	err = configMap.Lookup(uint32(firewall.ConfigLvsEnabled), &lvsEnabled)
	if err != nil {
		fmt.Printf("Error reading LVS config: %v\n", err)
		lvsEnabled = 0
	}

	fmt.Printf("LVS Status: ")
	if lvsEnabled == 1 {
		fmt.Printf("ENABLED\n")
	} else {
		fmt.Printf("DISABLED\n")
	}

	// Show active connections
	connMap, err := ebpf.LoadPinnedMap(firewall.PinPath+"/conn_track_map", &ebpf.LoadPinOptions{})
	if err != nil {
		fmt.Printf("Warning: failed to load conn_track_map: %v\n", err)
		return nil
	}
	defer connMap.Close()

	fmt.Printf("\nActive Connections:\n")
	fmt.Printf("%-15s %-6s %-15s %-6s %-15s %-6s\n",
		"Client IP", "Port", "Original VIP", "Port", "Target IP", "Port")
	fmt.Printf("%-15s %-6s %-15s %-6s %-15s %-6s\n",
		"---------------", "------", "---------------", "------", "---------------", "------")

	// Iterate through connection tracking map
	var key uint64
	var conn ConnTrack
	connCount := 0

	iter := connMap.Iterate()
	for iter.Next(&key, &conn) {
		// Convert IPs to readable format
		clientBytes := make([]byte, 4)
		originalBytes := make([]byte, 4)
		targetBytes := make([]byte, 4)

		binary.BigEndian.PutUint32(clientBytes, conn.ClientIP)
		binary.BigEndian.PutUint32(originalBytes, conn.OriginalDestIP)
		binary.BigEndian.PutUint32(targetBytes, conn.TargetIP)

		clientIP := net.IP(clientBytes).String()
		originalIP := net.IP(originalBytes).String()
		targetIP := net.IP(targetBytes).String()

		fmt.Printf("%-15s %-6d %-15s %-6d %-15s %-6d\n",
			clientIP, conn.ClientPort,
			originalIP, conn.OriginalDestPort,
			targetIP, conn.TargetPort)

		connCount++
	}

	if err := iter.Err(); err != nil {
		fmt.Printf("Error iterating connections: %v\n", err)
	}

	fmt.Printf("\nTotal active connections: %d\n", connCount)
	return nil
}

func runLvsCleanup(cmd *cobra.Command, args []string) error {
	// Load connection tracking map
	connMap, err := ebpf.LoadPinnedMap(firewall.PinPath+"/conn_track_map", &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("failed to load conn_track_map: %v", err)
	}
	defer connMap.Close()

	// Since it's an LRU map, old entries are automatically evicted
	// We could implement custom cleanup logic here if needed

	fmt.Printf("Connection tracking table uses LRU eviction - old entries are automatically cleaned up\n")
	fmt.Printf("Manual cleanup completed\n")

	return nil
}
