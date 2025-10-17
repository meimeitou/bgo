package cmd

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
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
)

// firewallLvsCmd represents the firewall-lvs command
var firewallLvsCmd = &cobra.Command{
	Use:   "firewall-lvs",
	Short: "Manage TC-based LVS load balancer rules",
	Long: `Manage TC (Traffic Control) based LVS (Load Balancer Virtual Server) rules.

This command allows you to:
- Add, remove, and list DNAT rules
- Enable/disable LVS functionality
- Monitor connection tracking and statistics
- Debug LVS processing

Note: The TC programs must be loaded first by the firewall-server daemon.
The TC implementation provides full L4 load balancing with DNAT/SNAT support.`,
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

// statsLvsCmd represents the stats command
var statsLvsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show LVS statistics",
	Long:  `Show detailed LVS NAT processing statistics including DNAT/SNAT packet counts`,
	RunE:  runLvsStats,
}

// debugLvsCmd represents the debug command
var debugLvsCmd = &cobra.Command{
	Use:   "debug",
	Short: "Show LVS debug information",
	Long:  `Show detailed debug information from LVS processing including counters and events`,
	RunE:  runLvsDebug,
}

func init() {
	// Add subcommands
	firewallLvsCmd.AddCommand(addDnatCmd)
	firewallLvsCmd.AddCommand(removeDnatCmd)
	firewallLvsCmd.AddCommand(listDnatCmd)
	firewallLvsCmd.AddCommand(enableLvsCmd)
	firewallLvsCmd.AddCommand(disableLvsCmd)
	firewallLvsCmd.AddCommand(statusLvsCmd)
	firewallLvsCmd.AddCommand(cleanupLvsCmd)
	firewallLvsCmd.AddCommand(statsLvsCmd)
	firewallLvsCmd.AddCommand(debugLvsCmd)

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
	OriginalIP   uint32 // 4 bytes
	OriginalPort uint16 // 2 bytes
	_            uint16 // 2 bytes padding (对应 C 结构中的 _pad1)
	TargetIP     uint32 // 4 bytes
	TargetPort   uint16 // 2 bytes
	Protocol     uint8  // 1 byte
	Enabled      uint8  // 1 byte
	// 总共 16 字节，与 C 结构体大小匹配
}

// Connection tracking structure
type ConnTrack struct {
	ClientIP         uint32
	ClientPort       uint16
	_                uint16 // padding
	OriginalDestIP   uint32
	OriginalDestPort uint16
	_                uint16 // padding
	TargetIP         uint32
	TargetPort       uint16
	_                uint16 // padding
	Timestamp        uint64
}

// Debug info structure matching BPF side
type DebugInfo struct {
	Timestamp uint64
	SrcIP     uint32
	DstIP     uint32
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Stage     uint8
	RuleIndex uint8
	Result    uint8
}

// Debug counter names
var debugCounterNames = map[uint32]string{
	0: "总数据包数",
	1: "LVS已启用",
	2: "DNAT规则查找",
	3: "DNAT规则检查",
	4: "DNAT匹配成功",
	5: "SNAT规则查找",
	6: "SNAT匹配成功",
	7: "新连接创建",
	8: "连接复用",
}

// Debug stage names
var debugStageNames = map[uint8]string{
	0: "入口",
	1: "DNAT查找",
	2: "DNAT匹配",
	3: "SNAT查找",
	4: "SNAT匹配",
	5: "连接跟踪",
}

// Debug result names
var debugResultNames = map[uint8]string{
	0: "继续处理",
	1: "匹配成功",
	2: "匹配失败",
	3: "创建连接",
	4: "复用连接",
	5: "丢弃",
}

// Helper function to convert uint32 IP to string
func uint32ToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

// Helper function to format protocol
func formatProtocol(proto uint8) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("Proto-%d", proto)
	}
}

// Helper function to format debug info
func formatDebugInfo(info *DebugInfo) string {
	timestamp := time.Unix(0, int64(info.Timestamp))
	stage := debugStageNames[info.Stage]
	if stage == "" {
		stage = fmt.Sprintf("Stage-%d", info.Stage)
	}
	result := debugResultNames[info.Result]
	if result == "" {
		result = fmt.Sprintf("Result-%d", info.Result)
	}

	return fmt.Sprintf("[%s] %s:%d -> %s:%d (%s) [%s] 规则#%d -> %s",
		timestamp.Format("15:04:05.000"),
		uint32ToIP(info.SrcIP), info.SrcPort,
		uint32ToIP(info.DstIP), info.DstPort,
		formatProtocol(info.Protocol),
		stage, info.RuleIndex, result)
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
		if existingRule.OriginalIP == binary.LittleEndian.Uint32(vipAddr.To4()) &&
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
	// 注意：BPF 程序中从 iphdr 读取的 IP 地址在 x86 架构上是小端序
	// 所以我们在 Go 中也使用小端序存储
	rule := DnatRule{
		OriginalIP:   binary.LittleEndian.Uint32(vipAddr.To4()),
		OriginalPort: uint16(vport),
		TargetIP:     binary.LittleEndian.Uint32(ripAddr.To4()),
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
		if existingRule.OriginalIP == binary.LittleEndian.Uint32(vipAddr.To4()) &&
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

		// Convert IPs back to readable format (使用小端序)
		vipBytes := make([]byte, 4)
		ripBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(vipBytes, rule.OriginalIP)
		binary.LittleEndian.PutUint32(ripBytes, rule.TargetIP)

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

func runLvsStats(cmd *cobra.Command, args []string) error {
	// Load the pinned TC stats map
	m, err := ebpf.LoadPinnedMap(firewall.PinPath+"/tc_stats_map", &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("failed to load tc_stats_map: %v", err)
	}
	defer m.Close()

	// Get statistics - must match struct firewall_tc_stats in firewall_tc.c
	var stats struct {
		TotalPackets   uint64
		AllowedPackets uint64
		DeniedPackets  uint64
		IngressPackets uint64
		EgressPackets  uint64
	}

	err = m.Lookup(uint32(0), &stats)
	if err != nil {
		return fmt.Errorf("failed to get statistics: %v", err)
	}

	fmt.Printf("=== TC Firewall Statistics ===\n")
	fmt.Printf("Time: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("Total Packets:     %d\n", stats.TotalPackets)
	fmt.Printf("Allowed Packets:   %d\n", stats.AllowedPackets)
	fmt.Printf("Denied Packets:    %d\n", stats.DeniedPackets)
	fmt.Printf("Ingress Packets:   %d\n", stats.IngressPackets)
	fmt.Printf("Egress Packets:    %d\n", stats.EgressPackets)

	if stats.TotalPackets > 0 {
		fmt.Printf("\nAllow Rate:        %.2f%%\n", float64(stats.AllowedPackets)/float64(stats.TotalPackets)*100)
		fmt.Printf("Deny Rate:         %.2f%%\n", float64(stats.DeniedPackets)/float64(stats.TotalPackets)*100)
		fmt.Printf("Ingress Rate:      %.2f%%\n", float64(stats.IngressPackets)/float64(stats.TotalPackets)*100)
		fmt.Printf("Egress Rate:       %.2f%%\n", float64(stats.EgressPackets)/float64(stats.TotalPackets)*100)
	}

	fmt.Printf("\n=== LVS Statistics (use 'debug' command for detailed counters) ===\n")

	return nil
}

func runLvsDebug(cmd *cobra.Command, args []string) error {
	subCommand := "counters"
	if len(args) > 0 {
		subCommand = args[0]
	}

	switch subCommand {
	case "counters":
		return showDebugCounters()
	case "clear":
		return clearDebugCounters()
	case "events":
		return showDebugEvents()
	case "monitor":
		return monitorDebugCounters()
	default:
		fmt.Printf("使用方法:\n")
		fmt.Printf("  %s firewall-lvs debug [子命令]\n\n", cmd.Root().Name())
		fmt.Printf("可用子命令:\n")
		fmt.Printf("  counters    显示调试计数器\n")
		fmt.Printf("  clear       清空调试计数器\n")
		fmt.Printf("  events      显示调试事件 (实验性)\n")
		fmt.Printf("  monitor     实时监控计数器\n")
		fmt.Printf("\n示例:\n")
		fmt.Printf("  %s firewall-lvs debug counters\n", cmd.Root().Name())
		fmt.Printf("  %s firewall-lvs debug monitor\n", cmd.Root().Name())
		return nil
	}
}

func showDebugCounters() error {
	// Load debug counters map
	m, err := ebpf.LoadPinnedMap(firewall.PinPath+"/debug_counters", &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("failed to load debug_counters map: %v", err)
	}
	defer m.Close()

	fmt.Printf("=== LVS 调试计数器 ===\n")
	fmt.Printf("时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println()
	fmt.Printf("%-8s | %-14s | %s\n", "计数器ID", "名称", "数值")
	fmt.Printf("---------|----------------|----------\n")

	for i := uint32(0); i <= 8; i++ {
		var value uint64
		err := m.Lookup(i, &value)
		if err != nil {
			continue
		}

		name, exists := debugCounterNames[i]
		if !exists {
			name = "未知"
		}

		fmt.Printf("%-8d | %-14s | %d\n", i, name, value)
	}
	fmt.Println()

	return nil
}

func clearDebugCounters() error {
	// Load debug counters map
	m, err := ebpf.LoadPinnedMap(firewall.PinPath+"/debug_counters", &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("failed to load debug_counters map: %v", err)
	}
	defer m.Close()

	fmt.Println("清空调试计数器...")

	for i := uint32(0); i <= 8; i++ {
		var zero uint64 = 0
		err := m.Update(i, zero, ebpf.UpdateAny)
		if err != nil {
			fmt.Printf("警告: 无法清空计数器 %d: %v\n", i, err)
		}
	}

	fmt.Println("调试计数器已清空")
	return nil
}

func showDebugEvents() error {
	fmt.Println("=== LVS 调试事件 (Ring Buffer) ===")
	fmt.Println("按 Ctrl+C 停止事件监控")
	fmt.Println()

	// Load the debug ring buffer map
	m, err := ebpf.LoadPinnedMap(firewall.PinPath+"/debug_map", &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("failed to load debug_map: %v", err)
	}
	defer m.Close()

	// Create a ring buffer reader
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		return fmt.Errorf("failed to create ring buffer reader: %v", err)
	}
	defer rd.Close()

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	go func() {
		<-c
		fmt.Println("\n事件监控已停止")
		cancel()
	}()

	// Start reading events
	fmt.Println("等待调试事件...")
	eventCount := 0

	for {
		select {
		case <-ctx.Done():
			fmt.Printf("\n总共收到 %d 个调试事件\n", eventCount)
			return nil
		default:
			// Read the next record from the ring buffer
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return nil
				}
				continue // Skip errors and continue reading
			}

			// Parse the debug info
			if len(record.RawSample) < int(unsafe.Sizeof(DebugInfo{})) {
				continue // Skip malformed records
			}

			var info DebugInfo
			data := record.RawSample
			info.Timestamp = binary.LittleEndian.Uint64(data[0:8])
			info.SrcIP = binary.LittleEndian.Uint32(data[8:12])
			info.DstIP = binary.LittleEndian.Uint32(data[12:16])
			info.SrcPort = binary.LittleEndian.Uint16(data[16:18])
			info.DstPort = binary.LittleEndian.Uint16(data[18:20])
			info.Protocol = data[20]
			info.Stage = data[21]
			info.RuleIndex = data[22]
			info.Result = data[23]

			// Format and display the debug info
			fmt.Println(formatDebugInfo(&info))
			eventCount++
		}
	}
}

func monitorDebugCounters() error {
	fmt.Println("=== 实时监控 LVS 调试计数器 ===")
	fmt.Println("按 Ctrl+C 停止监控")
	fmt.Println()

	// 使用信号处理来优雅退出
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	go func() {
		<-c
		fmt.Println("\n监控已停止")
		os.Exit(0)
	}()

	for range ticker.C {
		// 清屏 (在支持的终端中)
		fmt.Print("\033[2J\033[H")

		err := showDebugCounters()
		if err != nil {
			return err
		}
	}

	return nil
}
