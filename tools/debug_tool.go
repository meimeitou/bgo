package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
)

// 调试计数器名称
var counterNames = map[uint32]string{
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

// 调试信息结构
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

// 协议名称
func getProtocolName(proto uint8) string {
	switch proto {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("协议%d", proto)
	}
}

// 阶段名称
func getStageName(stage uint8) string {
	switch stage {
	case 0:
		return "LVS入口"
	case 1:
		return "DNAT查找"
	case 2:
		return "DNAT匹配"
	case 3:
		return "SNAT查找"
	case 4:
		return "SNAT匹配"
	case 99:
		return "LVS结果"
	default:
		return fmt.Sprintf("阶段%d", stage)
	}
}

// IP地址转换
func uint32ToIP(ip uint32) string {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24)).String()
}

// 显示调试计数器
func showDebugCounters() error {
	mapPath := "/sys/fs/bpf/firewall/debug_counters"

	m, err := ebpf.LoadPinnedMap(mapPath, &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("无法加载调试计数器 map: %v", err)
	}
	defer m.Close()

	fmt.Println("=== XDP LVS 调试计数器 ===")
	fmt.Printf("时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println()
	fmt.Println("计数器ID | 名称           | 数值")
	fmt.Println("---------|----------------|----------")

	for i := uint32(0); i <= 8; i++ {
		var value uint64
		err := m.Lookup(i, &value)
		if err != nil {
			continue
		}

		name, exists := counterNames[i]
		if !exists {
			name = "未知"
		}

		fmt.Printf("%-8d | %-14s | %d\n", i, name, value)
	}
	fmt.Println()

	return nil
}

// 清空调试计数器
func clearDebugCounters() error {
	mapPath := "/sys/fs/bpf/firewall/debug_counters"

	m, err := ebpf.LoadPinnedMap(mapPath, &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("无法加载调试计数器 map: %v", err)
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

// 监控调试计数器变化
func monitorCounters() error {
	fmt.Println("=== 实时监控调试计数器 ===")
	fmt.Println("按 Ctrl+C 停止监控")
	fmt.Println()

	for {
		// 清屏 (在Linux终端中)
		fmt.Print("\033[2J\033[H")

		err := showDebugCounters()
		if err != nil {
			return err
		}

		time.Sleep(1 * time.Second)
	}
}

// 显示LVS状态
func showLVSStatus() error {
	fmt.Println("=== XDP LVS 调试状态概览 ===")
	fmt.Printf("时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println()

	// 检查 BPF maps 是否存在
	mapsPath := "/sys/fs/bpf/firewall"
	if _, err := os.Stat(mapsPath); os.IsNotExist(err) {
		fmt.Println("✗ BPF Maps 不存在")
		return nil
	}

	fmt.Println("✓ BPF Maps 已创建")
	fmt.Printf("  Maps 位置: %s\n", mapsPath)

	// 检查调试 map
	debugMapPath := mapsPath + "/debug_counters"
	if _, err := os.Stat(debugMapPath); err == nil {
		fmt.Println("✓ 调试计数器可用")
	} else {
		fmt.Println("✗ 调试计数器不可用")
	}

	fmt.Println()
	return showDebugCounters()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("XDP LVS 调试工具 (Go版本)")
		fmt.Println()
		fmt.Println("用法: go run debug_tool.go [选项]")
		fmt.Println()
		fmt.Println("选项:")
		fmt.Println("  counters    显示调试计数器")
		fmt.Println("  clear       清空调试计数器")
		fmt.Println("  monitor     实时监控计数器变化")
		fmt.Println("  status      显示状态概览")
		fmt.Println()
		os.Exit(1)
	}

	if os.Geteuid() != 0 {
		fmt.Println("错误: 需要 root 权限运行此程序")
		fmt.Println("使用: sudo go run debug_tool.go [选项]")
		os.Exit(1)
	}

	command := os.Args[1]
	var err error

	switch command {
	case "counters":
		err = showDebugCounters()
	case "clear":
		err = clearDebugCounters()
	case "monitor":
		err = monitorCounters()
	case "status":
		err = showLVSStatus()
	default:
		fmt.Printf("错误: 未知选项 '%s'\n", command)
		os.Exit(1)
	}

	if err != nil {
		fmt.Printf("错误: %v\n", err)
		os.Exit(1)
	}
}
