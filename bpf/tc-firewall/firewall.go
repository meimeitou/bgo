package tcfirewall

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 firewall firewall.c -- -I../../lib/common -I../../lib/libbpf

// FirewallStats 防火墙统计信息
type FirewallStats struct {
	TotalPackets    uint64
	DroppedPackets  uint64
	AcceptedPackets uint64
	TCPPackets      uint64
	UDPPackets      uint64
	ICMPPackets     uint64
	OtherPackets    uint64
}

// FirewallConfig 防火墙配置
type FirewallConfig struct {
	Interface     string
	BlockedIPs    []net.IP
	BlockedPorts  []uint16
	AllowedIPs    []net.IP
	EnableIngress bool // 是否启用入站规则
	EnableEgress  bool // 是否启用出站规则
}

// TCFirewall TC防火墙
type TCFirewall struct {
	objs          *firewallObjects
	ingressLink   link.Link
	egressLink    link.Link
	config        *FirewallConfig
	statsInterval time.Duration
}

// NewTCFirewall 创建新的TC防火墙实例
func NewTCFirewall(config *FirewallConfig) *TCFirewall {
	return &TCFirewall{
		config:        config,
		statsInterval: 5 * time.Second,
	}
}

// Load 加载eBPF程序
func (fw *TCFirewall) Load() error {
	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}

	// 加载eBPF程序
	spec, err := loadFirewall()
	if err != nil {
		return fmt.Errorf("failed to load firewall spec: %w", err)
	}

	objs := &firewallObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return fmt.Errorf("failed to load and assign objects: %w", err)
	}

	fw.objs = objs
	return nil
}

// AttachToInterface 将防火墙附加到网络接口
func (fw *TCFirewall) AttachToInterface() error {
	if fw.objs == nil {
		return fmt.Errorf("eBPF objects not loaded")
	}

	// 获取网络接口索引
	iface, err := net.InterfaceByName(fw.config.Interface)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", fw.config.Interface, err)
	}

	// 创建TC qdisc (如果不存在)
	if err := fw.ensureQdisc(iface.Index); err != nil {
		return fmt.Errorf("failed to ensure qdisc: %w", err)
	}

	// 根据配置附加过滤器
	if fw.config.EnableIngress {
		// 附加ingress过滤器
		ingressLink, err := link.AttachTCX(link.TCXOptions{
			Program:   fw.objs.TcIngressFirewall,
			Attach:    ebpf.AttachTCXIngress,
			Interface: iface.Index,
		})
		if err != nil {
			return fmt.Errorf("failed to attach ingress filter: %w", err)
		}
		fw.ingressLink = ingressLink
		log.Printf("Attached ingress filter to interface %s", fw.config.Interface)
	}

	if fw.config.EnableEgress {
		// 附加egress过滤器
		egressLink, err := link.AttachTCX(link.TCXOptions{
			Program:   fw.objs.TcEgressFirewall,
			Attach:    ebpf.AttachTCXEgress,
			Interface: iface.Index,
		})
		if err != nil {
			if fw.ingressLink != nil {
				fw.ingressLink.Close()
			}
			return fmt.Errorf("failed to attach egress filter: %w", err)
		}
		fw.egressLink = egressLink
		log.Printf("Attached egress filter to interface %s", fw.config.Interface)
	}

	if !fw.config.EnableIngress && !fw.config.EnableEgress {
		return fmt.Errorf("at least one of ingress or egress must be enabled")
	}

	log.Printf("TC firewall attached to interface %s (index: %d)", fw.config.Interface, iface.Index)
	return nil
}

// ensureQdisc 确保TC qdisc存在
func (fw *TCFirewall) ensureQdisc(ifindex int) error {
	// 这里可以使用netlink库来管理qdisc，为了简化，我们假设qdisc已存在
	// 在实际使用中，你可能需要：
	// tc qdisc add dev <interface> clsact
	return nil
}

// LoadRules 加载防火墙规则
func (fw *TCFirewall) LoadRules() error {
	if fw.objs == nil {
		return fmt.Errorf("eBPF objects not loaded")
	}

	// 加载被阻止的IP
	for _, ip := range fw.config.BlockedIPs {
		if ip.To4() != nil {
			ipInt := ipToUint32(ip.To4())
			blocked := uint8(1)
			if err := fw.objs.BlockedIps.Put(ipInt, blocked); err != nil {
				return fmt.Errorf("failed to add blocked IP %s: %w", ip.String(), err)
			}
			log.Printf("Added blocked IP: %s", ip.String())
		}
	}

	// 加载被阻止的端口
	for _, port := range fw.config.BlockedPorts {
		blocked := uint8(1)
		if err := fw.objs.BlockedPorts.Put(port, blocked); err != nil {
			return fmt.Errorf("failed to add blocked port %d: %w", port, err)
		}
		log.Printf("Added blocked port: %d", port)
	}

	// 加载允许的IP（白名单）
	for _, ip := range fw.config.AllowedIPs {
		if ip.To4() != nil {
			ipInt := ipToUint32(ip.To4())
			allowed := uint8(1)
			if err := fw.objs.AllowedIps.Put(ipInt, allowed); err != nil {
				return fmt.Errorf("failed to add allowed IP %s: %w", ip.String(), err)
			}
			log.Printf("Added allowed IP: %s", ip.String())
		}
	}

	// 初始化统计信息
	stats := FirewallStats{}
	key := uint32(0)
	if err := fw.objs.StatsMap.Put(key, stats); err != nil {
		return fmt.Errorf("failed to initialize stats: %w", err)
	}

	return nil
}

// GetStats 获取防火墙统计信息
func (fw *TCFirewall) GetStats() (*FirewallStats, error) {
	if fw.objs == nil {
		return nil, fmt.Errorf("eBPF objects not loaded")
	}

	var stats FirewallStats
	key := uint32(0)
	if err := fw.objs.StatsMap.Lookup(key, &stats); err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	return &stats, nil
}

// PrintStats 打印统计信息
func (fw *TCFirewall) PrintStats() {
	stats, err := fw.GetStats()
	if err != nil {
		log.Printf("Failed to get stats: %v", err)
		return
	}

	fmt.Printf("\n=== TC Firewall Statistics ===\n")
	fmt.Printf("Total Packets:    %d\n", stats.TotalPackets)
	fmt.Printf("Dropped Packets:  %d\n", stats.DroppedPackets)
	fmt.Printf("Accepted Packets: %d\n", stats.AcceptedPackets)
	fmt.Printf("TCP Packets:      %d\n", stats.TCPPackets)
	fmt.Printf("UDP Packets:      %d\n", stats.UDPPackets)
	fmt.Printf("ICMP Packets:     %d\n", stats.ICMPPackets)
	fmt.Printf("Other Packets:    %d\n", stats.OtherPackets)

	if stats.TotalPackets > 0 {
		dropRate := float64(stats.DroppedPackets) / float64(stats.TotalPackets) * 100
		fmt.Printf("Drop Rate:        %.2f%%\n", dropRate)
	}
	fmt.Printf("===============================\n\n")
}

// StartStatsMonitor 启动统计信息监控
func (fw *TCFirewall) StartStatsMonitor(ctx context.Context) {
	ticker := time.NewTicker(fw.statsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fw.PrintStats()
		}
	}
}

// Close 关闭防火墙
func (fw *TCFirewall) Close() error {
	var errs []error

	if fw.ingressLink != nil {
		if err := fw.ingressLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close ingress link: %w", err))
		}
	}

	if fw.egressLink != nil {
		if err := fw.egressLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close egress link: %w", err))
		}
	}

	if fw.objs != nil {
		if err := fw.objs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close objects: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing firewall: %v", errs)
	}

	return nil
}

// ipToUint32 将IP地址转换为uint32
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 + uint32(ip[1])<<16 + uint32(ip[2])<<8 + uint32(ip[3])
}

// RunFirewall 运行TC防火墙
func RunFirewall(config *FirewallConfig) error {
	// 检查权限
	if os.Geteuid() != 0 {
		return fmt.Errorf("this program requires root privileges")
	}

	// 创建防火墙实例
	fw := NewTCFirewall(config)

	// 加载eBPF程序
	if err := fw.Load(); err != nil {
		return fmt.Errorf("failed to load firewall: %w", err)
	}
	defer fw.Close()

	// 加载规则
	if err := fw.LoadRules(); err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}

	// 附加到接口
	if err := fw.AttachToInterface(); err != nil {
		return fmt.Errorf("failed to attach to interface: %w", err)
	}

	log.Printf("TC firewall started on interface %s", config.Interface)
	log.Printf("Ingress enabled: %v", config.EnableIngress)
	log.Printf("Egress enabled: %v", config.EnableEgress)
	log.Printf("Blocked IPs: %v", config.BlockedIPs)
	log.Printf("Blocked Ports: %v", config.BlockedPorts)
	log.Printf("Allowed IPs: %v", config.AllowedIPs)

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动统计监控
	go fw.StartStatsMonitor(ctx)

	// 等待信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Println("Received signal, shutting down...")

	// 打印最终统计
	fw.PrintStats()

	return nil
}
