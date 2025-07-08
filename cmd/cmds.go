package cmd

import (
	"fmt"
	"net"
	"strconv"

	"github.com/meimeitou/bgo/bpf/bashreadline"
	tcfirewall "github.com/meimeitou/bgo/bpf/tc-firewall"
	"github.com/spf13/cobra"
)

func MakeBashReadline() *cobra.Command {
	var command = &cobra.Command{
		Use:   "bashreadline",
		Short: "Run bash readline bpf program",
		Example: `  bgo bashreadline
`,
		SilenceUsage: false,
		Run: func(cmd *cobra.Command, args []string) {
			bashreadline.BashReadline()
		},
	}

	return command
}

func MakeTCFirewall() *cobra.Command {
	var (
		interfaceName string
		blockedIPs    []string
		blockedPorts  []string
		allowedIPs    []string
		enableIngress bool
		enableEgress  bool
	)

	command := &cobra.Command{
		Use:   "tc-firewall",
		Short: "Run TC-based eBPF firewall",
		Long: `Run a Traffic Control (TC) based eBPF firewall that can block/allow 
specific IP addresses and ports for both ingress and egress traffic.

This firewall uses eBPF programs attached to TC to filter network packets
at the kernel level, providing high-performance packet filtering.

By default, only ingress (incoming) traffic filtering is enabled. You can
enable egress (outgoing) traffic filtering with the --egress flag, or
disable ingress filtering with --ingress=false.`,
		Example: `  # Block specific IPs and ports on eth0 (ingress only, default)
  bgo tc-firewall --interface eth0 --blocked-ips 192.168.1.100,10.0.0.50 --blocked-ports 22,80,443

  # Block IPs and ports for both ingress and egress traffic
  bgo tc-firewall --interface eth0 --blocked-ips 192.168.1.100 --blocked-ports 22,80 --ingress --egress

  # Allow only specific IPs (whitelist mode) for ingress traffic
  bgo tc-firewall --interface eth0 --allowed-ips 192.168.1.0/24,10.0.0.0/8 --ingress

  # Enable egress filtering only (disable ingress)
  bgo tc-firewall --interface eth0 --blocked-ips 192.168.1.100 --ingress=false --egress

  # Mixed mode: allow trusted IPs, block specific IPs and ports for both directions
  bgo tc-firewall --interface eth0 --allowed-ips 192.168.1.1 --blocked-ips 192.168.1.100 --blocked-ports 22,23,80 --ingress --egress`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTCFirewall(interfaceName, blockedIPs, blockedPorts, allowedIPs, enableIngress, enableEgress)
		},
	}

	command.Flags().StringVarP(&interfaceName, "interface", "i", "eth0", "Network interface to attach firewall")
	command.Flags().StringSliceVar(&blockedIPs, "blocked-ips", []string{}, "Comma-separated list of IP addresses to block")
	command.Flags().StringSliceVar(&blockedPorts, "blocked-ports", []string{}, "Comma-separated list of ports to block")
	command.Flags().StringSliceVar(&allowedIPs, "allowed-ips", []string{}, "Comma-separated list of IP addresses to allow (whitelist)")
	command.Flags().BoolVar(&enableIngress, "ingress", true, "Enable ingress (incoming) traffic filtering")
	command.Flags().BoolVar(&enableEgress, "egress", false, "Enable egress (outgoing) traffic filtering")

	return command
}

func runTCFirewall(interfaceName string, blockedIPs []string, blockedPortsStr []string, allowedIPs []string, enableIngress bool, enableEgress bool) error {
	// 验证至少启用了一个方向的过滤
	if !enableIngress && !enableEgress {
		return fmt.Errorf("at least one of --ingress or --egress must be enabled")
	}

	// 解析被阻止的IP
	var parsedBlockedIPs []net.IP
	for _, ipStr := range blockedIPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("invalid IP address: %s", ipStr)
		}
		parsedBlockedIPs = append(parsedBlockedIPs, ip)
	}

	// 解析被阻止的端口
	var parsedBlockedPorts []uint16
	for _, portStr := range blockedPortsStr {
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return fmt.Errorf("invalid port number: %s", portStr)
		}
		parsedBlockedPorts = append(parsedBlockedPorts, uint16(port))
	}

	// 解析允许的IP
	var parsedAllowedIPs []net.IP
	for _, ipStr := range allowedIPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("invalid IP address: %s", ipStr)
		}
		parsedAllowedIPs = append(parsedAllowedIPs, ip)
	}

	// 创建防火墙配置
	config := &tcfirewall.FirewallConfig{
		Interface:     interfaceName,
		BlockedIPs:    parsedBlockedIPs,
		BlockedPorts:  parsedBlockedPorts,
		AllowedIPs:    parsedAllowedIPs,
		EnableIngress: enableIngress,
		EnableEgress:  enableEgress,
	}

	// 运行防火墙
	return tcfirewall.RunFirewall(config)
}
