package cmd

import (
	"fmt"
	"log"
	"time"

	"github.com/meimeitou/bgo/bpf/filterdns"
	"github.com/spf13/cobra"
)

// MakeFilterDNS creates the filter-dns command
func MakeFilterDNS() *cobra.Command {
	var (
		interfaceName string
		showStats     bool
		statsInterval int
		whitelistFile string
		blacklistFile string
	)

	command := &cobra.Command{
		Use:   "filter-dns",
		Short: "Run XDP DNS filter that only allows port 53 traffic",
		Long: `Run a simple XDP filter that only allows DNS traffic (port 53) to pass through.
All other TCP/UDP traffic will be dropped.

This is useful for testing or creating a minimal DNS-only network filter.

Supports IP whitelist and blacklist for both IPv4 and IPv6 addresses.
Whitelist mode: only allows DNS traffic from IPs in the whitelist.
Blacklist mode: blocks DNS traffic from IPs in the blacklist.

IP list file format:
  - Plain text or CSV format
  - One IP address per line
  - Lines starting with # are treated as comments
  - Invalid IP addresses are skipped

Example:
  # Start DNS filter on eth0
  sudo bgo filter-dns --interface eth0

  # Start with whitelist
  sudo bgo filter-dns --interface eth0 --whitelist /path/to/whitelist.txt

  # Start with blacklist
  sudo bgo filter-dns --interface eth0 --blacklist /path/to/blacklist.txt

  # Start with stats display
  sudo bgo filter-dns --interface eth0 --stats --whitelist allowed_ips.csv

  # Custom stats interval (every 5 seconds)
  sudo bgo filter-dns --interface eth0 --stats --interval 5`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if interfaceName == "" {
				return fmt.Errorf("interface name is required")
			}

			// 检查不能同时指定黑名单和白名单
			if whitelistFile != "" && blacklistFile != "" {
				return fmt.Errorf("cannot specify both whitelist and blacklist")
			}

			// 创建DNS过滤器
			filter, err := filterdns.New(interfaceName, whitelistFile, blacklistFile)
			if err != nil {
				return fmt.Errorf("failed to create DNS filter: %w", err)
			}

			// 如果需要显示统计信息
			if showStats {
				go func() {
					ticker := time.NewTicker(time.Duration(statsInterval) * time.Second)
					defer ticker.Stop()

					for range ticker.C {
						stats, err := filter.GetStats()
						if err != nil {
							log.Printf("Failed to get stats: %v", err)
							continue
						}
						fmt.Printf("\n=== DNS Filter Stats ===\n")
						fmt.Printf("Total packets:      %d\n", stats.TotalPackets)
						fmt.Printf("DNS packets:        %d (passed)\n", stats.DNSPackets)
						fmt.Printf("Dropped packets:    %d\n", stats.DroppedPackets)
						if whitelistFile != "" {
							fmt.Printf("Whitelist allowed:  %d\n", stats.WhitelistAllowed)
							fmt.Printf("Whitelist dropped:  %d\n", stats.WhitelistDropped)
						}
						if blacklistFile != "" {
							fmt.Printf("Blacklist dropped:  %d\n", stats.BlacklistDropped)
						}
						fmt.Println("=========================")
					}
				}()
			}

			// 运行服务（阻塞直到收到退出信号）
			return filter.Run()
		},
	}

	command.Flags().StringVarP(&interfaceName, "interface", "i", "", "Network interface to attach XDP filter (required)")
	command.Flags().BoolVarP(&showStats, "stats", "s", false, "Show statistics periodically")
	command.Flags().IntVarP(&statsInterval, "interval", "n", 2, "Statistics display interval in seconds")
	command.Flags().StringVar(&whitelistFile, "whitelist", "", "Path to whitelist file (text or CSV, one IP per line)")
	command.Flags().StringVar(&blacklistFile, "blacklist", "", "Path to blacklist file (text or CSV, one IP per line)")
	command.MarkFlagRequired("interface")

	return command
}
