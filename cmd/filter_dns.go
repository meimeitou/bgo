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
	)

	command := &cobra.Command{
		Use:   "filter-dns",
		Short: "Run XDP DNS filter that only allows port 53 traffic",
		Long: `Run a simple XDP filter that only allows DNS traffic (port 53) to pass through.
All other TCP/UDP traffic will be dropped.

This is useful for testing or creating a minimal DNS-only network filter.

Example:
  # Start DNS filter on eth0
  sudo bgo filter-dns --interface eth0

  # Start with stats display
  sudo bgo filter-dns --interface eth0 --stats

  # Custom stats interval (every 5 seconds)
  sudo bgo filter-dns --interface eth0 --stats --interval 5`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if interfaceName == "" {
				return fmt.Errorf("interface name is required")
			}

			// 创建DNS过滤器
			filter, err := filterdns.New(interfaceName)
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
						fmt.Printf("Total packets:   %d\n", stats.TotalPackets)
						fmt.Printf("DNS packets:     %d (passed)\n", stats.DNSPackets)
						fmt.Printf("Dropped packets: %d\n", stats.DroppedPackets)
						fmt.Println("========================")
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
	command.MarkFlagRequired("interface")

	return command
}
