package cmd

import (
	"github.com/meimeitou/bgo/bpf/biosnoop"
	"github.com/spf13/cobra"
)

// MakeBioSnoop creates the biosnoop command
func MakeBioSnoop() *cobra.Command {
	var showQueue bool

	command := &cobra.Command{
		Use:   "biosnoop",
		Short: "Trace block device I/O and print details including issuing PID",
		Long: `Trace block device I/O and print details including issuing PID.

This tool traces block device I/O (disk I/O) and prints one line per I/O with details 
including issuing PID, process name, operation type, device, sector, size, and latency.

The tool works by tracing the kernel block I/O layer using eBPF tracepoints on:
- block:block_rq_issue - when I/O request is issued
- block:block_rq_complete - when I/O request completes

This provides stable tracing across different kernel versions and shows:
- Process information (PID, command name)
- I/O characteristics (read/write, sector, size)
- Timing information (latency, optional queue time)
- Device information

This is useful for:
- Identifying I/O patterns and performance issues
- Finding processes causing high disk activity  
- Analyzing I/O latency and throughput
- Debugging storage performance problems`,
		Example: `  # Trace all block device I/O
  bgo biosnoop

  # Include OS queued time in addition to device service time
  bgo biosnoop --queue

  # Trace for 10 seconds then exit
  timeout 10 bgo biosnoop`,
		RunE: func(cmd *cobra.Command, args []string) error {
			biosnoop.Run(showQueue)
			return nil
		},
	}

	command.Flags().BoolVarP(&showQueue, "queue", "Q", false, "include OS queued time")

	return command
}
