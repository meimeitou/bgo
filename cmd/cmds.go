package cmd

import (
	"github.com/meimeitou/bgo/bpf/bashreadline"
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
