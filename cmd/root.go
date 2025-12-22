package cmd

import "github.com/spf13/cobra"

var RootCmd = &cobra.Command{
	Use: "bgo",
	Run: func(cmd *cobra.Command, args []string) {
		printASCIIArt()
		cmd.Help()
	},
	Example: `  # bgo
`,
}

func init() {
	RootCmd.AddCommand(
		MakeVersion(),
		MakeBioSnoop(),
		MakeFirewallServer(),
		MakeFirewallUpdate(),
		MakeFirewallRateLimit(),
		firewallLvsCmd,
		MakeFilterDNS(),
	)
}
