package cmd

import (
	"fmt"

	"github.com/morikuni/aec"
	"github.com/spf13/cobra"
)

var (
	Version   string
	GitCommit string
)

const supportMessageShort = `
🚀 all rights reserved by meimeitou`

func printASCIIArt() {
	logo := aec.BlueF.Apply(agentFigletStr)
	support := aec.CyanF.Apply(supportMessageShort)

	fmt.Print(logo)

	fmt.Printf("%s\n\n", support)
}

func MakeVersion() *cobra.Command {
	var command = &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Example: `  agent version
` + supportMessageShort + `
`,
		SilenceUsage: false,
	}
	command.Run = func(cmd *cobra.Command, args []string) {
		printASCIIArt()
		fmt.Println("Version:", Version)
		fmt.Println("Git Commit:", GitCommit)
	}
	return command
}

const agentFigletStr = `
.-. .-')                           
\  ( OO )                          
 ;-----.\   ,----.     .-'),-----. 
 | .-.  |  '  .-./-') ( OO'  .-.  '
 | '-' /_) |  |_( O- )/   |  | |  |
 | .-. '.  |  | .--, \_) |  |\|  |
 | |  \  |(|  | '. (_/  \ |  | |  |
 | '--'  / |  '--'  |    ''  '-'  '
 '------'   '------'       '-----' 
`
