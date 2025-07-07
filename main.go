package main

import (
	"os"

	"github.com/meimeitou/bgo/cmd"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
