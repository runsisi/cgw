package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/runsisi/cgw/pkg/auth"
)

var (
	version bool
)

func init() {
	cobra.OnInitialize(initConfig)

	flags := rootCmd.Flags()
	flags.BoolVarP(&version, "version", "v", false, "version")

	rootCmd.AddCommand(auth.LoginCmd)
}

func initConfig() {
}

var rootCmd = &cobra.Command{
	Use:  "cgw",
	Long: "A gateway for ceph cluster.",
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if version {
			fmt.Println("0.1")
		}
	},
}

func execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func main() {
    execute()
}
