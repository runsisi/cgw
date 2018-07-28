package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/runsisi/cgw/cmd/auth"
	"github.com/runsisi/cgw/cmd/cluster"
)

var (
	version bool
)

var cmd = &cobra.Command{
	Use:  "cgw",
	Long: "A gateway for ceph cluster.",
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	cobra.OnInitialize()

	flags := cmd.Flags()
	flags.BoolVarP(&version, "version", "v", false, "version")

	cmd.AddCommand(auth.Cmd)
	cmd.AddCommand(cluster.Cmd)
}

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
