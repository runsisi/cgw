package cluster

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/runsisi/cgw/pkg/calamari/api"
)

var (
	config api.Config
)

var Cmd = &cobra.Command{
	Use:   "cluster",
	Short:  "Cluster operations",
	Long: "Cluster operations",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		run(args)
	},
}

func init() {
	flags := Cmd.Flags()

	config = api.Config{}
	flags.AddFlagSet(config.Flags())
}

func run(args []string) error {
	c, err := config.APIClient()
	if err != nil {
		return err
	}

	err = c.Cluster().List()
	if err != nil {
		fmt.Println(err)
		return err
	}

	return nil
}
