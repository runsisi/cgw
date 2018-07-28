package auth

import (
	"github.com/spf13/cobra"
	"github.com/runsisi/cgw/pkg/calamari/api"
)

var (
	config api.Config
)

var Cmd = &cobra.Command{
	Use:   "login",
	Short:  "Login to calamari backend",
	Long: "Login to calamari backend",
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

	err = c.Auth().Login()
	if err != nil {
		return err
	}

	return nil
}
