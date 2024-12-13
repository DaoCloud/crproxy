package cluster

import (
	"github.com/spf13/cobra"

	"github.com/daocloud/crproxy/cmd/crproxy/cluster/agent"
	"github.com/daocloud/crproxy/cmd/crproxy/cluster/auth"
	"github.com/daocloud/crproxy/cmd/crproxy/cluster/gateway"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "cluster",
		Short: "Cluster commands",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Usage()
		},
	}
	cmd.AddCommand(agent.NewCommand())
	cmd.AddCommand(gateway.NewCommand())
	cmd.AddCommand(auth.NewCommand())
	return cmd
}
