package main

import (
	"log/slog"
	"os"

	"github.com/daocloud/crproxy/cmd/crproxy/cluster"
	csync "github.com/daocloud/crproxy/cmd/crproxy/sync"
	"github.com/daocloud/crproxy/internal/signals"
	"github.com/spf13/cobra"

	_ "github.com/daocloud/crproxy/storage/driver/obs"
	_ "github.com/daocloud/crproxy/storage/driver/oss"
	_ "github.com/daocloud/crproxy/storage/driver/s3"
)

func init() {
	cmd.AddCommand(csync.NewCommand())
	cmd.AddCommand(cluster.NewCommand())
}

var (
	cmd = &cobra.Command{
		Use:   "crproxy",
		Short: "crproxy",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Usage()
		},
	}
)

func main() {
	ctx := signals.SetupSignalContext()
	err := cmd.ExecuteContext(ctx)
	if err != nil {
		slog.Error("execute failed", "error", err)
		os.Exit(1)
	}
}
