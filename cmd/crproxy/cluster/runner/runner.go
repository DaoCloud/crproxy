package runner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/daocloud/crproxy/cache"
	"github.com/daocloud/crproxy/runner"
	"github.com/daocloud/crproxy/storage"
	csync "github.com/daocloud/crproxy/sync"
	"github.com/daocloud/crproxy/transport"
	"github.com/docker/distribution/manifest/manifestlist"
	"github.com/spf13/cobra"
)

type flagpole struct {
	QueueURL string

	AdminToken string

	StorageURL []string
	Deep       bool
	Quick      bool
	Platform   []string
	Userpass   []string

	Duration time.Duration
}

func NewCommand() *cobra.Command {
	flags := &flagpole{
		Platform: []string{
			"linux/amd64",
			"linux/arm64",
		},
	}

	cmd := &cobra.Command{
		Use:   "runner",
		Short: "Runner",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd.Context(), flags)
		},
	}

	cmd.Flags().StringVar(&flags.AdminToken, "admin-token", flags.AdminToken, "Admin token")

	cmd.Flags().StringVar(&flags.QueueURL, "queue-url", flags.QueueURL, "Queue URL")

	cmd.Flags().StringArrayVar(&flags.StorageURL, "storage-url", flags.StorageURL, "Storage driver url")
	cmd.Flags().BoolVar(&flags.Deep, "deep", flags.Deep, "Deep sync with blob")
	cmd.Flags().BoolVar(&flags.Quick, "quick", flags.Quick, "Quick sync with tags")
	cmd.Flags().StringSliceVar(&flags.Platform, "platform", flags.Platform, "Platform")
	cmd.Flags().StringArrayVarP(&flags.Userpass, "user", "u", flags.Userpass, "host and username and password -u user:pwd@host")

	cmd.Flags().DurationVar(&flags.Duration, "duration", flags.Duration, "Duration of the running")

	return cmd
}

func runE(ctx context.Context, flags *flagpole) error {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	opts := []csync.Option{}

	var caches []*cache.Cache
	for _, s := range flags.StorageURL {
		sd, err := storage.NewStorage(s)
		if err != nil {
			return fmt.Errorf("create storage driver failed: %w", err)
		}

		cache, err := cache.NewCache(cache.WithStorageDriver(sd))
		if err != nil {
			return fmt.Errorf("create cache failed: %w", err)
		}

		caches = append(caches, cache)
	}

	transportOpts := []transport.Option{
		transport.WithLogger(logger),
	}

	if len(flags.Userpass) != 0 {
		transportOpts = append(transportOpts, transport.WithUserAndPass(flags.Userpass))
	}

	tp, err := transport.NewTransport(transportOpts...)
	if err != nil {
		return fmt.Errorf("create transport failed: %w", err)
	}

	opts = append(opts,
		csync.WithCaches(caches...),
		csync.WithDeep(flags.Deep),
		csync.WithQuick(flags.Quick),
		csync.WithTransport(tp),
		csync.WithLogger(logger),
		csync.WithFilterPlatform(filterPlatform(flags.Platform)),
	)

	sm, err := csync.NewSyncManager(opts...)
	if err != nil {
		return fmt.Errorf("create sync manager failed: %w", err)
	}

	runner, err := runner.NewRunner(http.DefaultClient, flags.QueueURL, flags.AdminToken, sm)
	if err != nil {
		return err
	}

	if flags.Duration > 0 {
		ctx, _ = context.WithTimeout(ctx, flags.Duration)
	}

	err = runner.Run(ctx, logger)
	if err != nil {
		if !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
	}
	return nil
}

func filterPlatform(ps []string) func(pf manifestlist.PlatformSpec) bool {
	platforms := map[string]struct{}{}
	for _, p := range ps {
		platforms[p] = struct{}{}
	}
	return func(pf manifestlist.PlatformSpec) bool {
		p := fmt.Sprintf("%s/%s", pf.OS, pf.Architecture)

		if _, ok := platforms[p]; ok {
			return true
		}
		return false
	}
}
