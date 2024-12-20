package sync

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"strings"

	"github.com/daocloud/crproxy/cache"
	"github.com/daocloud/crproxy/storage"
	csync "github.com/daocloud/crproxy/sync"
	"github.com/daocloud/crproxy/transport"
	"github.com/docker/distribution/manifest/manifestlist"
	"github.com/spf13/cobra"
)

type flagpole struct {
	StorageURL   []string
	Deep         bool
	List         []string
	ListFromFile string
	Platform     []string
	MaxWarn      int
	Userpass     []string
}

func NewCommand() *cobra.Command {
	flags := &flagpole{
		Platform: []string{
			"linux/amd64",
			"linux/arm64",
		},
		MaxWarn: -1,
	}

	cmd := &cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "sync",
		Short: "Sync images",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd.Context(), flags)
		},
	}

	cmd.Flags().StringSliceVar(&flags.StorageURL, "storage-url", flags.StorageURL, "Storage driver url")
	cmd.Flags().BoolVar(&flags.Deep, "deep", flags.Deep, "Deep sync")
	cmd.Flags().StringSliceVar(&flags.List, "list", flags.List, "List")
	cmd.Flags().StringVar(&flags.ListFromFile, "list-from-file", flags.ListFromFile, "List from file")
	cmd.Flags().StringSliceVar(&flags.Platform, "platform", flags.Platform, "Platform")
	cmd.Flags().IntVar(&flags.MaxWarn, "max-warn", flags.MaxWarn, "Max warn")
	cmd.Flags().StringSliceVarP(&flags.Userpass, "user", "u", flags.Userpass, "host and username and password -u user:pwd@host")
	return cmd
}

func runE(ctx context.Context, flags *flagpole) error {

	opts := []csync.Option{}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

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
		csync.WithDomainAlias(map[string]string{
			"docker.io": "registry-1.docker.io",
			"ollama.ai": "registry.ollama.ai",
		}),
		csync.WithDeep(flags.Deep),
		csync.WithTransport(tp),
		csync.WithLogger(logger),
		csync.WithFilterPlatform(filterPlatform(flags.Platform)),
	)

	sm, err := csync.NewSyncManager(opts...)
	if err != nil {
		return fmt.Errorf("create sync manager failed: %w", err)
	}

	warnCount := 0
	for _, item := range flags.List {
		err = sm.Image(ctx, item)
		if err != nil {
			logger.Warn("Sync failed", "error ", err)
			warnCount++
			if flags.MaxWarn > -1 && warnCount >= flags.MaxWarn {
				return fmt.Errorf("max warn reached")
			}
		}
	}

	if flags.ListFromFile != "" {
		f, err := os.ReadFile(flags.ListFromFile)
		if err != nil {
			return fmt.Errorf("read list from file failed: %w", err)
		}
		lines := strings.Split(string(f), "\n")

		rand.Shuffle(len(lines), func(i, j int) {
			lines[i], lines[j] = lines[j], lines[i]
		})
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			err = sm.Image(ctx, line)
			if err != nil {
				logger.Warn("Sync failed", "error ", err)
				warnCount++
				if flags.MaxWarn > -1 && warnCount >= flags.MaxWarn {
					return fmt.Errorf("max warn reached")
				}
			}
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
