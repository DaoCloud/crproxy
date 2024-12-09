package sync

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/daocloud/crproxy/cache"
	"github.com/daocloud/crproxy/clientset"
	csync "github.com/daocloud/crproxy/sync"
	"github.com/docker/distribution/manifest/manifestlist"
	"github.com/docker/distribution/registry/storage/driver/factory"
	"github.com/spf13/cobra"
)

type flagpole struct {
	StorageDriver     string
	StorageParameters map[string]string
	List              []string
	ListFromFile      string
	Platform          []string
	MaxWarn           int
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
	cmd.Flags().StringVar(&flags.StorageDriver, "storage-driver", flags.StorageDriver, "Storage driver")
	cmd.Flags().StringToStringVar(&flags.StorageParameters, "storage-parameters", flags.StorageParameters, "Storage parameters")
	cmd.Flags().StringSliceVar(&flags.List, "list", flags.List, "List")
	cmd.Flags().StringVar(&flags.ListFromFile, "list-from-file", flags.ListFromFile, "List from file")
	cmd.Flags().StringSliceVar(&flags.Platform, "platform", flags.Platform, "Platform")
	cmd.Flags().IntVar(&flags.MaxWarn, "max-warn", flags.MaxWarn, "Max warn")
	return cmd
}

func runE(ctx context.Context, flags *flagpole) error {

	opts := []csync.Option{}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cacheOpts := []cache.Option{}

	parameters := map[string]interface{}{}
	for k, v := range flags.StorageParameters {
		parameters[k] = v
	}
	sd, err := factory.Create(flags.StorageDriver, parameters)
	if err != nil {
		return fmt.Errorf("create storage driver failed: %w", err)
	}
	cacheOpts = append(cacheOpts, cache.WithStorageDriver(sd))

	cache, err := cache.NewCache(cacheOpts...)
	if err != nil {
		return fmt.Errorf("create cache failed: %w", err)
	}

	clientOpts := []clientset.Option{
		clientset.WithLogger(logger),
		clientset.WithMaxClientSizeForEachRegistry(16),
	}

	client, err := clientset.NewClientset(clientOpts...)
	if err != nil {
		return fmt.Errorf("create clientset failed: %w", err)
	}

	opts = append(opts,
		csync.WithCache(cache),
		csync.WithDomainAlias(map[string]string{
			"docker.io": "registry-1.docker.io",
			"ollama.ai": "registry.ollama.ai",
		}),
		csync.WithClient(client),
		csync.WithLogger(logger),
	)

	sm, err := csync.NewSyncManager(opts...)
	if err != nil {
		return fmt.Errorf("create sync manager failed: %w", err)
	}

	warnCount := 0
	for _, item := range flags.List {
		err = sm.Image(ctx, item, platformFilter(flags.Platform), func(sp csync.Progress) error {
			logger.Info("Sync", "progress", sp)
			return nil
		})
		if err != nil {
			logger.Warn("Sync failed", "error ", err)
			warnCount++
			if flags.MaxWarn > -1 && warnCount >= flags.MaxWarn {
				return fmt.Errorf("max warn reached")
			}
		}
	}

	if flags.ListFromFile != "" {
		f, err := os.Open(flags.ListFromFile)
		if err != nil {
			return fmt.Errorf("read list from file failed: %w", err)
		}
		defer f.Close()
		reader := bufio.NewReader(f)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			err = sm.Image(ctx, line, platformFilter(flags.Platform), func(sp csync.Progress) error {
				logger.Info("Sync", "progress", sp)
				return nil
			})
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

func platformFilter(ps []string) func(pf manifestlist.PlatformSpec) bool {
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
