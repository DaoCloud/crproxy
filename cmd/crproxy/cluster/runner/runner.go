package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/daocloud/crproxy/cache"
	"github.com/daocloud/crproxy/internal/spec"
	"github.com/daocloud/crproxy/queue/client"
	"github.com/daocloud/crproxy/runner"
	"github.com/daocloud/crproxy/transport"
	"github.com/spf13/cobra"
	"github.com/wzshiming/httpseek"
	"github.com/wzshiming/sss"
)

type flagpole struct {
	QueueURL   string
	QueueToken string

	ManifestStorageURL string

	BigStorageURL  string
	BigStorageSize int

	ResumeSize int

	StorageURL    []string
	Quick         bool
	Platform      []string
	Userpass      []string
	Retry         int
	RetryInterval time.Duration

	Lease string

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

	cmd.Flags().StringVar(&flags.QueueToken, "queue-token", flags.QueueToken, "Queue token")
	cmd.Flags().StringVar(&flags.QueueURL, "queue-url", flags.QueueURL, "Queue URL")

	cmd.Flags().StringArrayVar(&flags.StorageURL, "storage-url", flags.StorageURL, "Storage driver url")
	cmd.Flags().StringVar(&flags.BigStorageURL, "big-storage-url", flags.BigStorageURL, "Big storage driver url")
	cmd.Flags().IntVar(&flags.BigStorageSize, "big-storage-size", flags.BigStorageSize, "Big storage size")
	cmd.Flags().IntVar(&flags.ResumeSize, "resume-size", flags.ResumeSize, "Resume size")

	cmd.Flags().StringVar(&flags.ManifestStorageURL, "manifest-storage-url", flags.ManifestStorageURL, "manifest storage driver url")
	cmd.Flags().BoolVar(&flags.Quick, "quick", flags.Quick, "Quick sync with tags")
	cmd.Flags().StringSliceVar(&flags.Platform, "platform", flags.Platform, "Platform")
	cmd.Flags().StringArrayVarP(&flags.Userpass, "user", "u", flags.Userpass, "host and username and password -u user:pwd@host")
	cmd.Flags().IntVar(&flags.Retry, "retry", flags.Retry, "Retry")
	cmd.Flags().DurationVar(&flags.RetryInterval, "retry-interval", flags.RetryInterval, "Retry interval")
	cmd.Flags().DurationVar(&flags.Duration, "duration", flags.Duration, "Duration of the runner")
	cmd.Flags().StringVar(&flags.Lease, "lease", flags.Lease, "Lease of the runner")

	return cmd
}

func runE(ctx context.Context, flags *flagpole) error {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	var caches []*cache.Cache
	for _, s := range flags.StorageURL {
		sd, err := sss.NewSSS(sss.WithURL(s))
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

	var lease string
	if flags.Lease == "" {
		lease, err = identity()
		if err != nil {
			return err
		}
	} else {
		lease = fmt.Sprintf("%s-%d", flags.Lease, time.Now().Unix())
	}

	if flags.RetryInterval > 0 {
		tp = httpseek.NewMustReaderTransport(tp, func(request *http.Request, retry int, err error) error {
			if errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			if flags.Retry > 0 && retry >= flags.Retry {
				return err
			}
			if logger != nil {
				logger.Warn("Retry", "url", request.URL, "retry", retry, "error", err)
			}
			time.Sleep(flags.RetryInterval)
			return nil
		})
	}

	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 10 {
				return http.ErrUseLastResponse
			}
			s := make([]string, 0, len(via)+1)
			for _, v := range via {
				s = append(s, v.URL.String())
			}

			lastRedirect := req.URL.String()
			s = append(s, lastRedirect)
			logger.Info("redirect", "redirects", s)

			return nil
		},
		Transport: tp,
	}

	queueClient := client.NewMessageClient(http.DefaultClient, flags.QueueURL, flags.QueueToken)

	opts := []runner.Option{
		runner.WithCaches(caches...),
		runner.WithHttpClient(httpClient),
		runner.WithLease(lease),
		runner.WithLogger(logger),
		runner.WithQueueClient(queueClient),
		runner.WithFilterPlatform(filterPlatform(flags.Platform)),
	}

	if flags.BigStorageURL != "" && flags.BigStorageSize > 0 {
		bigCacheOpts := []cache.Option{}
		sd, err := sss.NewSSS(sss.WithURL(flags.BigStorageURL))
		if err != nil {
			return fmt.Errorf("create storage driver failed: %w", err)
		}
		bigCacheOpts = append(bigCacheOpts,
			cache.WithStorageDriver(sd),
		)
		bigsdcache, err := cache.NewCache(bigCacheOpts...)
		if err != nil {
			return fmt.Errorf("create cache failed: %w", err)
		}
		opts = append(opts, runner.WithBigCache(bigsdcache, flags.BigStorageSize))
	}

	if flags.ManifestStorageURL != "" {
		manifestCacheOpts := []cache.Option{}
		sd, err := sss.NewSSS(sss.WithURL(flags.ManifestStorageURL))
		if err != nil {
			return fmt.Errorf("create storage driver failed: %w", err)
		}
		manifestCacheOpts = append(manifestCacheOpts,
			cache.WithStorageDriver(sd),
		)
		manifestsdcache, err := cache.NewCache(manifestCacheOpts...)
		if err != nil {
			return fmt.Errorf("create cache failed: %w", err)
		}
		opts = append(opts, runner.WithManifestCache(manifestsdcache))
	}

	if flags.ResumeSize > 0 {
		opts = append(opts, runner.WithResumeSize(flags.ResumeSize))
	}

	runner, err := runner.NewRunner(opts...)
	if err != nil {
		return err
	}

	if flags.Duration > 0 {
		ctx, _ = context.WithTimeout(ctx, flags.Duration)
	}

	err = runner.Run(ctx)
	if err != nil {
		if !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
	}
	return nil
}

func filterPlatform(ps []string) func(pf spec.Platform) bool {
	platforms := map[spec.Platform]struct{}{}
	for _, p := range ps {
		ao := strings.SplitN(p, "/", 2)
		if len(ao) != 2 {
			continue
		}
		key := spec.Platform{
			OS:           ao[0],
			Architecture: ao[1],
		}
		platforms[key] = struct{}{}
	}
	return func(pf spec.Platform) bool {
		if _, ok := platforms[pf]; ok {
			return true
		}
		return false
	}
}

func identity() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("unable to get hostname: %w", err)
	}
	h := sha256.Sum256([]byte(hostname))
	hnHex := hex.EncodeToString(h[:])
	return fmt.Sprintf("%s-%d", hnHex[:16], time.Now().Unix()), nil
}
