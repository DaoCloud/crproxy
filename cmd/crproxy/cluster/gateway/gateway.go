package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/daocloud/crproxy/agent"
	"github.com/daocloud/crproxy/cache"
	"github.com/daocloud/crproxy/gateway"
	"github.com/daocloud/crproxy/internal/pki"
	"github.com/daocloud/crproxy/internal/server"
	"github.com/daocloud/crproxy/internal/utils"
	"github.com/daocloud/crproxy/queue/client"
	"github.com/daocloud/crproxy/signing"
	"github.com/daocloud/crproxy/storage"
	"github.com/daocloud/crproxy/token"
	"github.com/daocloud/crproxy/transport"
	"github.com/gorilla/handlers"
	"github.com/spf13/cobra"
	"github.com/wzshiming/httpseek"
)

type flagpole struct {
	BigStorageURL  string
	BigStorageSize int

	StorageURL    string
	RedirectLinks string
	SignLink      bool

	ManifestCacheDuration  time.Duration
	RecacheMaxWaitDuration time.Duration

	Userpass        []string
	Retry           int
	RetryInterval   time.Duration
	DisableTagsList bool

	Behind         bool
	Address        string
	AcmeHosts      []string
	AcmeCacheDir   string
	CertFile       string
	PrivateKeyFile string

	TokenPublicKeyFile string
	TokenURL           string

	ReadmeURL string

	BlobNoRedirectSize             int
	BlobNoRedirectMaxSizePerSecond int
	BlobCacheDuration              time.Duration

	DefaultRegistry         string
	OverrideDefaultRegistry map[string]string

	RegistryAlias map[string]string

	Concurrency int

	QueueURL   string
	QueueToken string
}

func NewCommand() *cobra.Command {
	flags := &flagpole{
		Address:           ":18001",
		BlobCacheDuration: time.Hour,
		Concurrency:       10,
		SignLink:          true,
	}

	cmd := &cobra.Command{
		Use:   "gateway",
		Short: "Gateway",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd.Context(), flags)
		},
	}

	cmd.Flags().StringVar(&flags.StorageURL, "storage-url", flags.StorageURL, "Storage driver url")
	cmd.Flags().StringVar(&flags.BigStorageURL, "big-storage-url", flags.BigStorageURL, "Big storage driver url")
	cmd.Flags().IntVar(&flags.BigStorageSize, "big-storage-size", flags.BigStorageSize, "Big storage size")
	cmd.Flags().StringVar(&flags.RedirectLinks, "redirect-links", flags.RedirectLinks, "Redirect links")
	cmd.Flags().BoolVar(&flags.SignLink, "sign-link", flags.SignLink, "Sign Link")

	cmd.Flags().DurationVar(&flags.ManifestCacheDuration, "manifest-cache-duration", flags.ManifestCacheDuration, "Manifest cache duration")
	cmd.Flags().DurationVar(&flags.RecacheMaxWaitDuration, "recache-max-wait-duration", flags.RecacheMaxWaitDuration, "Recache max wait duration")

	cmd.Flags().StringSliceVarP(&flags.Userpass, "user", "u", flags.Userpass, "host and username and password -u user:pwd@host")
	cmd.Flags().IntVar(&flags.Retry, "retry", flags.Retry, "Retry")
	cmd.Flags().DurationVar(&flags.RetryInterval, "retry-interval", flags.RetryInterval, "Retry interval")
	cmd.Flags().BoolVar(&flags.DisableTagsList, "disable-tags-list", flags.DisableTagsList, "Disable tags list")

	cmd.Flags().BoolVar(&flags.Behind, "behind", flags.Behind, "Behind")
	cmd.Flags().StringVar(&flags.Address, "address", flags.Address, "Address")
	cmd.Flags().StringSliceVar(&flags.AcmeHosts, "acme-hosts", flags.AcmeHosts, "Acme hosts")
	cmd.Flags().StringVar(&flags.AcmeCacheDir, "acme-cache-dir", flags.AcmeCacheDir, "Acme cache dir")
	cmd.Flags().StringVar(&flags.CertFile, "cert-file", flags.CertFile, "Cert file")
	cmd.Flags().StringVar(&flags.PrivateKeyFile, "private-key-file", flags.PrivateKeyFile, "Private key file")

	cmd.Flags().StringVar(&flags.TokenPublicKeyFile, "token-public-key-file", flags.TokenPublicKeyFile, "Token public key file")
	cmd.Flags().StringVar(&flags.TokenURL, "token-url", flags.TokenURL, "Token url")

	cmd.Flags().StringVar(&flags.ReadmeURL, "readme-url", flags.ReadmeURL, "Readme url")

	cmd.Flags().IntVar(&flags.BlobNoRedirectSize, "blob-no-redirect-size", flags.BlobNoRedirectSize, "Less than or equal to no redirect")
	cmd.Flags().IntVar(&flags.BlobNoRedirectMaxSizePerSecond, "blob-no-redirect-max-size-per-second", flags.BlobNoRedirectMaxSizePerSecond, "Maximum size per second for no redirect")
	cmd.Flags().DurationVar(&flags.BlobCacheDuration, "blob-cache-duration", flags.BlobCacheDuration, "Blob cache duration")

	cmd.Flags().StringVar(&flags.DefaultRegistry, "default-registry", flags.DefaultRegistry, "default registry used for non full-path docker pull, like:docker.io")
	cmd.Flags().StringToStringVar(&flags.OverrideDefaultRegistry, "override-default-registry", flags.OverrideDefaultRegistry, "override default registry")
	cmd.Flags().StringToStringVar(&flags.RegistryAlias, "registry-alias", flags.RegistryAlias, "registry alias")

	cmd.Flags().IntVar(&flags.Concurrency, "concurrency", flags.Concurrency, "Concurrency to source")

	cmd.Flags().StringVar(&flags.QueueToken, "queue-token", flags.QueueToken, "Queue token")
	cmd.Flags().StringVar(&flags.QueueURL, "queue-url", flags.QueueURL, "Queue URL")

	return cmd
}

func runE(ctx context.Context, flags *flagpole) error {
	mux := http.NewServeMux()

	gatewayOpts := []gateway.Option{}
	agentOpts := []agent.Option{}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	gatewayOpts = append(gatewayOpts,
		gateway.WithLogger(logger),
		gateway.WithDefaultRegistry(flags.DefaultRegistry),
		gateway.WithOverrideDefaultRegistry(flags.OverrideDefaultRegistry),
		gateway.WithConcurrency(flags.Concurrency),
		gateway.WithPathInfoModifyFunc(func(info *gateway.ImageInfo) *gateway.ImageInfo {
			if len(flags.RegistryAlias) != 0 {
				h, ok := flags.RegistryAlias[info.Host]
				if ok {
					info.Host = h
				}
			}

			info.Host, info.Name = utils.CorrectImage(info.Host, info.Name)
			return info
		}),
		gateway.WithDisableTagsList(flags.DisableTagsList),
	)

	agentOpts = append(agentOpts,
		agent.WithLogger(logger),
		agent.WithConcurrency(flags.Concurrency),
		agent.WithBlobNoRedirectSize(flags.BlobNoRedirectSize),
		agent.WithBlobNoRedirectMaxSizePerSecond(flags.BlobNoRedirectMaxSizePerSecond),
		agent.WithBlobCacheDuration(flags.BlobCacheDuration),
	)

	if flags.StorageURL != "" {
		cacheOpts := []cache.Option{
			cache.WithSignLink(flags.SignLink),
		}

		sd, err := storage.NewStorage(flags.StorageURL)
		if err != nil {
			return fmt.Errorf("create storage driver failed: %w", err)
		}
		cacheOpts = append(cacheOpts, cache.WithStorageDriver(sd))

		if flags.RedirectLinks != "" {
			u, err := url.Parse(flags.RedirectLinks)
			if err != nil {
				return fmt.Errorf("parse redirect links failed: %w", err)
			}
			cacheOpts = append(cacheOpts, cache.WithRedirectLinks(u))
		}

		sdcache, err := cache.NewCache(cacheOpts...)
		if err != nil {
			return fmt.Errorf("create cache failed: %w", err)
		}
		gatewayOpts = append(gatewayOpts,
			gateway.WithCache(sdcache),
			gateway.WithManifestCacheDuration(flags.ManifestCacheDuration),
			gateway.WithRecacheMaxWait(flags.RecacheMaxWaitDuration),
		)

		agentOpts = append(agentOpts,
			agent.WithCache(sdcache),
		)

		if flags.BigStorageURL != "" && flags.BigStorageSize > 0 {
			bigCacheOpts := []cache.Option{}
			sd, err := storage.NewStorage(flags.BigStorageURL)
			if err != nil {
				return fmt.Errorf("create storage driver failed: %w", err)
			}
			bigCacheOpts = append(bigCacheOpts,
				cache.WithSignLink(flags.SignLink),
				cache.WithStorageDriver(sd),
			)
			bigsdcache, err := cache.NewCache(bigCacheOpts...)
			if err != nil {
				return fmt.Errorf("create cache failed: %w", err)
			}
			agentOpts = append(agentOpts, agent.WithBigCache(bigsdcache, flags.BigStorageSize))
		}
	}

	if flags.TokenPublicKeyFile != "" {
		if flags.TokenURL == "" {
			return fmt.Errorf("token url is required")
		}
		publicKeyData, err := os.ReadFile(flags.TokenPublicKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read token public key file: %w", err)
		}
		publicKey, err := pki.DecodePublicKey(publicKeyData)
		if err != nil {
			return fmt.Errorf("failed to decode token public key: %w", err)
		}

		authenticator := token.NewAuthenticator(token.NewDecoder(signing.NewVerifier(publicKey)), flags.TokenURL)
		gatewayOpts = append(gatewayOpts, gateway.WithAuthenticator(authenticator))
		agentOpts = append(agentOpts, agent.WithAuthenticator(authenticator))
	}

	transportOpts := []transport.Option{
		transport.WithUserAndPass(flags.Userpass),
		transport.WithLogger(logger),
	}

	tp, err := transport.NewTransport(transportOpts...)
	if err != nil {
		return fmt.Errorf("create clientset failed: %w", err)
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

	if flags.QueueURL != "" {
		queueClient := client.NewMessageClient(http.DefaultClient, flags.QueueURL, flags.QueueToken)
		gatewayOpts = append(gatewayOpts, gateway.WithQueueClient(queueClient))
		agentOpts = append(agentOpts, agent.WithQueueClient(queueClient))
	}

	tp = transport.NewLogTransport(tp, logger, time.Second)

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
	gatewayOpts = append(gatewayOpts, gateway.WithClient(httpClient))
	agentOpts = append(agentOpts, agent.WithClient(httpClient))

	a, err := agent.NewAgent(
		agentOpts...,
	)
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	gatewayOpts = append(gatewayOpts, gateway.WithAgent(a))

	gw, err := gateway.NewGateway(gatewayOpts...)
	if err != nil {
		return fmt.Errorf("create gateway failed: %w", err)
	}

	if flags.ReadmeURL != "" {
		mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
			http.Redirect(rw, r, flags.ReadmeURL, http.StatusFound)
		})
	}
	mux.Handle("/v2/", gw)

	var handler http.Handler = mux
	handler = handlers.LoggingHandler(os.Stderr, handler)
	if flags.Behind {
		handler = handlers.ProxyHeaders(handler)
	}

	err = server.Run(ctx, flags.Address, handler, flags.AcmeHosts, flags.AcmeCacheDir, flags.CertFile, flags.PrivateKeyFile)
	if err != nil {
		return fmt.Errorf("failed to run server: %w", err)
	}
	return nil
}
