package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/daocloud/crproxy/cache"
	"github.com/daocloud/crproxy/gateway"
	"github.com/daocloud/crproxy/internal/pki"
	"github.com/daocloud/crproxy/internal/server"
	"github.com/daocloud/crproxy/signing"
	"github.com/daocloud/crproxy/storage"
	"github.com/daocloud/crproxy/token"
	"github.com/daocloud/crproxy/transport"
	"github.com/gorilla/handlers"
	"github.com/spf13/cobra"
)

type flagpole struct {
	StorageURL string

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

	BlobsLENoAgent int

	DefaultRegistry         string
	OverrideDefaultRegistry map[string]string

	RegistryAlias map[string]string

	Concurrency int
}

func NewCommand() *cobra.Command {
	flags := &flagpole{
		Address:     ":18001",
		Concurrency: 10,
	}

	cmd := &cobra.Command{
		Use:   "gateway",
		Short: "Gateway",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd.Context(), flags)
		},
	}

	cmd.Flags().StringVar(&flags.StorageURL, "storage-url", flags.StorageURL, "Storage driver url")
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

	cmd.Flags().IntVar(&flags.BlobsLENoAgent, "blobs-le-no-agent", flags.BlobsLENoAgent, "Less than or equal to No Agent")

	cmd.Flags().StringVar(&flags.DefaultRegistry, "default-registry", flags.DefaultRegistry, "default registry used for non full-path docker pull, like:docker.io")
	cmd.Flags().StringToStringVar(&flags.OverrideDefaultRegistry, "override-default-registry", flags.OverrideDefaultRegistry, "override default registry")
	cmd.Flags().StringToStringVar(&flags.RegistryAlias, "registry-alias", flags.RegistryAlias, "registry alias")

	cmd.Flags().IntVar(&flags.Concurrency, "concurrency", flags.Concurrency, "Concurrency to source")
	return cmd
}

func runE(ctx context.Context, flags *flagpole) error {
	mux := http.NewServeMux()

	opts := []gateway.Option{}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	opts = append(opts,
		gateway.WithLogger(logger),
		gateway.WithBlobsLENoAgent(flags.BlobsLENoAgent),
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

			if info.Host == "docker.io" {
				info.Host = "registry-1.docker.io"
			} else if info.Host == "ollama.ai" {
				info.Host = "registry.ollama.ai"
			}

			// docker.io/busybox => docker.io/library/busybox
			if info.Host == "registry-1.docker.io" && !strings.Contains(info.Name, "/") {
				info.Name = "library/" + info.Name
			}
			if info.Host == "registry.ollama.ai" && !strings.Contains(info.Name, "/") {
				info.Name = "library/" + info.Name
			}
			return info
		}),
		gateway.WithDisableTagsList(flags.DisableTagsList),
	)

	if flags.StorageURL != "" {
		cacheOpts := []cache.Option{}

		sd, err := storage.NewStorage(flags.StorageURL)
		if err != nil {
			return fmt.Errorf("create storage driver failed: %w", err)
		}
		cacheOpts = append(cacheOpts, cache.WithStorageDriver(sd))

		cache, err := cache.NewCache(cacheOpts...)
		if err != nil {
			return fmt.Errorf("create cache failed: %w", err)
		}
		opts = append(opts, gateway.WithCache(cache))
		opts = append(opts, gateway.WithManifestCacheDuration(flags.ManifestCacheDuration))
		opts = append(opts, gateway.WithRecacheMaxWait(flags.RecacheMaxWaitDuration))
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
		opts = append(opts, gateway.WithAuthenticator(authenticator))
	}

	transportOpts := []transport.Option{
		transport.WithUserAndPass(flags.Userpass),
		transport.WithLogger(logger),
	}

	tp, err := transport.NewTransport(transportOpts...)
	if err != nil {
		return fmt.Errorf("create clientset failed: %w", err)
	}

	tp = transport.NewLogTransport(tp, logger, time.Second)

	client := &http.Client{
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
	opts = append(opts, gateway.WithClient(client))

	a, err := gateway.NewGateway(opts...)
	if err != nil {
		return fmt.Errorf("create gateway failed: %w", err)
	}

	if flags.ReadmeURL != "" {
		mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
			http.Redirect(rw, r, flags.ReadmeURL, http.StatusFound)
		})
	}
	mux.Handle("/v2/", a)

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
