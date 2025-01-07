package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/daocloud/crproxy/agent"
	"github.com/daocloud/crproxy/cache"
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
	StorageURL    string
	RedirectLinks string
	LinkExpires   time.Duration

	Userpass      []string
	Retry         int
	RetryInterval time.Duration

	Behind         bool
	Address        string
	AcmeHosts      []string
	AcmeCacheDir   string
	CertFile       string
	PrivateKeyFile string

	TokenPublicKeyFile string
	TokenURL           string

	BlobsLENoAgent    int
	BlobCacheDuration time.Duration
}

func NewCommand() *cobra.Command {
	flags := &flagpole{
		Address:           ":18002",
		BlobCacheDuration: time.Hour,
	}

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd.Context(), flags)
		},
	}

	cmd.Flags().StringVar(&flags.StorageURL, "storage-url", flags.StorageURL, "Storage driver url")
	cmd.Flags().StringVar(&flags.RedirectLinks, "redirect-links", flags.RedirectLinks, "Redirect links")
	cmd.Flags().DurationVar(&flags.LinkExpires, "link-expires", flags.LinkExpires, "Link expires")

	cmd.Flags().StringSliceVarP(&flags.Userpass, "user", "u", flags.Userpass, "host and username and password -u user:pwd@host")
	cmd.Flags().IntVar(&flags.Retry, "retry", flags.Retry, "Retry")
	cmd.Flags().DurationVar(&flags.RetryInterval, "retry-interval", flags.RetryInterval, "Retry interval")

	cmd.Flags().BoolVar(&flags.Behind, "behind", flags.Behind, "Behind")
	cmd.Flags().StringVar(&flags.Address, "address", flags.Address, "Address")
	cmd.Flags().StringSliceVar(&flags.AcmeHosts, "acme-hosts", flags.AcmeHosts, "Acme hosts")
	cmd.Flags().StringVar(&flags.AcmeCacheDir, "acme-cache-dir", flags.AcmeCacheDir, "Acme cache dir")
	cmd.Flags().StringVar(&flags.CertFile, "cert-file", flags.CertFile, "Cert file")
	cmd.Flags().StringVar(&flags.PrivateKeyFile, "private-key-file", flags.PrivateKeyFile, "Private key file")

	cmd.Flags().StringVar(&flags.TokenPublicKeyFile, "token-public-key-file", flags.TokenPublicKeyFile, "Token public key file")
	cmd.Flags().StringVar(&flags.TokenURL, "token-url", flags.TokenURL, "Token url")

	cmd.Flags().IntVar(&flags.BlobsLENoAgent, "blobs-le-no-agent", flags.BlobsLENoAgent, "Less than or equal to No Agent")
	cmd.Flags().DurationVar(&flags.BlobCacheDuration, "blob-cache-duration", flags.BlobCacheDuration, "Blob cache duration")
	return cmd
}

func runE(ctx context.Context, flags *flagpole) error {
	mux := http.NewServeMux()

	opts := []agent.Option{}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cacheOpts := []cache.Option{}

	sd, err := storage.NewStorage(flags.StorageURL)
	if err != nil {
		return fmt.Errorf("create storage driver failed: %w", err)
	}
	cacheOpts = append(cacheOpts, cache.WithStorageDriver(sd))
	if flags.LinkExpires > 0 {
		cacheOpts = append(cacheOpts, cache.WithLinkExpires(flags.LinkExpires))
	}

	if flags.RedirectLinks != "" {
		u, err := url.Parse(flags.RedirectLinks)
		if err != nil {
			return fmt.Errorf("parse redirect links failed: %w", err)
		}
		cacheOpts = append(cacheOpts, cache.WithRedirectLinks(u))
	}

	cache, err := cache.NewCache(cacheOpts...)
	if err != nil {
		return fmt.Errorf("create cache failed: %w", err)
	}

	opts = append(opts,
		agent.WithCache(cache),
		agent.WithLogger(logger),
		agent.WithBlobsLENoAgent(flags.BlobsLENoAgent),
		agent.WithBlobCacheDuration(flags.BlobCacheDuration),
	)

	if flags.TokenPublicKeyFile != "" {
		publicKeyData, err := os.ReadFile(flags.TokenPublicKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read token public key file: %w", err)
		}
		publicKey, err := pki.DecodePublicKey(publicKeyData)
		if err != nil {
			return fmt.Errorf("failed to decode token public key: %w", err)
		}

		authenticator := token.NewAuthenticator(token.NewDecoder(signing.NewVerifier(publicKey)), flags.TokenURL)
		opts = append(opts, agent.WithAuthenticator(authenticator))
	}

	transportOpts := []transport.Option{
		transport.WithUserAndPass(flags.Userpass),
		transport.WithLogger(logger),
	}

	tp, err := transport.NewTransport(transportOpts...)
	if err != nil {
		return fmt.Errorf("create clientset failed: %w", err)
	}

	tp = transport.NewLogTransport(tp, logger, time.Minute)

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
	opts = append(opts, agent.WithClient(client))

	a, err := agent.NewAgent(opts...)
	if err != nil {
		return fmt.Errorf("create agent failed: %w", err)
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
