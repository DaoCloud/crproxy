package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/daocloud/crproxy/agent"
	"github.com/daocloud/crproxy/cache"
	"github.com/daocloud/crproxy/internal/pki"
	"github.com/daocloud/crproxy/internal/server"
	"github.com/daocloud/crproxy/signing"
	"github.com/daocloud/crproxy/token"
	"github.com/daocloud/crproxy/transport"
	"github.com/docker/distribution/registry/storage/driver/factory"
	"github.com/gorilla/handlers"
	"github.com/spf13/cobra"
)

type flagpole struct {
	StorageDriver     string
	StorageParameters map[string]string
	LinkExpires       time.Duration

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
}

func NewCommand() *cobra.Command {
	flags := &flagpole{
		Address: ":18002",
	}

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd.Context(), flags)
		},
	}

	cmd.Flags().StringVar(&flags.StorageDriver, "storage-driver", flags.StorageDriver, "Storage driver")
	cmd.Flags().StringToStringVar(&flags.StorageParameters, "storage-parameters", flags.StorageParameters, "Storage parameters")
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

	return cmd
}

func runE(ctx context.Context, flags *flagpole) error {
	mux := http.NewServeMux()

	opts := []agent.Option{}

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
	if flags.LinkExpires > 0 {
		cacheOpts = append(cacheOpts, cache.WithLinkExpires(flags.LinkExpires))
	}

	cache, err := cache.NewCache(cacheOpts...)
	if err != nil {
		return fmt.Errorf("create cache failed: %w", err)
	}

	opts = append(opts,
		agent.WithCache(cache),
		agent.WithLogger(logger),
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
		transport.WithLogger(logger),
	}

	tp, err := transport.NewTransport(transportOpts...)
	if err != nil {
		return fmt.Errorf("create clientset failed: %w", err)
	}

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
