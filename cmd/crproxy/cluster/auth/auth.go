package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"

	"github.com/daocloud/crproxy/internal/pki"
	"github.com/daocloud/crproxy/internal/server"
	"github.com/daocloud/crproxy/signing"
	"github.com/daocloud/crproxy/token"
	"github.com/gorilla/handlers"
	"github.com/spf13/cobra"
)

type flagpole struct {
	Behind         bool
	Address        string
	AcmeHosts      []string
	AcmeCacheDir   string
	CertFile       string
	PrivateKeyFile string

	TokenPrivateKeyFile string
	TokenPublicKeyFile  string

	SimpleAuthUserpass map[string]string

	AllowAnonymous              bool
	AnonymousRateLimitPerSecond uint64

	BlobsURLs []string

	WebhookURL string
}

func NewCommand() *cobra.Command {
	flags := &flagpole{
		Address: ":18000",
	}

	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Auth",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd.Context(), flags)
		},
	}

	cmd.Flags().BoolVar(&flags.Behind, "behind", flags.Behind, "Behind")
	cmd.Flags().StringVar(&flags.Address, "address", flags.Address, "Address")
	cmd.Flags().StringSliceVar(&flags.AcmeHosts, "acme-hosts", flags.AcmeHosts, "Acme hosts")
	cmd.Flags().StringVar(&flags.AcmeCacheDir, "acme-cache-dir", flags.AcmeCacheDir, "Acme cache dir")
	cmd.Flags().StringVar(&flags.CertFile, "cert-file", flags.CertFile, "Cert file")
	cmd.Flags().StringVar(&flags.PrivateKeyFile, "private-key-file", flags.PrivateKeyFile, "Private key file")

	cmd.Flags().StringVar(&flags.TokenPrivateKeyFile, "token-private-key-file", "", "private key file")
	cmd.Flags().StringVar(&flags.TokenPublicKeyFile, "token-public-key-file", "", "public key file")

	cmd.Flags().StringToStringVar(&flags.SimpleAuthUserpass, "simple-auth-userpass", flags.SimpleAuthUserpass, "Simple auth userpass")

	cmd.Flags().BoolVar(&flags.AllowAnonymous, "allow-anonymous", flags.AllowAnonymous, "Allow anonymous")

	cmd.Flags().StringSliceVar(&flags.BlobsURLs, "blobs-url", flags.BlobsURLs, "Blobs urls")

	cmd.Flags().StringVar(&flags.WebhookURL, "webhook-url", flags.WebhookURL, "Webhook url")

	return cmd
}

func runE(ctx context.Context, flags *flagpole) error {
	mux := http.NewServeMux()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	privateKeyData, err := os.ReadFile(flags.TokenPrivateKeyFile)
	if err != nil {
		logger.Error("failed to ReadFile", "file", flags.TokenPrivateKeyFile, "error", err)
		os.Exit(1)
	}
	privateKey, err := pki.DecodePrivateKey(privateKeyData)
	if err != nil {
		logger.Error("failed to DecodePrivateKey", "file", flags.TokenPrivateKeyFile, "error", err)
		os.Exit(1)
	}

	if flags.TokenPublicKeyFile != "" {
		publicKeyData, err := pki.EncodePublicKey(&privateKey.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to encode public key: %w", err)
		}

		err = os.WriteFile(flags.TokenPublicKeyFile, publicKeyData, 0644)
		if err != nil {
			return fmt.Errorf("failed to write token public key file: %w", err)
		}
	}

	getHosts := getBlobsURLs(flags.BlobsURLs)

	authFunc := func(r *http.Request, userinfo *url.Userinfo, t *token.Token) (token.Attribute, bool) {
		if userinfo == nil {
			if !flags.AllowAnonymous {
				return token.Attribute{}, false
			}
			t.RateLimitPerSecond = flags.AnonymousRateLimitPerSecond

			if !t.Block {
				t.BlobsURL = getHosts()
			}
			return t.Attribute, true
		}
		if flags.SimpleAuthUserpass == nil {
			return token.Attribute{}, false
		}
		pass, ok := flags.SimpleAuthUserpass[userinfo.Username()]
		if !ok {
			return token.Attribute{}, false
		}
		upass, ok := userinfo.Password()
		if !ok {
			return token.Attribute{}, false
		}
		if upass != pass {
			return token.Attribute{}, false
		}

		if flags.WebhookURL != "" {
			body, _ := json.Marshal(t)
			wu, err := url.Parse(flags.WebhookURL)
			if err != nil {
				logger.Error("failed to parse webhook url", "url", flags.WebhookURL, "error", err)
				return token.Attribute{}, false
			}
			wu.User = userinfo

			resp, err := http.Post(wu.String(), "application/json", bytes.NewBuffer(body))
			if err != nil {
				logger.Error("failed to post webhook", "url", flags.WebhookURL, "error", err)
				return token.Attribute{}, false
			}
			defer resp.Body.Close()

			switch resp.StatusCode {
			case http.StatusOK:
				err = json.NewDecoder(resp.Body).Decode(&t)
				if err != nil {
					logger.Error("failed to decode webhook response", "url", flags.WebhookURL, "error", err)
					return token.Attribute{}, false
				}
			case http.StatusForbidden:
				return token.Attribute{}, false
			default:
				logger.Error("failed to post webhook", "url", flags.WebhookURL, "status", resp.StatusCode)
				return token.Attribute{}, false
			}
		} else {
			t.NoRateLimit = true
			t.NoAllowlist = true
			t.NoBlock = true
			t.AllowTagsList = true
		}

		if !t.Block {
			if t.BlobsURL == "" {
				t.BlobsURL = getHosts()
			}
		}

		return t.Attribute, true
	}

	gen := token.NewGenerator(token.NewEncoder(signing.NewSigner(privateKey)), authFunc, logger)
	mux.Handle("/auth/token", gen)

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

func getBlobsURLs(urls []string) func() string {
	if len(urls) == 0 {
		return func() string {
			return ""
		}
	}
	var index uint64
	return func() string {
		n := atomic.AddUint64(&index, 1)
		return urls[n%uint64(len(urls))]
	}
}
