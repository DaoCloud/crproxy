package auth

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"

	_ "github.com/go-sql-driver/mysql"

	"github.com/daocloud/crproxy/internal/pki"
	"github.com/daocloud/crproxy/internal/server"
	"github.com/daocloud/crproxy/manager"
	"github.com/daocloud/crproxy/signing"
	"github.com/daocloud/crproxy/token"
	"github.com/emicklei/go-restful/v3"
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
	TokenExpiresSecond  int

	SimpleAuthUserpass map[string]string

	AllowAnonymous              bool
	AnonymousRateLimitPerSecond uint64
	AnonymousNoAllowlist        bool

	AdminToken string

	BlobsURLs []string

	DBURL string
}

func NewCommand() *cobra.Command {
	flags := &flagpole{
		Address:            ":18000",
		TokenExpiresSecond: 3600,
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
	cmd.Flags().IntVar(&flags.TokenExpiresSecond, "token-expires-second", flags.TokenExpiresSecond, "Token expires second")

	cmd.Flags().StringToStringVar(&flags.SimpleAuthUserpass, "simple-auth-userpass", flags.SimpleAuthUserpass, "Simple auth userpass")

	cmd.Flags().BoolVar(&flags.AllowAnonymous, "allow-anonymous", flags.AllowAnonymous, "Allow anonymous")
	cmd.Flags().Uint64Var(&flags.AnonymousRateLimitPerSecond, "anonymous-rate-limit-per-second", flags.AnonymousRateLimitPerSecond, "Rate limit for anonymous users per second")

	cmd.Flags().StringVar(&flags.AdminToken, "admin-token", flags.AdminToken, "Admin token")

	cmd.Flags().StringSliceVar(&flags.BlobsURLs, "blobs-url", flags.BlobsURLs, "Blobs urls")

	cmd.Flags().StringVar(&flags.DBURL, "db-url", flags.DBURL, "Database URL")

	return cmd
}

func runE(ctx context.Context, flags *flagpole) error {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	var privateKey *rsa.PrivateKey
	var err error
	if flags.TokenPrivateKeyFile != "" {
		privateKeyData, err := os.ReadFile(flags.TokenPrivateKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read token private key file: %w", err)
		}
		privateKey, err = pki.DecodePrivateKey(privateKeyData)
		if err != nil {
			return fmt.Errorf("failed to decode private key: %w", err)
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

	} else {
		privateKey, err = pki.GenerateKey()
		if err != nil {
			return fmt.Errorf("failed to generate private key: %w", err)
		}
	}

	container := restful.NewContainer()

	var mgr *manager.Manager
	if flags.DBURL != "" {
		dburl := flags.DBURL
		db, err := sql.Open("mysql", dburl)
		if err != nil {
			return fmt.Errorf("failed to connect to database: %w", err)
		}
		defer db.Close()

		if err = db.Ping(); err != nil {
			return fmt.Errorf("failed to ping database: %w", err)
		}

		logger.Info("Connected to DB")

		mgr = manager.NewManager(privateKey, flags.AdminToken, db)

		mgr.Register(container)

		mgr.InitTable(ctx)
	}

	getHosts := getBlobsURLs(flags.BlobsURLs)

	authFunc := func(r *http.Request, userinfo *url.Userinfo, t *token.Token) (token.Attribute, bool) {
		var has bool
		if userinfo != nil && flags.SimpleAuthUserpass != nil {
			pass, ok := flags.SimpleAuthUserpass[userinfo.Username()]
			if ok {
				upass, ok := userinfo.Password()
				if !ok {
					return token.Attribute{}, false
				}
				if upass != pass {
					return token.Attribute{}, false
				}
				t.NoRateLimit = true
				t.NoAllowlist = true
				t.NoBlock = true
				t.AllowTagsList = true
				has = true
			}
		}

		if !has {
			if mgr == nil {
				if userinfo == nil {
					if !flags.AllowAnonymous {
						return token.Attribute{}, false
					}
					t.RateLimitPerSecond = flags.AnonymousRateLimitPerSecond

					if !t.Block && !t.NoBlobsAgent {
						t.BlobsAgentURL = getHosts()
					}
					return t.Attribute, true
				}
				return token.Attribute{}, false
			}

			attr, err := mgr.GetTokenWithUser(r.Context(), userinfo, t)
			if err != nil {
				logger.Info("Failed to retrieve token", "user", userinfo, "err", err)
				return token.Attribute{}, false
			}
			t.Attribute = attr
		}

		if !t.Block && !t.NoBlobsAgent {
			if t.BlobsAgentURL == "" {
				t.BlobsAgentURL = getHosts()
			}
		}

		return t.Attribute, true
	}

	gen := token.NewGenerator(token.NewEncoder(signing.NewSigner(privateKey)), authFunc, flags.TokenExpiresSecond, logger)
	container.Handle("/auth/token", gen)

	var handler http.Handler = container

	handler = handlers.LoggingHandler(os.Stderr, handler)

	if flags.Behind {
		handler = handlers.ProxyHeaders(handler)
	}

	handler = handlers.CORS(
		handlers.AllowedMethods([]string{http.MethodHead, http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete}),
		handlers.AllowedHeaders([]string{"Authorization", "Accept", "Content-Type", "Origin"}),
		handlers.AllowedOrigins([]string{"*"}),
	)(handler)

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
