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
	"time"

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

	SimpleAuthUserpass map[string]string

	AllowAnonymous              bool
	AnonymousRateLimitPerSecond uint64

	BlobsURLs []string

	DBURL string
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

		mgr = manager.NewManager(privateKey, db, 1*time.Minute)

		mgr.Register(container)

		mgr.InitTable(ctx)
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

		if mgr != nil {
			attr, err := mgr.GetToken(r.Context(), userinfo, t)
			if err != nil {
				logger.Info("Failed to retrieve token", "user", userinfo, "err", err)
				return token.Attribute{}, false
			}
			t.Attribute = attr
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
	container.Handle("/auth/token", gen)

	var handler http.Handler = container
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
