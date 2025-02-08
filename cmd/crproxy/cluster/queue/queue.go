package queue

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	_ "github.com/go-sql-driver/mysql"

	"github.com/daocloud/crproxy/internal/server"
	"github.com/daocloud/crproxy/queue"
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

	TokenPublicKeyFile string

	SimpleAuthUserpass map[string]string

	AllowAnonymousRead bool

	AdminToken string

	DBURL string
}

func NewCommand() *cobra.Command {
	flags := &flagpole{
		Address: ":18010",
	}

	cmd := &cobra.Command{
		Use:   "queue",
		Short: "Queue",
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

	cmd.Flags().StringVar(&flags.TokenPublicKeyFile, "token-public-key-file", "", "public key file")

	cmd.Flags().StringVar(&flags.AdminToken, "admin-token", flags.AdminToken, "Admin token")

	cmd.Flags().StringVar(&flags.DBURL, "db-url", flags.DBURL, "Database URL")

	cmd.Flags().BoolVar(&flags.AllowAnonymousRead, "allow-anonymous-read", flags.AllowAnonymousRead, "Allow anonymous read access")
	return cmd
}

func runE(ctx context.Context, flags *flagpole) error {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	container := restful.NewContainer()

	var mgr *queue.QueueManager
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

		mgr = queue.NewQueueManager(flags.AdminToken, flags.AllowAnonymousRead, db)

		mgr.Register(container)

		mgr.InitTable(ctx)

		mgr.Schedule(ctx, logger)
	}

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

	err := server.Run(ctx, flags.Address, handler, flags.AcmeHosts, flags.AcmeCacheDir, flags.CertFile, flags.PrivateKeyFile)
	if err != nil {
		return fmt.Errorf("failed to run server: %w", err)
	}
	return nil
}
