package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/spf13/pflag"
	"github.com/wzshiming/geario"

	"github.com/wzshiming/crproxy"
)

var (
	address              string
	userpass             []string
	blobsSpeedLimit      string
	totalBlobsSpeedLimit string
)

func init() {
	pflag.StringSliceVarP(&userpass, "user", "u", nil, "host and username and password -u user:pwd@host")
	pflag.StringVarP(&address, "address", "a", ":8080", "listen on the address")
	pflag.StringVar(&blobsSpeedLimit, "blobs-speed-limit", "", "blobs speed limit per second (default unlimited)")
	pflag.StringVar(&totalBlobsSpeedLimit, "total-blobs-speed-limit", "", "total blobs speed limit per second (default unlimited)")
	pflag.Parse()
}

func toUserAndPass(userpass []string) (map[string]crproxy.Userpass, error) {
	bc := map[string]crproxy.Userpass{}
	for _, up := range userpass {
		s := strings.SplitN(up, "@", 3)
		if len(s) != 2 {
			return nil, fmt.Errorf("invalid userpass %q", up)
		}

		u := strings.SplitN(s[0], ":", 3)
		if len(s) != 2 {
			return nil, fmt.Errorf("invalid userpass %q", up)
		}
		host := s[1]
		user := u[0]
		pwd := u[1]
		bc[host] = crproxy.Userpass{
			Username: user,
			Password: pwd,
		}
	}
	return bc, nil
}

func main() {
	ctx := context.Background()
	logger := log.New(os.Stderr, "[cr proxy] ", log.LstdFlags)

	mux := http.NewServeMux()
	cli := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 10 {
				return http.ErrUseLastResponse
			}
			s := make([]string, 0, len(via)+1)
			for _, v := range via {
				s = append(s, v.URL.String())
			}
			s = append(s, req.URL.String())
			logger.Println("redirect", s)
			return nil
		},
	}

	opts := []crproxy.Option{
		crproxy.WithBaseClient(cli),
		crproxy.WithLogger(logger),
		crproxy.WithMaxClientSizeForEachRegistry(16),
		crproxy.WithDomainAlias(map[string]string{
			"docker.io": "registry-1.docker.io",
		}),
		crproxy.WithPathInfoModifyFunc(func(info *crproxy.PathInfo) *crproxy.PathInfo {
			// docker.io/busybox => docker.io/library/busybox
			if info.Host == "registry-1.docker.io" && !strings.Contains(info.Image, "/") {
				info.Image = "library/" + info.Image
			}
			return info
		}),
	}

	if len(userpass) != 0 {
		bc, err := toUserAndPass(userpass)
		if err != nil {
			logger.Println("failed to toUserAndPass", err)
			os.Exit(1)
		}
		opts = append(opts, crproxy.WithUserAndPass(bc))
	}

	if blobsSpeedLimit != "" {
		b, err := geario.FromHumanSize(blobsSpeedLimit)
		if err != nil {
			logger.Println("failed to FromHumanSize:", err)
			os.Exit(1)
		}
		opts = append(opts, crproxy.WithBlobsSpeedLimit(b))
	}

	if totalBlobsSpeedLimit != "" {
		b, err := geario.FromHumanSize(totalBlobsSpeedLimit)
		if err != nil {
			logger.Println("failed to FromHumanSize:", err)
			os.Exit(1)
		}
		opts = append(opts, crproxy.WithTotalBlobsSpeedLimit(b))
	}

	crp, err := crproxy.NewCRProxy(opts...)
	if err != nil {
		logger.Println("failed to NewCRProxy:", err)
		os.Exit(1)
	}

	mux.Handle("/v2/", crp)
	server := http.Server{
		BaseContext: func(listener net.Listener) context.Context {
			return ctx
		},
		Handler: handlers.LoggingHandler(os.Stderr, mux),
		Addr:    address,
	}

	err = server.ListenAndServe()
	if err != nil {
		logger.Println("failed to ListenAndServe:", err)
		os.Exit(1)
	}
}
