package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver/factory"
	"github.com/gorilla/handlers"
	"github.com/spf13/pflag"
	"github.com/wzshiming/geario"

	_ "github.com/daocloud/crproxy/storage/driver/oss"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/azure"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/gcs"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/s3-aws"

	"github.com/daocloud/crproxy"
)

var (
	behind               bool
	address              string
	userpass             []string
	disableKeepAlives    []string
	limitDelay           bool
	blobsSpeedLimit      string
	ipsSpeedLimit        string
	totalBlobsSpeedLimit string
	allowHostList        []string
	blockImageList       []string
	privilegedIPList     []string
	retry                int
	retryInterval        time.Duration
	storageDriver        string
	storageParameters    map[string]string
	linkExpires          time.Duration
	redirectLinks        string
	disableTagsList      bool
	enablePprof          bool
	defaultRegistry      string
)

func init() {
	pflag.BoolVar(&behind, "behind", false, "Behind the reverse proxy")
	pflag.StringSliceVarP(&userpass, "user", "u", nil, "host and username and password -u user:pwd@host")
	pflag.StringVarP(&address, "address", "a", ":8080", "listen on the address")
	pflag.StringSliceVar(&disableKeepAlives, "disable-keep-alives", nil, "disable keep alives for the host")
	pflag.BoolVar(&limitDelay, "limit-delay", false, "limit with delay")
	pflag.StringVar(&blobsSpeedLimit, "blobs-speed-limit", "", "blobs speed limit per second (default unlimited)")
	pflag.StringVar(&ipsSpeedLimit, "ips-speed-limit", "", "ips speed limit per second (default unlimited)")
	pflag.StringVar(&totalBlobsSpeedLimit, "total-blobs-speed-limit", "", "total blobs speed limit per second (default unlimited)")
	pflag.StringSliceVar(&allowHostList, "allow-host-list", nil, "allow host list")
	pflag.StringSliceVar(&blockImageList, "block-image-list", nil, "block image list")
	pflag.StringSliceVar(&privilegedIPList, "privileged-ip-list", nil, "privileged IP list")
	pflag.IntVar(&retry, "retry", 0, "retry times")
	pflag.DurationVar(&retryInterval, "retry-interval", 0, "retry interval")
	pflag.StringVar(&storageDriver, "storage-driver", "", "storage driver")
	pflag.StringToStringVar(&storageParameters, "storage-parameters", nil, "storage parameters")
	pflag.DurationVar(&linkExpires, "link-expires", 0, "link expires")
	pflag.StringVar(&redirectLinks, "redirect-links", "", "redirect links")
	pflag.BoolVar(&disableTagsList, "disable-tags-list", false, "disable tags list")
	pflag.BoolVar(&enablePprof, "enable-pprof", false, "Enable pprof")
	pflag.StringVar(&defaultRegistry, "default-registry", "", "default registry used for non full-path docker pull, like:docker.io")
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
			"ollama.ai": "registry.ollama.ai",
		}),
		crproxy.WithPathInfoModifyFunc(func(info *crproxy.ModifyInfo) *crproxy.ModifyInfo {
			// docker.io/busybox => docker.io/library/busybox
			if info.Host == "registry-1.docker.io" && !strings.Contains(info.Image, "/") {
				info.Image = "library/" + info.Image
			}
			if info.Host == "registry.ollama.ai" && !strings.Contains(info.Image, "/") {
				info.Image = "library/" + info.Image
			}
			return info
		}),
		crproxy.WithDisableKeepAlives(disableKeepAlives),
	}

	if storageDriver != "" {
		parameters := map[string]interface{}{}
		for k, v := range storageParameters {
			parameters[k] = v
		}
		sd, err := factory.Create(storageDriver, parameters)
		if err != nil {
			logger.Println("create storage driver failed:", err)
			os.Exit(1)
		}
		opts = append(opts, crproxy.WithStorageDriver(sd))
		if linkExpires > 0 {
			opts = append(opts, crproxy.WithLinkExpires(linkExpires))
		}
		if redirectLinks != "" {
			u, err := url.Parse(redirectLinks)
			if err != nil {
				logger.Println("parse redirect links failed:", err)
				os.Exit(1)
			}
			opts = append(opts, crproxy.WithRedirectLinks(u))
		}
	}

	if len(blockImageList) != 0 || len(allowHostList) != 0 {
		allowHostMap := map[string]struct{}{}
		for _, host := range allowHostList {
			allowHostMap[host] = struct{}{}
		}
		blockImageMap := map[string]struct{}{}
		for _, image := range blockImageList {
			blockImageMap[image] = struct{}{}
		}
		opts = append(opts, crproxy.WithBlockFunc(func(info *crproxy.PathInfo) bool {
			if len(allowHostMap) != 0 {
				_, ok := allowHostMap[info.Host]
				if !ok {
					return true
				}
			}

			if len(blockImageMap) != 0 {
				image := info.Host + "/" + info.Image
				_, ok := blockImageMap[image]
				if ok {
					return true
				}
			}

			return false
		}))
	}

	if len(privilegedIPList) != 0 {
		opts = append(opts, crproxy.WithPrivilegedIPs(privilegedIPList))
	}

	if len(userpass) != 0 {
		bc, err := toUserAndPass(userpass)
		if err != nil {
			logger.Println("failed to toUserAndPass", err)
			os.Exit(1)
		}
		opts = append(opts, crproxy.WithUserAndPass(bc))
	}

	if ipsSpeedLimit != "" {
		b, d, err := getLimit(ipsSpeedLimit)
		if err != nil {
			logger.Println("failed to getLimit:", err)
			os.Exit(1)
		}
		opts = append(opts, crproxy.WithIPsSpeedLimit(b, d))
	}

	if blobsSpeedLimit != "" {
		b, d, err := getLimit(blobsSpeedLimit)
		if err != nil {
			logger.Println("failed to getLimit:", err)
			os.Exit(1)
		}
		opts = append(opts, crproxy.WithBlobsSpeedLimit(b, d))
	}

	if totalBlobsSpeedLimit != "" {
		b, err := geario.FromBytesSize(totalBlobsSpeedLimit)
		if err != nil {
			logger.Println("failed to FromBytesSize:", err)
			os.Exit(1)
		}
		opts = append(opts, crproxy.WithTotalBlobsSpeedLimit(b))
	}

	if disableTagsList {
		opts = append(opts, crproxy.WithDisableTagsList(true))
	}

	if retry > 0 {
		opts = append(opts, crproxy.WithRetry(retry, retryInterval))
	}
	if limitDelay {
		opts = append(opts, crproxy.WithLimitDelay(true))
	}

	if defaultRegistry != "" {
		opts = append(opts, crproxy.WithDefaultRegistry(defaultRegistry))
	}

	crp, err := crproxy.NewCRProxy(opts...)
	if err != nil {
		logger.Println("failed to NewCRProxy:", err)
		os.Exit(1)
	}

	mux.Handle("/v2/", crp)

	mux.HandleFunc("/internal/api/image/sync", crp.Sync)

	if enablePprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	var handler http.Handler = mux
	handler = handlers.LoggingHandler(os.Stderr, handler)
	if behind {
		handler = handlers.ProxyHeaders(handler)
	}
	server := http.Server{
		BaseContext: func(listener net.Listener) context.Context {
			return ctx
		},
		Handler: handler,
		Addr:    address,
	}

	err = server.ListenAndServe()
	if err != nil {
		logger.Println("failed to ListenAndServe:", err)
		os.Exit(1)
	}
}

func getLimit(s string) (geario.B, time.Duration, error) {
	i := strings.Index(s, "/")
	if i == -1 {
		b, err := geario.FromBytesSize(s)
		if err != nil {
			return 0, 0, err
		}
		return b, time.Second, nil
	}

	b, err := geario.FromBytesSize(s[:i])
	if err != nil {
		return 0, 0, err
	}

	dur := s[i+1:]
	if dur[0] < '0' || dur[0] > '9' {
		dur = "1" + dur
	}

	d, err := time.ParseDuration(dur)
	if err != nil {
		return 0, 0, err
	}

	return b, d, nil
}
