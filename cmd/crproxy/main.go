package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver/factory"
	"github.com/gorilla/handlers"
	"github.com/spf13/pflag"
	"github.com/wzshiming/geario"
	"github.com/wzshiming/hostmatcher"

	_ "github.com/daocloud/crproxy/storage/driver/oss"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/azure"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/gcs"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/s3-aws"

	"github.com/daocloud/crproxy"
	"github.com/daocloud/crproxy/internal/server"
)

var (
	behind                      bool
	address                     string
	userpass                    []string
	disableKeepAlives           []string
	limitDelay                  bool
	blobsSpeedLimit             string
	ipsSpeedLimit               string
	totalBlobsSpeedLimit        string
	allowHostList               []string
	allowImageListFromFile      string
	blockImageList              []string
	blockMessage                string
	privilegedIPList            []string
	privilegedImageListFromFile string
	privilegedNoAuth            bool
	retry                       int
	retryInterval               time.Duration
	storageDriver               string
	storageParameters           map[string]string
	linkExpires                 time.Duration
	redirectLinks               string
	disableTagsList             bool
	enablePprof                 bool
	defaultRegistry             string
	overrideDefaultRegistry     map[string]string
	simpleAuth                  bool
	simpleAuthUserpass          map[string]string
	tokenURL                    string
	tokenAuthForceTLS           bool

	redirectOriginBlobLinks bool

	acmeHosts      []string
	acmeCacheDir   string
	certFile       string
	privateKeyFile string

	enableInternalAPI bool

	readmeURL string
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
	pflag.StringVar(&allowImageListFromFile, "allow-image-list-from-file", "", "allow image list from file")
	pflag.StringSliceVar(&blockImageList, "block-image-list", nil, "block image list")
	pflag.StringVar(&blockMessage, "block-message", "", "block message")
	pflag.StringSliceVar(&privilegedIPList, "privileged-ip-list", nil, "privileged IP list")
	pflag.BoolVar(&privilegedNoAuth, "privileged-no-auth", false, "privileged no auth (deprecated)")
	pflag.StringVar(&privilegedImageListFromFile, "privileged-image-list-from-file", "", "privileged image list from file")
	pflag.IntVar(&retry, "retry", 0, "retry times")
	pflag.DurationVar(&retryInterval, "retry-interval", 0, "retry interval")
	pflag.StringVar(&storageDriver, "storage-driver", "", "storage driver")
	pflag.StringToStringVar(&storageParameters, "storage-parameters", nil, "storage parameters")
	pflag.DurationVar(&linkExpires, "link-expires", 0, "link expires")
	pflag.StringVar(&redirectLinks, "redirect-links", "", "redirect links")
	pflag.BoolVar(&disableTagsList, "disable-tags-list", false, "disable tags list")
	pflag.BoolVar(&enablePprof, "enable-pprof", false, "Enable pprof")
	pflag.StringVar(&defaultRegistry, "default-registry", "", "default registry used for non full-path docker pull, like:docker.io")
	pflag.StringToStringVar(&overrideDefaultRegistry, "override-default-registry", nil, "override default registry")
	pflag.BoolVar(&simpleAuth, "simple-auth", false, "enable simple auth")
	pflag.StringToStringVar(&simpleAuthUserpass, "simple-auth-user", nil, "simple auth user and password")
	pflag.StringVar(&tokenURL, "token-url", "", "token url")
	pflag.BoolVar(&tokenAuthForceTLS, "token-auth-force-tls", false, "token auth force TLS")

	pflag.BoolVar(&redirectOriginBlobLinks, "redirect-origin-blob-links", false, "redirect origin blob links")

	pflag.StringSliceVar(&acmeHosts, "acme-hosts", nil, "acme hosts")
	pflag.StringVar(&acmeCacheDir, "acme-cache-dir", "", "acme cache dir")
	pflag.StringVar(&certFile, "cert-file", "", "cert file")
	pflag.StringVar(&privateKeyFile, "private-key-file", "", "private key file")
	pflag.BoolVar(&enableInternalAPI, "enable-internal-api", false, "enable internal api")

	pflag.StringVar(&readmeURL, "readme-url", "", "redirect readme url when not found")
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

			lastRedirect := req.URL.String()
			s = append(s, lastRedirect)
			logger.Println("redirect", s)

			if v := crproxy.GetCtxValue(req.Context()); v != nil {
				v.LastRedirect = lastRedirect
			}
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
		crproxy.WithPathInfoModifyFunc(func(info *crproxy.ImageInfo) *crproxy.ImageInfo {
			// docker.io/busybox => docker.io/library/busybox
			if info.Host == "docker.io" && !strings.Contains(info.Name, "/") {
				info.Name = "library/" + info.Name
			}
			if info.Host == "ollama.ai" && !strings.Contains(info.Name, "/") {
				info.Name = "library/" + info.Name
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

	if allowImageListFromFile != "" {
		f, err := os.ReadFile(allowImageListFromFile)
		if err != nil {
			logger.Println("can't read allow list file %s", allowImageListFromFile)
			os.Exit(1)
		}

		var matcher atomic.Pointer[hostmatcher.Matcher]
		m, err := getListFrom(bytes.NewReader(f))
		if err != nil {
			logger.Println("can't read allow list file %s", allowImageListFromFile)
			os.Exit(1)
		}
		matcher.Store(&m)

		if enableInternalAPI {
			mux.HandleFunc("PUT /internal/api/allows", func(rw http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					logger.Println("read body failed:", err)
					rw.WriteHeader(http.StatusBadRequest)
					rw.Write([]byte(err.Error()))
					return
				}
				m, err := getListFrom(bytes.NewReader(body))
				if err != nil {
					logger.Println("can't read allow list file %s", allowImageListFromFile)
					rw.WriteHeader(http.StatusBadRequest)
					rw.Write([]byte(err.Error()))
					return
				}

				err = os.WriteFile(allowImageListFromFile, body, 0644)
				if err != nil {
					logger.Println("write file failed:", err)
					rw.WriteHeader(http.StatusBadRequest)
					rw.Write([]byte(err.Error()))
					return
				}

				matcher.Store(&m)
			})
		}
		opts = append(opts, crproxy.WithBlockFunc(func(info *crproxy.ImageInfo) bool {
			return !(*matcher.Load()).Match(info.Host + "/" + info.Name)
		}))
	} else if len(blockImageList) != 0 || len(allowHostList) != 0 {
		allowHostMap := map[string]struct{}{}
		for _, host := range allowHostList {
			allowHostMap[host] = struct{}{}
		}
		blockImageMap := map[string]struct{}{}
		for _, image := range blockImageList {
			blockImageMap[image] = struct{}{}
		}
		opts = append(opts, crproxy.WithBlockFunc(func(info *crproxy.ImageInfo) bool {
			if len(allowHostMap) != 0 {
				_, ok := allowHostMap[info.Host]
				if !ok {
					return true
				}
			}

			if len(blockImageMap) != 0 {
				image := info.Host + "/" + info.Name
				_, ok := blockImageMap[image]
				if ok {
					return true
				}
			}

			return false
		}))
	}

	if blockMessage != "" {
		opts = append(opts, crproxy.WithBlockMessage(blockMessage))
	}

	if len(privilegedIPList) != 0 || privilegedImageListFromFile != "" {
		var matcher atomic.Pointer[hostmatcher.Matcher]
		if privilegedImageListFromFile != "" {
			f, err := os.ReadFile(privilegedImageListFromFile)
			if err != nil {
				logger.Println("can't read privileged list file %s", privilegedImageListFromFile)
				os.Exit(1)
			}

			m, err := getListFrom(bytes.NewReader(f))
			if err != nil {
				logger.Println("can't read privileged list file %s", privilegedImageListFromFile)
				os.Exit(1)
			}
			matcher.Store(&m)

			if enableInternalAPI {
				mux.HandleFunc("PUT /internal/api/privileged", func(rw http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						logger.Println("read body failed:", err)
						rw.WriteHeader(http.StatusBadRequest)
						rw.Write([]byte(err.Error()))
						return
					}
					m, err := getListFrom(bytes.NewReader(body))
					if err != nil {
						logger.Println("can't read allow list file %s", privilegedImageListFromFile)
						rw.WriteHeader(http.StatusBadRequest)
						rw.Write([]byte(err.Error()))
						return
					}

					err = os.WriteFile(privilegedImageListFromFile, body, 0644)
					if err != nil {
						logger.Println("write file failed:", err)
						rw.WriteHeader(http.StatusBadRequest)
						rw.Write([]byte(err.Error()))
						return
					}

					matcher.Store(&m)
				})
			}
		}

		set := map[string]struct{}{}
		for _, ip := range privilegedIPList {
			set[ip] = struct{}{}
		}
		opts = append(opts, crproxy.WithPrivilegedFunc(func(r *http.Request, info *crproxy.ImageInfo) bool {
			if len(set) != 0 {
				ip := r.RemoteAddr
				if _, ok := set[ip]; ok {
					return true
				}
			}
			if m := matcher.Load(); m != nil && info != nil {
				return (*m).Match(info.Host + "/" + info.Name)
			}
			return false
		}))
	}

	if privilegedNoAuth {
		opts = append(opts, crproxy.WithPrivilegedNoAuth(true))
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

	if len(overrideDefaultRegistry) != 0 {
		opts = append(opts, crproxy.WithOverrideDefaultRegistry(overrideDefaultRegistry))
	}

	if simpleAuth {
		opts = append(opts, crproxy.WithSimpleAuth(true, tokenURL, tokenAuthForceTLS))
	}
	if len(simpleAuthUserpass) != 0 {

		opts = append(opts, crproxy.WithSimpleAuthUserFunc(func(r *http.Request, userinfo *url.Userinfo) bool {
			pass, ok := simpleAuthUserpass[userinfo.Username()]
			if !ok {
				return false
			}
			upass, ok := userinfo.Password()
			if !ok {
				return false
			}
			if upass != pass {
				return false
			}
			return true
		}))
	}

	if redirectOriginBlobLinks {
		opts = append(opts, crproxy.WithRedirectToOriginBlobFunc(func(r *http.Request, info *crproxy.ImageInfo) bool {
			return true
		}))
	}

	crp, err := crproxy.NewCRProxy(opts...)
	if err != nil {
		logger.Println("failed to NewCRProxy:", err)
		os.Exit(1)
	}

	mux.Handle("/v2/", crp)
	mux.HandleFunc("/auth/token", crp.AuthToken)

	mux.HandleFunc("/internal/api/image/sync", crp.Sync)

	if enablePprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
	if readmeURL != "" {
		mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
			http.Redirect(rw, r, readmeURL, http.StatusFound)
		})
	}

	var handler http.Handler = mux
	handler = handlers.LoggingHandler(os.Stderr, handler)
	if behind {
		handler = handlers.ProxyHeaders(handler)
	}

	err = server.Run(ctx, address, handler, acmeHosts, acmeCacheDir, certFile, privateKeyFile)
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

func getListFrom(r io.Reader) (hostmatcher.Matcher, error) {
	lines := bufio.NewReader(r)
	hosts := []string{}
	for {
		line, _, err := lines.ReadLine()
		if err == io.EOF {
			break
		}
		h := strings.TrimSpace(string(line))
		if len(h) == 0 {
			continue
		}
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no hosts found")
	}
	if !slices.IsSorted(hosts) {
		return nil, fmt.Errorf("hosts not sorted: %v", hosts)
	}
	return hostmatcher.NewMatcher(hosts), nil
}
