package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daocloud/crproxy/cache"
	"github.com/daocloud/crproxy/clientset"
	csync "github.com/daocloud/crproxy/cmd/crproxy/sync"
	"github.com/docker/distribution/registry/storage/driver/factory"
	"github.com/gorilla/handlers"
	"github.com/spf13/cobra"
	"github.com/wzshiming/geario"
	"github.com/wzshiming/hostmatcher"

	_ "github.com/daocloud/crproxy/storage/driver/obs"
	_ "github.com/daocloud/crproxy/storage/driver/oss"
	_ "github.com/docker/distribution/registry/storage/driver/azure"
	_ "github.com/docker/distribution/registry/storage/driver/gcs"
	_ "github.com/docker/distribution/registry/storage/driver/s3-aws"

	"github.com/daocloud/crproxy"
	"github.com/daocloud/crproxy/internal/pki"
	"github.com/daocloud/crproxy/internal/server"
	"github.com/daocloud/crproxy/signing"
	"github.com/daocloud/crproxy/token"
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
	blockIPListFromFile         string
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
	simpleAuthAllowAnonymous    bool
	tokenURL                    string

	redirectOriginBlobLinks bool

	acmeHosts      []string
	acmeCacheDir   string
	certFile       string
	privateKeyFile string

	enableInternalAPI bool

	readmeURL string

	allowHeadMethod bool

	manifestCacheDuration time.Duration

	tokenPrivateKeyFile string
	tokenPublicKeyFile  string
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
	pflag.StringSliceVar(&blockImageList, "block-image-list", nil, "block image list (deprecated)")
	pflag.StringVar(&blockMessage, "block-message", "", "block message")
	pflag.StringVar(&blockIPListFromFile, "block-ip-list-from-file", "", "block ip list from file")
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
	pflag.BoolVar(&simpleAuthAllowAnonymous, "simple-auth-allow-anonymous", false, "simple auth allow anonymous")

	pflag.StringVar(&tokenURL, "token-url", "", "token url")

	pflag.BoolVar(&redirectOriginBlobLinks, "redirect-origin-blob-links", false, "redirect origin blob links")

	pflag.StringSliceVar(&acmeHosts, "acme-hosts", nil, "acme hosts")
	pflag.StringVar(&acmeCacheDir, "acme-cache-dir", "", "acme cache dir")
	pflag.StringVar(&certFile, "cert-file", "", "cert file")
	pflag.StringVar(&privateKeyFile, "private-key-file", "", "private key file")
	pflag.BoolVar(&enableInternalAPI, "enable-internal-api", false, "enable internal api")

	pflag.StringVar(&readmeURL, "readme-url", "", "redirect readme url when not found")
	pflag.BoolVar(&allowHeadMethod, "allow-head-method", false, "allow head method")

	pflag.DurationVar(&manifestCacheDuration, "manifest-cache-duration", 0, "manifest cache duration")

	pflag.StringVar(&tokenPrivateKeyFile, "token-private-key-file", "", "private key file")
	pflag.StringVar(&tokenPublicKeyFile, "token-public-key-file", "", "public key file")

	cmd.AddCommand(csync.NewCommand())
}

var (
	cmd = &cobra.Command{
		Use:   "crproxy",
		Short: "crproxy",
		Run: func(cmd *cobra.Command, args []string) {
			run(cmd.Context())
		},
	}
	pflag = cmd.Flags()
)

func main() {
	cmd.Execute()
}

func toUserAndPass(userpass []string) (map[string]clientset.Userpass, error) {
	bc := map[string]clientset.Userpass{}
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
		bc[host] = clientset.Userpass{
			Username: user,
			Password: pwd,
		}
	}
	return bc, nil
}

func run(ctx context.Context) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

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
			logger.Info("redirect", "redirects", s)

			if v := crproxy.GetCtxValue(req.Context()); v != nil {
				v.LastRedirect = lastRedirect
			}
			return nil
		},
	}
	clientOpts := []clientset.Option{
		clientset.WithLogger(logger),
		clientset.WithBaseClient(cli),
		clientset.WithMaxClientSizeForEachRegistry(16),
		clientset.WithDisableKeepAlives(disableKeepAlives),
	}

	opts := []crproxy.Option{
		crproxy.WithLogger(logger),
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
	}

	if storageDriver != "" {
		cacheOpts := []cache.Option{}
		parameters := map[string]interface{}{}
		for k, v := range storageParameters {
			parameters[k] = v
		}
		sd, err := factory.Create(storageDriver, parameters)
		if err != nil {
			logger.Error("create storage driver failed", "error", err)
			os.Exit(1)
		}
		cacheOpts = append(cacheOpts, cache.WithStorageDriver(sd))
		if linkExpires > 0 {
			cacheOpts = append(cacheOpts, cache.WithLinkExpires(linkExpires))
		}
		if redirectLinks != "" {
			u, err := url.Parse(redirectLinks)
			if err != nil {
				logger.Error("parse redirect links failed", "error", err)
				os.Exit(1)
			}
			cacheOpts = append(cacheOpts, cache.WithRedirectLinks(u))
		}

		cache, err := cache.NewCache(cacheOpts...)
		if err != nil {
			logger.Error("create cache failed", "error", err)
			os.Exit(1)
		}
		opts = append(opts, crproxy.WithCache(cache))
	}

	if allowImageListFromFile != "" {
		f, err := os.ReadFile(allowImageListFromFile)
		if err != nil {
			logger.Error("can't read allow list file", "file", allowImageListFromFile, "error", err)
			os.Exit(1)
		}

		var matcher atomic.Pointer[hostmatcher.Matcher]
		m, err := getListFrom(bytes.NewReader(f))
		if err != nil {
			logger.Error("can't read allow list file", "file", allowImageListFromFile, "error", err)
			os.Exit(1)
		}
		matcher.Store(&m)

		if enableInternalAPI {
			mux.HandleFunc("PUT /internal/api/allows", func(rw http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					logger.Error("read body failed", "error", err)
					rw.WriteHeader(http.StatusBadRequest)
					rw.Write([]byte(err.Error()))
					return
				}
				m, err := getListFrom(bytes.NewReader(body))
				if err != nil {
					logger.Error("can't read allow list file", "file", allowImageListFromFile, "error", err)
					rw.WriteHeader(http.StatusBadRequest)
					rw.Write([]byte(err.Error()))
					return
				}

				err = os.WriteFile(allowImageListFromFile, body, 0644)
				if err != nil {
					logger.Error("write file failed", "error", err)
					rw.WriteHeader(http.StatusBadRequest)
					rw.Write([]byte(err.Error()))
					return
				}

				matcher.Store(&m)
			})
		}
		opts = append(opts, crproxy.WithBlockFunc(func(info *crproxy.BlockInfo) (string, bool) {
			if (*matcher.Load()).Match(info.Host + "/" + info.Name) {
				return "", false
			}
			return blockMessage, true
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
		opts = append(opts, crproxy.WithBlockFunc(func(info *crproxy.BlockInfo) (string, bool) {
			if len(allowHostMap) != 0 {
				_, ok := allowHostMap[info.Host]
				if !ok {
					return blockMessage, true
				}
			}

			if len(blockImageMap) != 0 {
				image := info.Host + "/" + info.Name
				_, ok := blockImageMap[image]
				if ok {
					return blockMessage, true
				}
			}

			return "", false
		}))
	}

	if len(privilegedIPList) != 0 || privilegedImageListFromFile != "" {
		var matcher atomic.Pointer[hostmatcher.Matcher]
		if privilegedImageListFromFile != "" {
			f, err := os.ReadFile(privilegedImageListFromFile)
			if err != nil {
				logger.Error("can't read privileged list file", "file", privilegedImageListFromFile, "error", err)
				os.Exit(1)
			}

			m, err := getListFrom(bytes.NewReader(f))
			if err != nil {
				logger.Error("can't read privileged list file", "file", privilegedImageListFromFile, "error", err)
				os.Exit(1)
			}
			matcher.Store(&m)

			if enableInternalAPI {
				mux.HandleFunc("PUT /internal/api/privileged", func(rw http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						logger.Error("read body failed", "error", err)
						rw.WriteHeader(http.StatusBadRequest)
						rw.Write([]byte(err.Error()))
						return
					}
					m, err := getListFrom(bytes.NewReader(body))
					if err != nil {
						logger.Error("can't read privileged list file", "file", privilegedImageListFromFile, "error", err)
						rw.WriteHeader(http.StatusBadRequest)
						rw.Write([]byte(err.Error()))
						return
					}

					err = os.WriteFile(privilegedImageListFromFile, body, 0644)
					if err != nil {
						logger.Error("write file failed", "file", privilegedImageListFromFile, "error", err)
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

	if blockIPListFromFile != "" {
		f, err := os.ReadFile(blockIPListFromFile)
		if err != nil {
			logger.Error("can't read block ip list file", "file", blockIPListFromFile, "error", err)
			os.Exit(1)
		}
		bf, err := getIPReasonCSVListFrom(bytes.NewReader(f))
		if err != nil {
			logger.Error("can't read block ip list file", "file", blockIPListFromFile, "error", err)
			os.Exit(1)
		}

		var bfMutex sync.RWMutex
		block := func(info *crproxy.BlockInfo) (string, bool) {
			bfMutex.RLock()
			defer bfMutex.RUnlock()
			return bf(info)
		}
		opts = append(opts, crproxy.WithBlockFunc(block))
		if enableInternalAPI {
			mux.HandleFunc("PUT /internal/api/block-ips", func(rw http.ResponseWriter, r *http.Request) {
				blockFunc, err := getIPReasonCSVListFrom(r.Body)
				if err != nil {
					logger.Error("can't read block ip list file", "file", blockIPListFromFile, "error", err)
					rw.WriteHeader(http.StatusBadRequest)
					rw.Write([]byte(err.Error()))
					return
				}
				bfMutex.Lock()
				bf = blockFunc
				bfMutex.Unlock()
			})
		}
	}

	if len(userpass) != 0 {
		bc, err := toUserAndPass(userpass)
		if err != nil {
			logger.Error("failed to toUserAndPass", "error", err)
			os.Exit(1)
		}
		clientOpts = append(clientOpts, clientset.WithUserAndPass(bc))
	}

	if ipsSpeedLimit != "" {
		b, d, err := getLimit(ipsSpeedLimit)
		if err != nil {
			logger.Error("failed to getLimit", "error", err)
			os.Exit(1)
		}
		opts = append(opts, crproxy.WithIPsSpeedLimit(b, d))
	}

	if blobsSpeedLimit != "" {
		b, d, err := getLimit(blobsSpeedLimit)
		if err != nil {
			logger.Error("failed to getLimit", "error", err)
			os.Exit(1)
		}
		opts = append(opts, crproxy.WithBlobsSpeedLimit(b, d))
	}

	if totalBlobsSpeedLimit != "" {
		b, err := geario.FromBytesSize(totalBlobsSpeedLimit)
		if err != nil {
			logger.Error("failed to FromBytesSize", "error", err)
			os.Exit(1)
		}
		opts = append(opts, crproxy.WithTotalBlobsSpeedLimit(b))
	}

	if disableTagsList {
		opts = append(opts, crproxy.WithDisableTagsList(true))
	}

	if retry > 0 {
		clientOpts = append(clientOpts, clientset.WithRetry(retry, retryInterval))
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

	var auth func(r *http.Request, userinfo *url.Userinfo) (token.Attribute, bool)

	if len(simpleAuthUserpass) != 0 {
		auth = func(r *http.Request, userinfo *url.Userinfo) (token.Attribute, bool) {
			if userinfo == nil {
				return token.Attribute{}, simpleAuthAllowAnonymous
			}
			pass, ok := simpleAuthUserpass[userinfo.Username()]
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
			return token.Attribute{
				NoRateLimit:   true,
				NoAllowlist:   true,
				NoBlock:       true,
				AllowTagsList: true,
			}, true
		}
	}

	if simpleAuth {
		var privateKey *rsa.PrivateKey
		var publicKey *rsa.PublicKey
		if tokenPrivateKeyFile == "" && tokenPublicKeyFile == "" {
			k, err := pki.GenerateKey()
			if err != nil {
				logger.Error("failed to GenerateKey", "error", err)
				os.Exit(1)
			}
			privateKey = k
			publicKey = &k.PublicKey
		} else {
			if tokenPrivateKeyFile != "" {
				privateKeyData, err := os.ReadFile(tokenPrivateKeyFile)
				if err != nil {
					logger.Error("failed to ReadFile", "file", tokenPrivateKeyFile, "error", err)
					os.Exit(1)
				}
				k, err := pki.DecodePrivateKey(privateKeyData)
				if err != nil {
					logger.Error("failed to DecodePrivateKey", "file", tokenPrivateKeyFile, "error", err)
					os.Exit(1)
				}
				privateKey = k
			}
			if tokenPublicKeyFile != "" {
				publicKeyData, err := os.ReadFile(tokenPublicKeyFile)
				if err != nil {
					logger.Error("failed to ReadFile", "file", tokenPublicKeyFile, "error", err)
					os.Exit(1)
				}
				k, err := pki.DecodePublicKey(publicKeyData)
				if err != nil {
					logger.Error("failed to DecodePublicKey", "file", tokenPublicKeyFile, "error", err)
					os.Exit(1)
				}
				publicKey = k
			} else if privateKey != nil {
				publicKey = &privateKey.PublicKey
			}
		}
		opts = append(opts, crproxy.WithSimpleAuth(true))

		authenticator := token.NewAuthenticator(token.NewDecoder(signing.NewVerifier(publicKey)), tokenURL)
		opts = append(opts, crproxy.WithAuthenticator(authenticator))

		if privateKey != nil {
			gen := token.NewGenerator(token.NewEncoder(signing.NewSigner(privateKey)), auth, logger)
			mux.Handle("/auth/token", gen)
		}
	}

	if redirectOriginBlobLinks {
		opts = append(opts, crproxy.WithRedirectToOriginBlobFunc(func(r *http.Request, info *crproxy.ImageInfo) bool {
			return true
		}))
	}

	if allowHeadMethod {
		clientOpts = append(clientOpts, clientset.WithAllowHeadMethod(allowHeadMethod))
	}

	if manifestCacheDuration != 0 {
		opts = append(opts, crproxy.WithManifestCacheDuration(manifestCacheDuration))
	}

	clientset, err := clientset.NewClientset(clientOpts...)
	if err != nil {
		logger.Error("failed to NewClientset", "error", err)
		os.Exit(1)
	}
	opts = append(opts, crproxy.WithClient(clientset))

	crp, err := crproxy.NewCRProxy(opts...)
	if err != nil {
		logger.Error("failed to NewCRProxy", "error", err)
		os.Exit(1)
	}

	mux.Handle("/v2/", crp)

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
		logger.Error("failed to ListenAndServe", "error", err)
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

func getIPReasonCSVListFrom(r io.Reader) (func(*crproxy.BlockInfo) (string, bool), error) {
	kv := map[string]string{}

	reader := csv.NewReader(r)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		kv[record[0]] = record[1]
	}

	return func(info *crproxy.BlockInfo) (string, bool) {
		reason, ok := kv[info.IP]
		if !ok {
			return "", false
		}
		return reason, true
	}, nil
}
