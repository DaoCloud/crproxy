package crproxy

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/daocloud/crproxy/cache"
	"github.com/daocloud/crproxy/internal/maps"
	"github.com/daocloud/crproxy/token"
	"github.com/docker/distribution/registry/api/errcode"
	"github.com/wzshiming/geario"
)

var (
	prefix  = "/v2/"
	catalog = prefix + "_catalog"
)

type ImageInfo struct {
	Host string
	Name string
}

type BlockInfo struct {
	IP   string
	Host string
	Name string
}

type CRProxy struct {
	httpClient               *http.Client
	modify                   func(info *ImageInfo) *ImageInfo
	domainAlias              map[string]string
	bytesPool                sync.Pool
	logger                   *slog.Logger
	totalBlobsSpeedLimit     *geario.Gear
	speedLimitRecord         maps.SyncMap[string, *geario.BPS]
	blobsSpeedLimit          *geario.B
	blobsSpeedLimitDuration  time.Duration
	ipsSpeedLimit            *geario.B
	ipsSpeedLimitDuration    time.Duration
	blockFunc                []func(*BlockInfo) (string, bool)
	limitDelay               bool
	privilegedNoAuth         bool
	disableTagsList          bool
	simpleAuth               bool
	defaultRegistry          string
	overrideDefaultRegistry  map[string]string
	privilegedFunc           func(r *http.Request, info *ImageInfo) bool
	redirectToOriginBlobFunc func(r *http.Request, info *ImageInfo) bool
	cache                    *cache.Cache
	mutCache                 sync.Map
	manifestCache            maps.SyncMap[cacheKey, time.Time]
	manifestCacheDuration    time.Duration
	authenticator            *token.Authenticator
}

type Option func(c *CRProxy)

func WithTransport(transport http.RoundTripper) Option {
	return func(c *CRProxy) {
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

				c.logger.Info("redirect", "redirects", s)

				if v := getCtxValue(req.Context()); v != nil {
					v.LastRedirect = lastRedirect
				}
				return nil
			},
			Transport: transport,
		}
		c.httpClient = cli
	}
}

func WithManifestCacheDuration(d time.Duration) Option {
	return func(c *CRProxy) {
		c.manifestCacheDuration = d
	}
}

func WithPrivilegedFunc(f func(r *http.Request, info *ImageInfo) bool) Option {
	return func(c *CRProxy) {
		c.privilegedFunc = f
	}
}

func WithRedirectToOriginBlobFunc(f func(r *http.Request, info *ImageInfo) bool) Option {
	return func(c *CRProxy) {
		c.redirectToOriginBlobFunc = f
	}
}

func WithSimpleAuth(b bool) Option {
	return func(c *CRProxy) {
		c.simpleAuth = b
	}
}

func WithDefaultRegistry(target string) Option {
	return func(c *CRProxy) {
		c.defaultRegistry = target
	}
}

func WithOverrideDefaultRegistry(overrideDefaultRegistry map[string]string) Option {
	return func(c *CRProxy) {
		c.overrideDefaultRegistry = overrideDefaultRegistry
	}
}

func WithDisableTagsList(b bool) Option {
	return func(c *CRProxy) {
		c.disableTagsList = b
	}
}

func WithPrivilegedNoAuth(b bool) Option {
	return func(c *CRProxy) {
		c.privilegedNoAuth = true
	}
}

func WithLimitDelay(b bool) Option {
	return func(c *CRProxy) {
		c.limitDelay = b
	}
}

func WithBlobsSpeedLimit(limit geario.B, duration time.Duration) Option {
	return func(c *CRProxy) {
		c.blobsSpeedLimit = &limit
		c.blobsSpeedLimitDuration = duration
	}
}

func WithIPsSpeedLimit(limit geario.B, duration time.Duration) Option {
	return func(c *CRProxy) {
		c.ipsSpeedLimit = &limit
		c.ipsSpeedLimitDuration = duration
	}
}

func WithTotalBlobsSpeedLimit(limit geario.B) Option {
	return func(c *CRProxy) {
		c.totalBlobsSpeedLimit = geario.NewGear(time.Second, limit)
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(c *CRProxy) {
		c.logger = logger
	}
}

func WithDomainAlias(domainAlias map[string]string) Option {
	return func(c *CRProxy) {
		c.domainAlias = domainAlias
	}
}

func WithPathInfoModifyFunc(modify func(info *ImageInfo) *ImageInfo) Option {
	return func(c *CRProxy) {
		c.modify = modify
	}
}

func WithBlockFunc(blockFunc func(info *BlockInfo) (string, bool)) Option {
	return func(c *CRProxy) {
		c.blockFunc = append(c.blockFunc, blockFunc)
	}
}

func WithAuthenticator(authenticator *token.Authenticator) Option {
	return func(c *CRProxy) {
		c.authenticator = authenticator
	}
}

func WithCache(cache *cache.Cache) Option {
	return func(c *CRProxy) {
		c.cache = cache
	}
}

func NewCRProxy(opts ...Option) (*CRProxy, error) {
	c := &CRProxy{
		logger: slog.Default(),
		bytesPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024)
			},
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.simpleAuth {
		if c.authenticator == nil {
			return nil, fmt.Errorf("no authenticator provided")
		}
	}
	return c, nil
}

func (c *CRProxy) disableKeepAlives(rt http.RoundTripper) http.RoundTripper {
	if rt == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.DisableKeepAlives = true
		return tr
	}
	if tr, ok := rt.(*http.Transport); ok {
		if !tr.DisableKeepAlives {
			tr = tr.Clone()
			tr.DisableKeepAlives = true
		}
		return tr
	}
	c.logger.Warn("failed to disable keep alives")
	return rt
}

func apiBase(w http.ResponseWriter, r *http.Request) {
	const emptyJSON = "{}"
	// Provide a simple /v2/ 200 OK response with empty json response.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(emptyJSON)))

	fmt.Fprint(w, emptyJSON)
}

func emptyTagsList(w http.ResponseWriter, r *http.Request) {
	const emptyTagsList = `{"name":"disable-list-tags","tags":[]}`

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(emptyTagsList)))
	fmt.Fprint(w, emptyTagsList)
}

func getIP(str string) string {
	host, _, err := net.SplitHostPort(str)
	if err == nil && host != "" {
		return host
	}
	return str
}

func (c *CRProxy) block(info *BlockInfo) (string, bool) {
	for _, blockFunc := range c.blockFunc {
		blockMessage, block := blockFunc(info)
		if block {
			return blockMessage, true
		}
	}
	return "", false
}

func (c *CRProxy) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		errcode.ServeJSON(rw, errcode.ErrorCodeUnsupported)
		return
	}
	oriPath := r.URL.Path
	if oriPath == catalog {
		errcode.ServeJSON(rw, errcode.ErrorCodeUnsupported)
		return
	}

	r.RemoteAddr = getIP(r.RemoteAddr)
	var t *token.Token
	if c.simpleAuth {
		gt, err := c.authenticator.Authorization(r)
		if err != nil {
			if err != token.ErrNoAuth {
				c.logger.Warn("failed to authorize", "remoteAddr", r.RemoteAddr, "error", err)
			}
			c.authenticator.Authenticate(rw, r)
			return
		}
		t = &gt
	} else {
		t = &token.Token{}
	}

	if oriPath == prefix {
		apiBase(rw, r)
		return
	}
	if c.simpleAuth && (t.Scope == "") {
		c.authenticator.Authenticate(rw, r)
		return
	}
	if !strings.HasPrefix(oriPath, prefix) {
		c.notFoundResponse(rw, r)
		return
	}

	defaultRegistry := c.defaultRegistry
	if c.overrideDefaultRegistry != nil {
		r, ok := c.overrideDefaultRegistry[r.Host]
		if ok {
			defaultRegistry = r
		}
	}
	info, ok := ParseOriginPathInfo(oriPath, defaultRegistry)
	if !ok {
		errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
		return
	}

	if c.modify != nil {
		n := c.modify(&ImageInfo{
			Host: info.Host,
			Name: info.Image,
		})
		info.Host = n.Host
		info.Image = n.Name
	}

	imageInfo := &ImageInfo{
		Host: info.Host,
		Name: info.Image,
	}

	if c.isPrivileged(r, imageInfo) {
		t.NoRateLimit = true
		t.NoAllowlist = true
		t.AllowTagsList = true
		t.NoBlock = true
	}

	if c.disableTagsList && info.TagsList && !t.AllowTagsList {
		emptyTagsList(rw, r)
		return
	}

	if c.blockFunc != nil && !t.NoBlock {
		blockMessage, block := c.block(&BlockInfo{
			IP:   r.RemoteAddr,
			Host: info.Host,
			Name: info.Image,
		})
		if block {
			if blockMessage != "" {
				errcode.ServeJSON(rw, errcode.ErrorCodeDenied.WithMessage(blockMessage))
			} else {
				errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
			}
			return
		}
	}

	info.Host = c.getDomainAlias(info.Host)

	path, err := info.Path()
	if err != nil {
		c.logger.Warn("failed to get path", "error", err)
		errcode.ServeJSON(rw, errcode.ErrorCodeUnknown)
		return
	}

	u := url.URL{
		Scheme: "https",
		Host:   info.Host,
		Path:   path,
	}

	r, err = http.NewRequestWithContext(r.Context(), r.Method, u.String(), nil)
	if err != nil {
		c.logger.Warn("failed to new request", "error", err)
		errcode.ServeJSON(rw, errcode.ErrorCodeUnknown)
		return
	}

	if info.Blobs != "" && c.isRedirectToOriginBlob(r, imageInfo) {
		c.redirectBlobResponse(rw, r, info)
		return
	}

	if !t.NoRateLimit {
		if !c.checkLimit(rw, r, info) {
			return
		}
	}

	if c.cache != nil {
		if info.Blobs != "" {
			c.cacheBlobResponse(rw, r, info, t)
			return
		}

		if info.Manifests != "" {
			c.cacheManifestResponse(rw, r, info, t)
			return
		}
	}
	c.directResponse(rw, r, info, t)
}

func (c *CRProxy) directResponse(rw http.ResponseWriter, r *http.Request, info *PathInfo, t *token.Token) {
	resp, err := c.httpClient.Do(r)
	if err != nil {
		c.logger.Warn("failed to request", "host", info.Host, "image", info.Image, "error", err)
		errcode.ServeJSON(rw, errcode.ErrorCodeUnknown)
		return
	}
	defer func() {
		resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		c.logger.Warn("origin direct response 40x", "host", info.Host, "image", info.Image, "response", dumpResponse(resp))
		errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
		return
	}

	resp.Header.Del("Docker-Ratelimit-Source")

	if resp.StatusCode == http.StatusOK {
		oldLink := resp.Header.Get("Link")
		if oldLink != "" {
			resp.Header.Set("Link", addPrefixToImageForPagination(oldLink, info.Host))
		}
	}

	header := rw.Header()
	for k, v := range resp.Header {
		key := textproto.CanonicalMIMEHeaderKey(k)
		header[key] = v
	}
	rw.WriteHeader(resp.StatusCode)

	if r.Method != http.MethodHead {
		buf := c.bytesPool.Get().([]byte)
		defer c.bytesPool.Put(buf)
		var body io.Reader = resp.Body

		if !t.NoRateLimit {
			c.accumulativeLimit(r, info, resp.ContentLength)

			if c.totalBlobsSpeedLimit != nil && info.Blobs != "" {
				body = c.totalBlobsSpeedLimit.Reader(body)
			}

			if c.blobsSpeedLimit != nil && info.Blobs != "" {
				body = geario.NewGear(c.blobsSpeedLimitDuration, *c.blobsSpeedLimit).Reader(body)
			}
		}

		io.CopyBuffer(rw, body, buf)
	}
}

func (c *CRProxy) errorResponse(rw http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		e := err.Error()
		c.logger.Warn("error response", "remoteAddr", r.RemoteAddr, "error", e)
	}

	if err == nil {
		err = errcode.ErrorCodeUnknown
	}

	errcode.ServeJSON(rw, err)
}

func (c *CRProxy) notFoundResponse(rw http.ResponseWriter, r *http.Request) {
	http.NotFound(rw, r)
}

func (c *CRProxy) redirect(rw http.ResponseWriter, r *http.Request, blob string, info *PathInfo) error {

	referer := r.RemoteAddr
	if info != nil {
		referer += fmt.Sprintf(":%s/%s", info.Host, info.Image)
	}

	u, err := c.cache.RedirectBlob(r.Context(), blob, referer)
	if err != nil {
		return err
	}
	c.logger.Info("Cache hit", "digest", blob, "url", u)
	http.Redirect(rw, r, u, http.StatusTemporaryRedirect)
	return nil
}

func (c *CRProxy) getDomainAlias(host string) string {
	if c.domainAlias == nil {
		return host
	}
	h, ok := c.domainAlias[host]
	if !ok {
		return host
	}
	return h
}
