package gateway

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/daocloud/crproxy/agent"
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

type Gateway struct {
	httpClient            *http.Client
	modify                func(info *ImageInfo) *ImageInfo
	logger                *slog.Logger
	disableTagsList       bool
	cache                 *cache.Cache
	manifestCache         maps.SyncMap[cacheKey, time.Time]
	manifestCacheDuration time.Duration
	authenticator         *token.Authenticator

	agent *agent.Agent
}

type Option func(c *Gateway)

func WithClient(client *http.Client) Option {
	return func(c *Gateway) {
		c.httpClient = client
	}
}

func WithManifestCacheDuration(d time.Duration) Option {
	return func(c *Gateway) {
		c.manifestCacheDuration = d
	}
}

func WithDisableTagsList(b bool) Option {
	return func(c *Gateway) {
		c.disableTagsList = b
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(c *Gateway) {
		c.logger = logger
	}
}

func WithPathInfoModifyFunc(modify func(info *ImageInfo) *ImageInfo) Option {
	return func(c *Gateway) {
		c.modify = modify
	}
}

func WithAuthenticator(authenticator *token.Authenticator) Option {
	return func(c *Gateway) {
		c.authenticator = authenticator
	}
}

func WithCache(cache *cache.Cache) Option {
	return func(c *Gateway) {
		c.cache = cache
	}
}

func NewGateway(opts ...Option) (*Gateway, error) {
	c := &Gateway{
		logger: slog.Default(),
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.authenticator == nil {
		return nil, fmt.Errorf("no authenticator provided")
	}

	if c.cache != nil {
		a, err := agent.NewAgent(
			agent.WithClient(c.httpClient),
			agent.WithAuthenticator(c.authenticator),
			agent.WithLogger(c.logger),
			agent.WithCache(c.cache),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create agent: %w", err)
		}
		c.agent = a
	}
	return c, nil
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

func (c *Gateway) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	oriPath := r.URL.Path
	if !strings.HasPrefix(oriPath, prefix) {
		http.NotFound(rw, r)
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		errcode.ServeJSON(rw, errcode.ErrorCodeUnsupported)
		return
	}

	if oriPath == catalog {
		errcode.ServeJSON(rw, errcode.ErrorCodeUnsupported)
		return
	}

	r.RemoteAddr = getIP(r.RemoteAddr)

	var t token.Token
	var err error

	authData := r.Header.Get("Authorization")

	if c.authenticator != nil {
		t, err = c.authenticator.Authorization(r)
		if err != nil {
			c.authenticator.Authenticate(rw, r)
			return
		}
	}

	if oriPath == prefix {
		apiBase(rw, r)
		return
	}

	if c.authenticator != nil {
		if t.Scope == "" {
			c.authenticator.Authenticate(rw, r)
			return
		}
		if t.Block {
			if t.BlockMessage != "" {
				errcode.ServeJSON(rw, errcode.ErrorCodeDenied.WithMessage(t.BlockMessage))
			} else {
				errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
			}
			return
		}
	}

	info, ok := parseOriginPathInfo(oriPath)
	if !ok {
		errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
		return
	}

	if t.Attribute.Host != "" {
		info.Host = t.Attribute.Host
	}
	if info.Host == "" {
		errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
		return
	}
	if t.Attribute.Image != "" {
		info.Image = t.Attribute.Image
	}

	if c.modify != nil {
		n := c.modify(&ImageInfo{
			Host: info.Host,
			Name: info.Image,
		})
		info.Host = n.Host
		info.Image = n.Name
	}

	if c.disableTagsList && info.TagsList && !t.AllowTagsList {
		emptyTagsList(rw, r)
		return
	}

	if info.Blobs != "" {
		c.blob(rw, r, info, &t, authData)
		return
	}

	if info.Manifests != "" {
		if c.cache != nil {
			c.cacheManifestResponse(rw, r, info, &t)
			return
		}
	}
	c.forward(rw, r, info, &t)
}

func (c *Gateway) forward(rw http.ResponseWriter, r *http.Request, info *PathInfo, t *token.Token) {
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
		var body io.Reader = resp.Body

		if t.RateLimitPerSecond > 0 {
			body = geario.NewGear(time.Second, geario.B(t.RateLimitPerSecond)).Reader(body)
		}

		io.Copy(rw, body)
	}
}

func (c *Gateway) errorResponse(rw http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		e := err.Error()
		c.logger.Warn("error response", "remoteAddr", r.RemoteAddr, "error", e)
	}

	if err == nil {
		err = errcode.ErrorCodeUnknown
	}

	errcode.ServeJSON(rw, err)
}
