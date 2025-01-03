package gateway

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/daocloud/crproxy/agent"
	"github.com/daocloud/crproxy/cache"
	"github.com/daocloud/crproxy/internal/utils"
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
	mutCache        sync.Map
	httpClient      *http.Client
	modify          func(info *ImageInfo) *ImageInfo
	logger          *slog.Logger
	disableTagsList bool
	cache           *cache.Cache

	manifestCache *manifestCache
	authenticator *token.Authenticator

	defaultRegistry         string
	overrideDefaultRegistry map[string]string

	acceptsItems []string
	acceptsStr   string
	accepts      map[string]struct{}

	blobsLENoAgent int

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
		c.manifestCache = newManifestCache(d)
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

func WithBlobsLENoAgent(blobsLENoAgent int) Option {
	return func(c *Gateway) {
		c.blobsLENoAgent = blobsLENoAgent
	}
}

func WithDefaultRegistry(target string) Option {
	return func(c *Gateway) {
		c.defaultRegistry = target
	}
}

func WithOverrideDefaultRegistry(overrideDefaultRegistry map[string]string) Option {
	return func(c *Gateway) {
		c.overrideDefaultRegistry = overrideDefaultRegistry
	}
}

func NewGateway(opts ...Option) (*Gateway, error) {
	c := &Gateway{
		logger: slog.Default(),
		acceptsItems: []string{
			"application/vnd.oci.image.index.v1+json",
			"application/vnd.docker.distribution.manifest.list.v2+json",
			"application/vnd.oci.image.manifest.v1+json",
			"application/vnd.docker.distribution.manifest.v2+json",
		},
		accepts: map[string]struct{}{},
	}

	for _, item := range c.acceptsItems {
		c.accepts[item] = struct{}{}
	}
	c.acceptsStr = strings.Join(c.acceptsItems, ",")

	for _, opt := range opts {
		opt(c)
	}

	if c.cache != nil {
		a, err := agent.NewAgent(
			agent.WithClient(c.httpClient),
			agent.WithAuthenticator(c.authenticator),
			agent.WithLogger(c.logger),
			agent.WithCache(c.cache),
			agent.WithBlobsLENoAgent(c.blobsLENoAgent),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create agent: %w", err)
		}
		c.agent = a
	}
	return c, nil
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

	r.RemoteAddr = utils.GetIP(r.RemoteAddr)

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
		utils.ResponseAPIBase(rw, r)
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
		info.Host = c.defaultRegistry
		if c.overrideDefaultRegistry != nil {
			r, ok := c.overrideDefaultRegistry[r.Host]
			if ok {
				info.Host = r
			}
		}
	}

	if info.Host == "" {
		errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
		return
	}

	if r.URL.RawQuery != "" {
		q := r.URL.Query()
		if ns := q.Get("ns"); ns != "" && ns != info.Host {
			errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
			return
		}
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
		utils.ResponseEmptyTagsList(rw, r)
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
	u := &url.URL{
		Scheme: "https",
		Host:   info.Host,
		Path:   path,
	}
	forwardReq, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), nil)
	if err != nil {
		c.logger.Warn("failed to new request", "error", err)
		errcode.ServeJSON(rw, errcode.ErrorCodeUnknown)
		return
	}

	resp, err := c.httpClient.Do(forwardReq)
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

	if forwardReq.Method != http.MethodHead {
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
