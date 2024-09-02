package crproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/daocloud/crproxy/internal/maps"
	"github.com/distribution/distribution/v3/registry/api/errcode"
	"github.com/distribution/distribution/v3/registry/client/auth"
	"github.com/distribution/distribution/v3/registry/client/auth/challenge"
	"github.com/distribution/distribution/v3/registry/client/transport"
	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/wzshiming/geario"
	"github.com/wzshiming/hostmatcher"
	"github.com/wzshiming/httpseek"
	"github.com/wzshiming/lru"
)

var (
	prefix  = "/v2/"
	catalog = prefix + "_catalog"
)

type Logger interface {
	Println(v ...interface{})
}

type ImageInfo struct {
	Host string
	Name string
}

type CRProxy struct {
	baseClient              *http.Client
	challengeManager        challenge.Manager
	clientset               maps.SyncMap[string, *lru.LRU[string, *http.Client]]
	clientSize              int
	modify                  func(info *ImageInfo) *ImageInfo
	insecureDomain          map[string]struct{}
	domainDisableKeepAlives map[string]struct{}
	domainAlias             map[string]string
	userAndPass             map[string]Userpass
	basicCredentials        *basicCredentials
	mutClientset            sync.Mutex
	bytesPool               sync.Pool
	logger                  Logger
	totalBlobsSpeedLimit    *geario.Gear
	speedLimitRecord        maps.SyncMap[string, *geario.BPS]
	blobsSpeedLimit         *geario.B
	blobsSpeedLimitDuration time.Duration
	ipsSpeedLimit           *geario.B
	ipsSpeedLimitDuration   time.Duration
	blockFunc               func(*ImageInfo) bool
	blockMessage            string
	retry                   int
	retryInterval           time.Duration
	storageDriver           storagedriver.StorageDriver
	linkExpires             time.Duration
	mutCache                sync.Map
	redirectLinks           *url.URL
	limitDelay              bool
	privilegedNoAuth        bool
	disableTagsList         bool
	simpleAuth              bool
	simpleAuthUserpassFunc  func(r *http.Request, userinfo *url.Userinfo) bool
	tokenURL                string
	tokenAuthForceTLS       bool
	matcher                 hostmatcher.Matcher

	defaultRegistry         string
	overrideDefaultRegistry map[string]string

	privilegedFunc           func(r *http.Request, info *ImageInfo) bool
	redirectToOriginBlobFunc func(r *http.Request, info *ImageInfo) bool
}

type Option func(c *CRProxy)

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

func WithSimpleAuth(b bool, tokenURL string, forceTLS bool) Option {
	return func(c *CRProxy) {
		c.simpleAuth = b
		c.tokenURL = tokenURL
		c.tokenAuthForceTLS = forceTLS
	}
}

func WithSimpleAuthUserFunc(f func(r *http.Request, userinfo *url.Userinfo) bool) Option {
	return func(c *CRProxy) {
		c.simpleAuthUserpassFunc = f
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

func WithLinkExpires(d time.Duration) Option {
	return func(c *CRProxy) {
		c.linkExpires = d
	}
}

func WithRedirectLinks(l *url.URL) Option {
	return func(c *CRProxy) {
		c.redirectLinks = l
	}
}

func WithStorageDriver(storageDriver storagedriver.StorageDriver) Option {
	return func(c *CRProxy) {
		c.storageDriver = storageDriver
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

func WithBaseClient(baseClient *http.Client) Option {
	return func(c *CRProxy) {
		c.baseClient = baseClient
	}
}

func WithLogger(logger Logger) Option {
	return func(c *CRProxy) {
		c.logger = logger
	}
}

func WithUserAndPass(userAndPass map[string]Userpass) Option {
	return func(c *CRProxy) {
		c.userAndPass = userAndPass
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

func WithMaxClientSizeForEachRegistry(clientSize int) Option {
	return func(c *CRProxy) {
		c.clientSize = clientSize
	}
}

func WithDisableKeepAlives(disableKeepAlives []string) Option {
	return func(c *CRProxy) {
		c.domainDisableKeepAlives = map[string]struct{}{}
		for _, v := range disableKeepAlives {
			c.domainDisableKeepAlives[v] = struct{}{}
		}
	}
}

func WithBlockFunc(blockFunc func(info *ImageInfo) bool) Option {
	return func(c *CRProxy) {
		c.blockFunc = blockFunc
	}
}

func WithBlockMessage(msg string) Option {
	return func(c *CRProxy) {
		c.blockMessage = msg
	}
}

func WithRetry(retry int, retryInterval time.Duration) Option {
	return func(c *CRProxy) {
		c.retry = retry
		c.retryInterval = retryInterval
	}
}

func NewCRProxy(opts ...Option) (*CRProxy, error) {
	c := &CRProxy{
		challengeManager: challenge.NewSimpleManager(),
		clientSize:       10240,
		baseClient:       http.DefaultClient,
		bytesPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024)
			},
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	if len(c.userAndPass) != 0 {
		bc, err := newBasicCredentials(c.userAndPass, c.getDomainAlias, c.getScheme)
		if err != nil {
			return nil, err
		}
		c.basicCredentials = bc
	}
	return c, nil
}

func (c *CRProxy) hostURL(host string) string {
	return c.getScheme(host) + "://" + host
}

func (c *CRProxy) pingURL(host string) string {
	return c.hostURL(host) + prefix
}

func (c *CRProxy) getScheme(host string) string {
	if c.insecureDomain != nil {
		_, ok := c.insecureDomain[host]
		if ok {
			return "http"
		}
	}
	return "https"
}

func (c *CRProxy) getClientset(host string, image string) *http.Client {
	sets, hasSets := c.clientset.Load(host)
	if hasSets {
		client, ok := sets.Get(image)
		if ok {
			return client
		}
	}

	c.mutClientset.Lock()
	defer c.mutClientset.Unlock()
	if sets == nil {
		sets = lru.NewLRU(c.clientSize, func(image string, client *http.Client) {
			if c.logger != nil {
				c.logger.Println("evicted client", host, image)
			}
			client.CloseIdleConnections()
		})
		c.clientset.Store(host, sets)
	}

	if c.logger != nil {
		c.logger.Println("cache client", host, image)
	}
	var credentialStore auth.CredentialStore
	if c.basicCredentials != nil {
		credentialStore = c.basicCredentials
	}
	authHandler := auth.NewTokenHandler(nil, credentialStore, image, "pull")

	tr := c.baseClient.Transport

	if c.domainDisableKeepAlives != nil {
		if _, ok := c.domainDisableKeepAlives[host]; ok {
			tr = c.disableKeepAlives(tr)
		}
	}

	if c.retryInterval > 0 {
		if tr == nil {
			tr = http.DefaultTransport
		}
		tr = httpseek.NewMustReaderTransport(tr, func(request *http.Request, retry int, err error) error {
			if errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			if c.retry > 0 && retry >= c.retry {
				return err
			}
			if c.logger != nil {
				c.logger.Println("Retry", request.URL, retry, err)
			}
			time.Sleep(c.retryInterval)
			return nil
		})
	}

	tr = transport.NewTransport(tr, auth.NewAuthorizer(c.challengeManager, authHandler))

	client := &http.Client{
		Transport:     tr,
		CheckRedirect: c.baseClient.CheckRedirect,
		Timeout:       c.baseClient.Timeout,
		Jar:           c.baseClient.Jar,
	}

	sets.Put(image, client)
	return client
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
	if c.logger != nil {
		c.logger.Println("failed to disable keep alives")
	}
	return rt
}

func (c *CRProxy) ping(host string) error {
	if c.logger != nil {
		c.logger.Println("ping", host)
	}

	ep := c.pingURL(host)
	e, err := url.Parse(ep)
	if err != nil {
		return err
	}
	challenges, err := c.challengeManager.GetChallenges(*e)
	if err == nil && len(challenges) != 0 {
		return nil
	}

	resp, err := c.baseClient.Get(ep)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	err = c.challengeManager.AddResponse(resp)
	if err != nil {
		return err
	}
	return nil
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

func (c *CRProxy) do(cli *http.Client, r *http.Request) (*http.Response, error) {
	resp, err := cli.Do(r)
	if err == nil {
		return resp, nil
	}

	if r.Method != http.MethodHead {
		return nil, err
	}

	r.Method = http.MethodGet
	defer func() {
		r.Method = http.MethodHead
	}()
	resp0, err0 := cli.Do(r)
	if err0 != nil {
		return nil, err
	}
	return resp0, nil
}

func (c *CRProxy) doWithAuth(cli *http.Client, r *http.Request, host string) (*http.Response, error) {
	resp, err := c.do(cli, r)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		err = c.ping(host)
		if err != nil {
			if c.logger != nil {
				c.logger.Println("failed to ping", host, err)
			}
			return resp, nil
		}

		resp0, err0 := c.do(cli, r)
		if err0 != nil {
			if c.logger != nil {
				c.logger.Println("failed to redo", host, err)
			}
			return resp, nil
		}
		resp.Body.Close()
		resp = resp0
	}
	return resp, nil
}

func getIP(str string) string {
	host, _, err := net.SplitHostPort(str)
	if err == nil && host != "" {
		return host
	}
	return str
}

func (c *CRProxy) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		errcode.ServeJSON(rw, errcode.ErrorCodeUnsupported)
		return
	}

	r.RemoteAddr = getIP(r.RemoteAddr)

	if c.simpleAuth && !c.authorization(rw, r) {
		c.authenticate(rw, r)
		return
	}

	oriPath := r.URL.Path
	if oriPath == prefix {
		apiBase(rw, r)
		return
	}
	if !strings.HasPrefix(oriPath, prefix) {
		c.notFoundResponse(rw, r)
		return
	}
	if oriPath == catalog {
		errcode.ServeJSON(rw, errcode.ErrorCodeUnsupported)
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

	if c.blockFunc != nil && c.blockFunc(imageInfo) {
		if c.blockMessage != "" {
			errcode.ServeJSON(rw, errcode.ErrorCodeDenied.WithMessage(c.blockMessage))
		} else {
			errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
		}
		return
	}

	info.Host = c.getDomainAlias(info.Host)

	if info.TagsList && c.disableTagsList {
		emptyTagsList(rw, r)
		return
	}

	path, err := info.Path()
	if err != nil {
		if c.logger != nil {
			c.logger.Println("failed to get path", err)
		}
		errcode.ServeJSON(rw, errcode.ErrorCodeUnknown)
		return
	}
	r.RequestURI = ""
	r.Host = info.Host
	r.URL.Host = info.Host
	r.URL.Scheme = c.getScheme(info.Host)
	r.URL.Path = path
	r.URL.RawQuery = ""
	r.URL.ForceQuery = false

	if info.Blobs != "" && c.isRedirectToOriginBlob(r, imageInfo) {
		c.redirectBlobResponse(rw, r, info)
		return
	}

	if !c.isPrivileged(r, imageInfo) {
		if !c.checkLimit(rw, r, info) {
			return
		}
	}

	if c.storageDriver != nil {
		if info.Blobs != "" {
			c.cacheBlobResponse(rw, r, info)
			return
		} else if info.Manifests != "" {
			c.cacheManifestResponse(rw, r, info)
			return
		}
	}
	c.directResponse(rw, r, info)
}

func (c *CRProxy) directResponse(rw http.ResponseWriter, r *http.Request, info *PathInfo) {
	cli := c.getClientset(info.Host, info.Image)
	resp, err := c.doWithAuth(cli, r, info.Host)
	if err != nil {
		if c.logger != nil {
			c.logger.Println("failed to request", info.Host, info.Image, err)
		}
		errcode.ServeJSON(rw, errcode.ErrorCodeUnknown)
		return
	}
	defer func() {
		resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
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

		if !c.isPrivileged(r, &ImageInfo{
			Host: info.Host,
			Name: info.Image,
		}) {
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
		if c.logger != nil {
			c.logger.Println("error response", r.RemoteAddr, e)
		}
	}

	if err == nil {
		err = errcode.ErrorCodeUnknown
	}

	errcode.ServeJSON(rw, err)
}

func (c *CRProxy) notFoundResponse(rw http.ResponseWriter, r *http.Request) {
	http.NotFound(rw, r)
}

func (c *CRProxy) redirect(rw http.ResponseWriter, r *http.Request, blobPath string) error {
	options := map[string]interface{}{
		"method": r.Method,
	}
	linkExpires := c.linkExpires
	if linkExpires > 0 {
		options["expiry"] = time.Now().Add(linkExpires)
	}
	u, err := c.storageDriver.URLFor(r.Context(), blobPath, options)
	if err != nil {
		return err
	}
	if c.logger != nil {
		c.logger.Println("Cache hit", blobPath, u)
	}
	if c.redirectLinks != nil {
		uri, err := url.Parse(u)
		if err == nil {
			uri.Scheme = c.redirectLinks.Scheme
			uri.Host = c.redirectLinks.Host
			u = uri.String()
		}
	}
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
