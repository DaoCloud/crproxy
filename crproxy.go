package crproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/distribution/distribution/v3/registry/api/errcode"
	"github.com/distribution/distribution/v3/registry/client/auth"
	"github.com/distribution/distribution/v3/registry/client/auth/challenge"
	"github.com/distribution/distribution/v3/registry/client/transport"
	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/wzshiming/crproxy/internal/maps"
	"github.com/wzshiming/geario"
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

type CRProxy struct {
	baseClient              *http.Client
	challengeManager        challenge.Manager
	clientset               maps.SyncMap[string, *lru.LRU[string, *http.Client]]
	clientSize              int
	modify                  func(info *PathInfo) *PathInfo
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
	blockFunc               func(*PathInfo) bool
	retry                   int
	retryInterval           time.Duration
	storageDriver           storagedriver.StorageDriver
	linkExpires             time.Duration
	mutCache                sync.Map
	redirectLinks           *url.URL
	limitDelay              bool
	privilegedIPSet         map[string]struct{}
	disableTagsList         bool
}

type Option func(c *CRProxy)

func WithDisableTagsList(b bool) Option {
	return func(c *CRProxy) {
		c.disableTagsList = b
	}
}

func WithPrivilegedIPs(ips []string) Option {
	return func(c *CRProxy) {
		if c.privilegedIPSet == nil {
			c.privilegedIPSet = map[string]struct{}{}
		}
		for _, ip := range ips {
			c.privilegedIPSet[ip] = struct{}{}
		}
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

func WithPathInfoModifyFunc(modify func(info *PathInfo) *PathInfo) Option {
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

func WithBlockFunc(blockFunc func(info *PathInfo) bool) Option {
	return func(c *CRProxy) {
		c.blockFunc = blockFunc
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

func (c *CRProxy) pingURL(host string) string {
	return c.getScheme(host) + "://" + host + prefix
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
	c.mutClientset.Lock()
	defer c.mutClientset.Unlock()

	if c.logger != nil {
		c.logger.Println("ping", host)
	}
	resp, err := c.baseClient.Get(c.pingURL(host))
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

func (c *CRProxy) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		errcode.ServeJSON(rw, errcode.ErrorCodeUnsupported)
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

	info, ok := ParseOriginPathInfo(oriPath)
	if !ok {
		errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
		return
	}
	info.Host = c.getDomainAlias(info.Host)

	if c.modify != nil {
		info = c.modify(info)
	}

	if c.blockFunc != nil && c.blockFunc(info) {
		errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
		return
	}

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

	if !c.checkLimit(rw, r, info) {
		return
	}

	if c.storageDriver != nil && info.Blobs != "" {
		c.cacheBlobResponse(rw, r, info)
		return
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
		if !c.accumulativeLimit(rw, r, info, resp.ContentLength) {
			return
		}

		buf := c.bytesPool.Get().([]byte)
		defer c.bytesPool.Put(buf)
		var body io.Reader = resp.Body

		if !c.isPrivileged(r.RemoteAddr) {
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

func (c *CRProxy) cacheBlobResponse(rw http.ResponseWriter, r *http.Request, info *PathInfo) {
	ctx := r.Context()

	blob := strings.TrimPrefix(info.Blobs, "sha256:")
	blobPath := path.Join("/docker/registry/v2/blobs/sha256", blob[:2], blob, "data")

	closeValue, loaded := c.mutCache.LoadOrStore(blobPath, make(chan struct{}))
	closeCh := closeValue.(chan struct{})
	for loaded {
		select {
		case <-ctx.Done():
			err := ctx.Err().Error()
			if c.logger != nil {
				c.logger.Println(err)
			}
			http.Error(rw, err, http.StatusInternalServerError)
			return
		case <-closeCh:
		}
		closeValue, loaded = c.mutCache.LoadOrStore(blobPath, make(chan struct{}))
		closeCh = closeValue.(chan struct{})
	}

	doneCache := func() {
		c.mutCache.Delete(blobPath)
		close(closeCh)
	}

	stat, err := c.storageDriver.Stat(ctx, blobPath)
	if err == nil {
		doneCache()

		size := stat.Size()
		if r.Method == http.MethodHead {
			rw.Header().Set("Content-Length", strconv.FormatInt(size, 10))
			rw.Header().Set("Content-Type", "application/octet-stream")
			return
		}

		if !c.accumulativeLimit(rw, r, info, size) {
			c.errorResponse(rw, r, nil)
			return
		}

		err = c.redirect(rw, r, blobPath)
		if err == nil {
			return
		}
		c.errorResponse(rw, r, ctx.Err())
		return
	}
	if c.logger != nil {
		c.logger.Println("Cache miss", blobPath)
	}

	type repo struct {
		err  error
		size int64
	}
	signalCh := make(chan repo, 1)

	go func() {
		defer doneCache()
		size, err := c.cacheBlobContent(r, blobPath, info)
		signalCh <- repo{
			err:  err,
			size: size,
		}
	}()

	select {
	case <-ctx.Done():
		c.errorResponse(rw, r, ctx.Err())
		return
	case signal := <-signalCh:
		if signal.err != nil {
			c.errorResponse(rw, r, signal.err)
			return
		}
		if r.Method == http.MethodHead {
			rw.Header().Set("Content-Length", strconv.FormatInt(signal.size, 10))
			rw.Header().Set("Content-Type", "application/octet-stream")
			return
		}
		if !c.accumulativeLimit(rw, r, info, signal.size) {
			c.errorResponse(rw, r, nil)
			return
		}

		err = c.redirect(rw, r, blobPath)
		if err != nil {
			if c.logger != nil {
				c.logger.Println("failed to redirect", blobPath, err)
			}
		}
		return
	}
}

func (c *CRProxy) cacheBlobContent(r *http.Request, blobPath string, info *PathInfo) (int64, error) {
	cli := c.getClientset(info.Host, info.Image)
	resp, err := c.doWithAuth(cli, r, info.Host)
	if err != nil {
		return 0, err
	}
	defer func() {
		resp.Body.Close()
	}()

	buf := c.bytesPool.Get().([]byte)
	defer c.bytesPool.Put(buf)

	fw, err := c.storageDriver.Writer(context.Background(), blobPath, false)
	if err != nil {
		return 0, err
	}

	h := sha256.New()
	n, err := io.CopyBuffer(fw, io.TeeReader(resp.Body, h), buf)
	if err != nil {
		fw.Cancel()
		return 0, err
	}

	if n != resp.ContentLength {
		fw.Cancel()
		return 0, fmt.Errorf("expected %d bytes, got %d", resp.ContentLength, n)
	}

	hash := hex.EncodeToString(h.Sum(nil)[:])
	if info.Blobs[7:] != hash {
		fw.Cancel()
		return 0, fmt.Errorf("expected %s hash, got %s", info.Blobs[7:], hash)
	}

	err = fw.Commit()
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (c *CRProxy) errorResponse(rw http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		e := err.Error()
		if c.logger != nil {
			c.logger.Println(e)
		}
	}
	errcode.ServeJSON(rw, errcode.ErrorCodeUnknown)
}

func (c *CRProxy) notFoundResponse(rw http.ResponseWriter, r *http.Request) {
	http.NotFound(rw, r)
}

var (
	ErrorCodeTooManyRequests = errcode.ErrorCodeTooManyRequests

	ErrorCodeTooManyBandwidthsByBlob = errcode.Register("errcode", errcode.ErrorDescriptor{
		Value:          "TOOMANYBANDWIDTHS",
		Message:        "blob too many bandwidths",
		Description:    `Blobs are accessed too much`,
		HTTPStatusCode: http.StatusTooManyRequests,
	})
)

func addr(str string) string {
	i := strings.LastIndex(str, ":")
	if i <= 0 {
		return str
	}
	return str[:i]
}

func (c *CRProxy) isPrivileged(a string) bool {
	if c.privilegedIPSet == nil {
		return false
	}
	address := addr(a)

	_, ok := c.privilegedIPSet[address]
	return ok
}

func (c *CRProxy) checkLimit(rw http.ResponseWriter, r *http.Request, info *PathInfo) bool {
	if c.isPrivileged(r.RemoteAddr) {
		return true
	}

	if c.ipsSpeedLimit != nil && info.Blobs != "" {
		address := addr(r.RemoteAddr)
		bps, _ := c.speedLimitRecord.LoadOrStore(address, geario.NewBPSAver(c.ipsSpeedLimitDuration))
		aver := bps.Aver()
		if aver > *c.ipsSpeedLimit {
			if c.logger != nil {
				c.logger.Println("exceed limit", address, aver, *c.ipsSpeedLimit)
			}
			if c.limitDelay {
				for bps.Aver() > *c.ipsSpeedLimit {
					select {
					case <-r.Context().Done():
						return false
					case <-time.After(bps.Next().Sub(time.Now())):
					}
				}
			} else {
				err := ErrorCodeTooManyRequests
				rw.Header().Set("X-Retry-After", strconv.FormatInt(bps.Next().Unix(), 10))
				errcode.ServeJSON(rw, err)
				return false
			}
		}
	}

	return true
}

func (c *CRProxy) accumulativeLimit(rw http.ResponseWriter, r *http.Request, info *PathInfo, size int64) bool {
	if c.isPrivileged(r.RemoteAddr) {
		return true
	}

	if c.blobsSpeedLimit != nil && info.Blobs != "" {
		dur := GetSleepDuration(geario.B(size), *c.blobsSpeedLimit, c.blobsSpeedLimitDuration)
		if c.logger != nil {
			c.logger.Println("delay request", geario.B(size), dur)
		}
		select {
		case <-r.Context().Done():
			return false
		case <-time.After(dur):
		}
	}

	if c.ipsSpeedLimit != nil && info.Blobs != "" {
		bps, ok := c.speedLimitRecord.Load(addr(r.RemoteAddr))
		if ok {
			bps.Add(geario.B(size))
		}
	}

	return true
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

func addPrefixToImageForPagination(oldLink string, host string) string {
	linkAndRel := strings.SplitN(oldLink, ";", 2)
	if len(linkAndRel) != 2 {
		return oldLink
	}
	linkURL := strings.SplitN(strings.Trim(linkAndRel[0], "<>"), "/v2/", 2)
	if len(linkURL) != 2 {
		return oldLink
	}
	mirrorPath := prefix + host + "/" + linkURL[1]
	return fmt.Sprintf("<%s>;%s", mirrorPath, linkAndRel[1])
}

type PathInfo struct {
	Host  string
	Image string

	TagsList  bool
	Manifests string
	Blobs     string
}

func (p PathInfo) Path() (string, error) {
	if p.TagsList {
		return prefix + p.Image + "/tags/list", nil
	}
	if p.Manifests != "" {
		return prefix + p.Image + "/manifests/" + p.Manifests, nil
	}
	if p.Blobs != "" {
		return prefix + p.Image + "/blobs/" + p.Blobs, nil
	}
	return "", fmt.Errorf("unknow kind %#v", p)
}

func ParseOriginPathInfo(path string) (*PathInfo, bool) {
	path = strings.TrimLeft(path, prefix)
	i := strings.IndexByte(path, '/')
	if i <= 0 {
		return nil, false
	}
	host := path[:i]
	tail := path[i+1:]
	if !isDomainName(host) || !strings.Contains(host, ".") {
		return nil, false
	}

	tails := strings.Split(tail, "/")
	if len(tails) < 3 {
		return nil, false
	}
	image := strings.Join(tails[:len(tails)-2], "/")
	if image == "" {
		return nil, false
	}

	info := &PathInfo{
		Host:  host,
		Image: image,
	}
	switch tails[len(tails)-2] {
	case "tags":
		info.TagsList = tails[len(tails)-1] == "list"
	case "manifests":
		info.Manifests = tails[len(tails)-1]
	case "blobs":
		info.Blobs = tails[len(tails)-1]
		if len(info.Blobs) != 7+64 {
			return nil, false
		}
	}
	return info, true
}

// isDomainName checks if a string is a presentation-format domain name
// (currently restricted to hostname-compatible "preferred name" LDH labels and
// SRV-like "underscore labels"; see golang.org/issue/12421).
func isDomainName(s string) bool {
	// See RFC 1035, RFC 3696.
	// Presentation format has dots before every label except the first, and the
	// terminal empty label is optional here because we assume fully-qualified
	// (absolute) input. We must therefore reserve space for the first and last
	// labels' length octets in wire format, where they are necessary and the
	// maximum total length is 255.
	// So our _effective_ maximum is 253, but 254 is not rejected if the last
	// character is a dot.
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}

	last := byte('.')
	nonNumeric := false // true once we've seen a letter or hyphen
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			nonNumeric = true
			partlen++
		case '0' <= c && c <= '9':
			// fine
			partlen++
		case c == '-':
			// Byte before dash cannot be dot.
			if last == '.' {
				return false
			}
			partlen++
			nonNumeric = true
		case c == '.':
			// Byte before dot cannot be dot, dash.
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}

	return nonNumeric
}
