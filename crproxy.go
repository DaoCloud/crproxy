package crproxy

import (
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/distribution/distribution/v3/registry/api/errcode"
	"github.com/distribution/distribution/v3/registry/client/auth"
	"github.com/distribution/distribution/v3/registry/client/auth/challenge"
	"github.com/distribution/distribution/v3/registry/client/transport"
	"github.com/wzshiming/geario"
	"github.com/wzshiming/lru"
)

var (
	prefix             = "/v2/"
	catalog            = prefix + "_catalog"
	speedLimitDuration = time.Second
)

type Logger interface {
	Println(v ...interface{})
}

type CRProxy struct {
	baseClient              *http.Client
	challengeManager        challenge.Manager
	clientset               map[string]*lru.LRU[string, *http.Client]
	clientSize              int
	modify                  func(info *PathInfo) *PathInfo
	insecureDomain          map[string]struct{}
	domainDisableKeepAlives map[string]struct{}
	domainAlias             map[string]string
	userAndPass             map[string]Userpass
	basicCredentials        *basicCredentials
	mut                     sync.Mutex
	bytesPool               sync.Pool
	logger                  Logger
	totalBlobsSpeedLimit    *geario.Gear
	blobsSpeedLimit         *geario.B
	blockFunc               func(*PathInfo) bool
}

type Option func(c *CRProxy)

func WithBlobsSpeedLimit(limit geario.B) Option {
	return func(c *CRProxy) {
		c.blobsSpeedLimit = &limit
	}
}

func WithTotalBlobsSpeedLimit(limit geario.B) Option {
	return func(c *CRProxy) {
		c.totalBlobsSpeedLimit = geario.NewGear(speedLimitDuration, limit)
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

func NewCRProxy(opts ...Option) (*CRProxy, error) {
	c := &CRProxy{
		challengeManager: challenge.NewSimpleManager(),
		clientset:        map[string]*lru.LRU[string, *http.Client]{},
		clientSize:       16,
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
	c.mut.Lock()
	defer c.mut.Unlock()
	if c.clientset[host] != nil {
		client, ok := c.clientset[host].Get(image)
		if ok {
			return client
		}
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

	tr = transport.NewTransport(tr, auth.NewAuthorizer(c.challengeManager, authHandler))

	client := &http.Client{
		Transport:     tr,
		CheckRedirect: c.baseClient.CheckRedirect,
		Timeout:       c.baseClient.Timeout,
		Jar:           c.baseClient.Jar,
	}
	if c.clientset[host] == nil {
		c.clientset[host] = lru.NewLRU(c.clientSize, func(image string, client *http.Client) {
			if c.logger != nil {
				c.logger.Println("evicted client", host, image)
			}
			client.CloseIdleConnections()
		})
	}
	c.clientset[host].Put(image, client)
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
	c.mut.Lock()
	defer c.mut.Unlock()

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
		http.NotFound(rw, r)
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

		if c.totalBlobsSpeedLimit != nil && info.Blobs != "" {
			body = c.totalBlobsSpeedLimit.Reader(body)
		}

		if c.blobsSpeedLimit != nil && info.Blobs != "" {
			body = geario.NewGear(speedLimitDuration, *c.blobsSpeedLimit).Reader(body)
		}

		io.CopyBuffer(rw, body, buf)
	}
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
	if !isDomainName(host) {
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
