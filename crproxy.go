package crproxy

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/distribution/distribution/v3/registry/api/errcode"
	"github.com/distribution/distribution/v3/registry/client/auth"
	"github.com/distribution/distribution/v3/registry/client/auth/challenge"
	"github.com/distribution/distribution/v3/registry/client/transport"
)

var (
	prefix = "/v2/"
)

type Logger interface {
	Println(v ...interface{})
}

type CRProxy struct {
	baseClient       *http.Client
	challengeManager challenge.Manager
	clientset        map[string]map[string]*http.Client
	domainAlias      map[string]string
	userAndPass      map[string]Userpass
	basicCredentials *basicCredentials
	mux              sync.Mutex
	bytesPool        sync.Pool
	logger           Logger
	pingURL          func(host string) string
}

type Option func(c *CRProxy)

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

func NewCRProxy(opts ...Option) (*CRProxy, error) {
	c := &CRProxy{
		challengeManager: challenge.NewSimpleManager(),
		clientset:        map[string]map[string]*http.Client{},
		baseClient:       http.DefaultClient,
		pingURL: func(host string) string {
			return "https://" + host + prefix
		},
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
		bc, err := newBasicCredentials(c.userAndPass, c.getDomainAlias)
		if err != nil {
			return nil, err
		}
		c.basicCredentials = bc
	}
	return c, nil
}

func (c *CRProxy) getClientset(host string, image string) *http.Client {
	c.mux.Lock()
	defer c.mux.Unlock()
	if c.clientset[host] != nil && c.clientset[host][image] != nil {
		return c.clientset[host][image]
	}

	if c.logger != nil {
		c.logger.Println("cache client", host, image)
	}
	var credentialStore auth.CredentialStore
	if c.basicCredentials != nil {
		credentialStore = c.basicCredentials
	}
	authHandler := auth.NewTokenHandler(nil, credentialStore, image, "pull")
	client := &http.Client{
		Transport:     transport.NewTransport(c.baseClient.Transport, auth.NewAuthorizer(c.challengeManager, authHandler)),
		CheckRedirect: c.baseClient.CheckRedirect,
		Timeout:       c.baseClient.Timeout,
		Jar:           c.baseClient.Jar,
	}
	if c.clientset[host] == nil {
		c.clientset[host] = map[string]*http.Client{}
	}
	c.clientset[host][image] = client
	return client
}

func (c *CRProxy) ping(host string) error {
	c.mux.Lock()
	defer c.mux.Unlock()

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

	host, path, image, ok := c.getHostAndWantPath(oriPath)
	if !ok ||
		!isDomainName(host) {
		errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
		return
	}

	r.RequestURI = ""
	r.Host = host
	r.URL.Host = host
	r.URL.Scheme = "https"
	r.URL.Path = path

	cli := c.getClientset(host, image)
	resp, err := c.doWithAuth(cli, r, host)
	if err != nil {
		if c.logger != nil {
			c.logger.Println("failed to request", host, image, err)
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
			resp.Header.Set("Link", strings.Replace(oldLink, path, oriPath, 1))
		}
	}

	header := rw.Header()
	for k, v := range resp.Header {
		header[k] = v
	}
	rw.WriteHeader(resp.StatusCode)

	if r.Method != http.MethodHead {
		buf := c.bytesPool.Get().([]byte)
		defer c.bytesPool.Put(buf)
		io.CopyBuffer(rw, resp.Body, buf)
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

func (c *CRProxy) getHostAndWantPath(s string) (host, path, image string, ok bool) {
	s = strings.TrimLeft(s, prefix)
	i := strings.IndexByte(s, '/')
	if i <= 0 {
		return "", "", "", false
	}
	host = s[:i]
	tail := s[i+1:]
	if !strings.Contains(host, ".") {
		return "", "", "", false
	}

	host = c.getDomainAlias(host)
	i = strings.LastIndexByte(tail, '/')
	i = strings.LastIndexByte(tail[:i], '/')
	image = tail[:i]
	if image == "" {
		return "", "", "", false
	}

	// docker.io/golang => docker.io/library/golang
	if host == "registry-1.docker.io" && !strings.Contains(image, "/") {
		image = "library/" + image
		tail = "library/" + tail
	}

	path = prefix + tail
	return host, path, image, true
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
