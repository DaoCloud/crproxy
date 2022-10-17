package crproxy

import (
	"io"
	"net/http"
	"strings"
	"sync"

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
	mux              sync.Mutex
	bytesPool        sync.Pool
	logger           Logger
}

func NewCRProxy(baseClient *http.Client, logger Logger) *CRProxy {
	return &CRProxy{
		challengeManager: challenge.NewSimpleManager(),
		clientset:        map[string]map[string]*http.Client{},
		baseClient:       baseClient,
		logger:           logger,
		bytesPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024)
			},
		},
	}
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
	authHandler := auth.NewTokenHandler(nil, nil, image, "pull")
	client := &http.Client{
		Transport: transport.NewTransport(c.baseClient.Transport, auth.NewAuthorizer(c.challengeManager, authHandler)),
	}
	if c.clientset[host] == nil {
		c.clientset[host] = map[string]*http.Client{}
	}
	c.clientset[host][image] = client
	return client
}

func (c *CRProxy) responseErrorCode(rw http.ResponseWriter, code int) {
	http.Error(rw, http.StatusText(code), code)
}

func (c *CRProxy) ping(host string) error {
	c.mux.Lock()
	defer c.mux.Unlock()

	if c.logger != nil {
		c.logger.Println("ping", host)
	}
	resp, err := c.baseClient.Get("https://" + host + prefix)
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

func (c *CRProxy) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		c.responseErrorCode(rw, http.StatusForbidden)
		return
	}
	path := r.URL.Path
	if path == prefix {
		rw.WriteHeader(http.StatusOK)
		return
	}
	if !strings.HasPrefix(path, prefix) {
		http.NotFound(rw, r)
		return
	}

	host, path, image, ok := getHostAndWantPath(path)
	if !ok {
		http.NotFound(rw, r)
		return
	}

	r.RequestURI = ""
	r.Host = host
	r.URL.Host = host
	r.URL.Scheme = "https"
	r.URL.Path = path

	cli := c.getClientset(host, image)
	resp, err := cli.Do(r)
	if err != nil {
		if c.logger != nil {
			c.logger.Println("failed to request", host, image, err)
		}
		c.responseErrorCode(rw, http.StatusInternalServerError)
		return
	}
	defer func() {
		resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()

		err = c.ping(host)
		if err != nil {
			if c.logger != nil {
				c.logger.Println("failed to ping", host, err)
			}
			c.responseErrorCode(rw, http.StatusInternalServerError)
			return
		}

		resp, err = cli.Do(r)
		if err != nil {
			if c.logger != nil {
				c.logger.Println("failed to request again", host, image, err)
			}
			c.responseErrorCode(rw, http.StatusInternalServerError)
			return
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

func getHostAndWantPath(s string) (host, path, image string, ok bool) {
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

	// docker.io/library/golang => registry-1.docker.io/library/golang
	if host == "docker.io" {
		host = "registry-1.docker.io"
	}
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
