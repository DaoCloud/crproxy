package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/daocloud/crproxy/internal/maps"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/wzshiming/httpseek"
)

type Userpass = authn.AuthConfig

type Transport struct {
	baseTransport           http.RoundTripper
	insecureDomain          map[string]struct{}
	domainDisableKeepAlives map[string]struct{}
	userAndPass             map[string]Userpass
	clientset               maps.SyncMap[string, maps.SyncMap[string, http.RoundTripper]]
	mutClientset            sync.Mutex
	logger                  *slog.Logger
	retry                   int
	retryInterval           time.Duration
	allowHeadMethod         bool
}

type Option func(c *Transport)

func WithBaseTransport(baseTransport http.RoundTripper) Option {
	return func(c *Transport) {
		c.baseTransport = baseTransport
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(c *Transport) {
		c.logger = logger
	}
}

func WithUserAndPass(userAndPass map[string]Userpass) Option {
	return func(c *Transport) {
		c.userAndPass = userAndPass
	}
}

func WithDisableKeepAlives(disableKeepAlives []string) Option {
	return func(c *Transport) {
		c.domainDisableKeepAlives = map[string]struct{}{}
		for _, v := range disableKeepAlives {
			c.domainDisableKeepAlives[v] = struct{}{}
		}
	}
}

func WithRetry(retry int, retryInterval time.Duration) Option {
	return func(c *Transport) {
		c.retry = retry
		c.retryInterval = retryInterval
	}
}

func WithAllowHeadMethod(allowHeadMethod bool) Option {
	return func(c *Transport) {
		c.allowHeadMethod = allowHeadMethod
	}
}

func NewTransport(opts ...Option) (*Transport, error) {
	c := &Transport{
		logger:        slog.Default(),
		baseTransport: http.DefaultTransport,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

func (c *Transport) getRegistry(host string) (name.Registry, error) {
	if c.insecureDomain != nil {
		_, ok := c.insecureDomain[host]
		if ok {
			return name.NewRegistry(host, name.Insecure)
		}
	}
	return name.NewRegistry(host)
}

func (c *Transport) getUserpass(host string) Userpass {
	userpass, ok := c.userAndPass[host]
	if !ok {
		return Userpass{}
	}
	return userpass
}

func parsePath(path string) (string, bool) {
	path = strings.TrimPrefix(path, "/v2/")
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		return "", false
	}

	image := strings.Join(parts[0:len(parts)-2], "/")

	return image, true
}

func (c *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	image, ok := parsePath(req.URL.Path)
	if !ok {
		return nil, fmt.Errorf("invalid path: %s", req.URL.Path)
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	rt, err := c.getRoundTripper(host, image)
	if err != nil {
		return nil, err
	}

	resp, err := rt.RoundTrip(req.WithContext(req.Context()))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		c.logger.Warn("unauthorized retry", "url", req.URL)

		sets, hasSets := c.clientset.Load(host)
		if hasSets {
			sets.Delete(image)
		}

		resp, err = rt.RoundTrip(req.WithContext(req.Context()))
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

func (c *Transport) getRoundTripper(host string, image string) (http.RoundTripper, error) {
	sets, hasSets := c.clientset.Load(host)
	if hasSets {
		client, ok := sets.Load(image)
		if ok {
			return client, nil
		}
	}

	c.mutClientset.Lock()
	defer c.mutClientset.Unlock()

	registry, err := c.getRegistry(host)
	if err != nil {
		return nil, err
	}

	tr, err := transport.NewWithContext(
		context.Background(),
		registry,
		authn.FromConfig(c.getUserpass(host)),
		c.baseTransport,
		[]string{"repository:" + image + ":pull"},
	)
	if err != nil {
		return nil, err
	}

	if c.domainDisableKeepAlives != nil {
		if _, ok := c.domainDisableKeepAlives[host]; ok {
			tr = c.disableKeepAlives(tr)
		}
	}

	if c.retryInterval > 0 {
		tr = httpseek.NewMustReaderTransport(tr, func(request *http.Request, retry int, err error) error {
			if errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			if c.retry > 0 && retry >= c.retry {
				return err
			}
			c.logger.Info("Retry", "url", request.URL, "retry", retry, "error", err)
			time.Sleep(c.retryInterval)
			return nil
		})
	}

	sets.Store(image, tr)
	return tr, nil
}

func (c *Transport) disableKeepAlives(rt http.RoundTripper) http.RoundTripper {
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
	c.logger.Warn("Failed to disable keep alives")
	return rt
}

func ToUserAndPass(userpass []string) (map[string]Userpass, error) {
	bc := map[string]Userpass{}
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
		bc[host] = Userpass{
			Username: user,
			Password: pwd,
		}
	}
	return bc, nil
}
