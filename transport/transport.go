package transport

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/daocloud/crproxy/internal/maps"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

type Transport struct {
	baseTransport http.RoundTripper
	userAndPass   map[string]authn.AuthConfig
	clientset     maps.SyncMap[string, maps.SyncMap[string, http.RoundTripper]]
	mutClientset  sync.Mutex
	logger        *slog.Logger
}

type Option func(c *Transport) error

func WithBaseTransport(baseTransport http.RoundTripper) Option {
	return func(c *Transport) error {
		c.baseTransport = baseTransport
		return nil
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(c *Transport) error {
		c.logger = logger
		return nil
	}
}

func WithUserAndPass(userAndPass []string) Option {
	return func(c *Transport) error {
		userpass, err := toUserAndPass(userAndPass)
		if err != nil {
			return err
		}
		c.userAndPass = userpass
		return nil
	}
}

func NewTransport(opts ...Option) (http.RoundTripper, error) {
	c := &Transport{
		logger:        slog.Default(),
		baseTransport: http.DefaultTransport,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

func (c *Transport) getUserpass(host string) (authn.AuthConfig, bool) {
	userpass, ok := c.userAndPass[host]
	if !ok {
		return authn.AuthConfig{}, false
	}
	return userpass, true
}

func parsePath(path string) (string, bool) {
	if !strings.HasPrefix(path, "/v2/") {
		return "", false
	}
	path = path[4:]
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		return "", false
	}

	image := strings.Join(parts[0:len(parts)-2], "/")

	return image, true
}

func (c *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt, err := c.getRoundTripper(req)
	if err != nil {
		return nil, err
	}

	return rt.RoundTrip(req)
}

func getHostAndSecure(req *http.Request) (string, bool) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	secure := req.TLS != nil || req.URL.Scheme == "https"

	return host, secure
}

func (c *Transport) getRoundTripper(req *http.Request) (http.RoundTripper, error) {
	image, ok := parsePath(req.URL.Path)
	if !ok {
		return c.baseTransport, nil
	}

	host, secure := getHostAndSecure(req)

	sets, hasSets := c.clientset.Load(host)
	if hasSets {
		tr, ok := sets.Load(image)
		if ok {
			return tr, nil
		}
	}

	var registry name.Registry
	var err error
	if secure {
		registry, err = name.NewRegistry(host)
	} else {
		registry, err = name.NewRegistry(host, name.Insecure)
	}
	if err != nil {
		return nil, err
	}

	var auth authn.Authenticator
	if u, ok := c.getUserpass(host); ok {
		auth = authn.FromConfig(u)
	} else {
		auth = authn.Anonymous
	}

	c.mutClientset.Lock()
	defer c.mutClientset.Unlock()
	tr, ok := sets.Load(image)
	if ok {
		return tr, nil
	}

	tr, err = transport.NewWithContext(
		context.Background(),
		registry,
		auth,
		c.baseTransport,
		[]string{"repository:" + image + ":pull"},
	)
	if err != nil {
		return nil, err
	}

	sets.Store(image, tr)
	return tr, nil
}

func toUserAndPass(userpass []string) (map[string]authn.AuthConfig, error) {
	bc := map[string]authn.AuthConfig{}
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
		bc[host] = authn.AuthConfig{
			Username: user,
			Password: pwd,
		}
	}
	return bc, nil
}
