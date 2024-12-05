package clientset

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/daocloud/crproxy/internal/maps"
	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/auth/challenge"
	"github.com/docker/distribution/registry/client/transport"
	storagedriver "github.com/docker/distribution/registry/storage/driver"
	"github.com/wzshiming/httpseek"
	"github.com/wzshiming/lru"
)

const (
	prefix = "/v2/"
)

type Clientset struct {
	baseClient              *http.Client
	challengeManager        challenge.Manager
	clientset               maps.SyncMap[string, *lru.LRU[string, *http.Client]]
	clientSize              int
	insecureDomain          map[string]struct{}
	domainDisableKeepAlives map[string]struct{}
	domainAlias             map[string]string
	userAndPass             map[string]Userpass
	basicCredentials        *basicCredentials
	mutClientset            sync.Mutex
	logger                  *slog.Logger
	retry                   int
	retryInterval           time.Duration
	storageDriver           storagedriver.StorageDriver
	mutCache                sync.Map
	allowHeadMethod         bool
}

type Option func(c *Clientset)

func WithStorageDriver(storageDriver storagedriver.StorageDriver) Option {
	return func(c *Clientset) {
		c.storageDriver = storageDriver
	}
}

func WithBaseClient(baseClient *http.Client) Option {
	return func(c *Clientset) {
		c.baseClient = baseClient
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(c *Clientset) {
		c.logger = logger
	}
}

func WithUserAndPass(userAndPass map[string]Userpass) Option {
	return func(c *Clientset) {
		c.userAndPass = userAndPass
	}
}

func WithDomainAlias(domainAlias map[string]string) Option {
	return func(c *Clientset) {
		c.domainAlias = domainAlias
	}
}

func WithMaxClientSizeForEachRegistry(clientSize int) Option {
	return func(c *Clientset) {
		c.clientSize = clientSize
	}
}

func WithDisableKeepAlives(disableKeepAlives []string) Option {
	return func(c *Clientset) {
		c.domainDisableKeepAlives = map[string]struct{}{}
		for _, v := range disableKeepAlives {
			c.domainDisableKeepAlives[v] = struct{}{}
		}
	}
}

func WithRetry(retry int, retryInterval time.Duration) Option {
	return func(c *Clientset) {
		c.retry = retry
		c.retryInterval = retryInterval
	}
}

func WithAllowHeadMethod(allowHeadMethod bool) Option {
	return func(c *Clientset) {
		c.allowHeadMethod = allowHeadMethod
	}
}

func NewClientset(opts ...Option) (*Clientset, error) {
	c := &Clientset{
		logger:           slog.Default(),
		challengeManager: challenge.NewSimpleManager(),
		clientSize:       10240,
		baseClient:       http.DefaultClient,
	}

	for _, opt := range opts {
		opt(c)
	}
	if len(c.userAndPass) != 0 {
		bc, err := newBasicCredentials(c.userAndPass, c.getDomainAlias, c.GetScheme)
		if err != nil {
			return nil, err
		}
		c.basicCredentials = bc
	}

	return c, nil
}

func (c *Clientset) HostURL(host string) string {
	return c.GetScheme(host) + "://" + host
}

func (c *Clientset) pingURL(host string) string {
	return c.HostURL(host) + prefix
}

func (c *Clientset) GetScheme(host string) string {
	if c.insecureDomain != nil {
		_, ok := c.insecureDomain[host]
		if ok {
			return "http"
		}
	}
	return "https"
}

func (c *Clientset) GetClientset(host string, image string) *http.Client {
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
			c.logger.Info("evicted client", "host", host, "image", image)
			client.CloseIdleConnections()
		})
		c.clientset.Store(host, sets)
	}

	c.logger.Info("cache client", "host", host, "image", image)
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
			c.logger.Info("Retry", "url", request.URL, "retry", retry, "error", err)
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

func (c *Clientset) disableKeepAlives(rt http.RoundTripper) http.RoundTripper {
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

func (c *Clientset) Ping(host string) error {
	c.logger.Info("ping", "host", host)

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

func (c *Clientset) Do(cli *http.Client, r *http.Request) (resp *http.Response, err error) {
	forHead := !c.allowHeadMethod && r.Method == http.MethodHead
	if forHead {
		r.Method = http.MethodGet
	}
	resp, err = cli.Do(r)
	if err != nil {
		return nil, err
	}

	if forHead {
		r.Method = http.MethodHead
		if resp.Body != nil {
			resp.Body.Close()
		}
		resp.Body = http.NoBody
	}
	return resp, err
}

func (c *Clientset) DoWithAuth(cli *http.Client, r *http.Request, host string) (*http.Response, error) {
	resp, err := c.Do(cli, r)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		err = c.Ping(host)
		if err != nil {
			c.logger.Warn("failed to ping", "host", host, "error", err)
			return resp, nil
		}

		resp0, err0 := c.Do(cli, r)
		if err0 != nil {
			c.logger.Warn("failed to redo", "host", host, "error", err)
			return resp, nil
		}
		resp.Body.Close()
		resp = resp0
	}
	return resp, nil
}

func (c *Clientset) getDomainAlias(host string) string {
	if c.domainAlias == nil {
		return host
	}
	h, ok := c.domainAlias[host]
	if !ok {
		return host
	}
	return h
}
