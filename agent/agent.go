package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daocloud/crproxy/cache"
	"github.com/daocloud/crproxy/token"
	"github.com/docker/distribution/registry/api/errcode"
)

type BlobInfo struct {
	Host  string
	Image string

	Blobs string
}

type Agent struct {
	mutCache      sync.Map
	httpClient    *http.Client
	logger        *slog.Logger
	cache         *cache.Cache
	authenticator *token.Authenticator
}

type Option func(c *Agent) error

func WithCache(cache *cache.Cache) Option {
	return func(c *Agent) error {
		c.cache = cache
		return nil
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(c *Agent) error {
		c.logger = logger
		return nil
	}
}

func WithAuthenticator(authenticator *token.Authenticator) Option {
	return func(c *Agent) error {
		c.authenticator = authenticator
		return nil
	}
}

func WithClient(client *http.Client) Option {
	return func(c *Agent) error {
		c.httpClient = client
		return nil
	}
}

func NewAgent(opts ...Option) (*Agent, error) {
	c := &Agent{
		logger:     slog.Default(),
		httpClient: http.DefaultClient,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// /v2/{source}/{path...}/blobs/sha256:{digest}

func parsePath(path string) (string, string, string, bool) {
	path = strings.TrimPrefix(path, "/v2/")
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		return "", "", "", false
	}
	if parts[len(parts)-2] != "blobs" {
		return "", "", "", false
	}
	source := parts[0]
	image := strings.Join(parts[1:len(parts)-2], "/")
	digest := parts[len(parts)-1]
	if !strings.HasPrefix(digest, "sha256:") {
		return "", "", "", false
	}
	return source, image, digest, true
}

func (c *Agent) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	source, image, digest, ok := parsePath(r.URL.Path)
	if !ok {
		http.NotFound(rw, r)
		return
	}

	info := &BlobInfo{
		Host:  source,
		Image: image,
		Blobs: digest,
	}

	var t token.Token
	var err error
	if c.authenticator != nil {
		t, err = c.authenticator.Authorization(r)
		if err != nil {
			c.errorResponse(rw, r, errcode.ErrorCodeDenied.WithMessage(err.Error()))
			return
		}
	}

	if t.Block {
		if t.BlockMessage != "" {
			errcode.ServeJSON(rw, errcode.ErrorCodeDenied.WithMessage(t.BlockMessage))
		} else {
			errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
		}
		return
	}

	c.Serve(rw, r, info, &t)
}

func (c *Agent) Serve(rw http.ResponseWriter, r *http.Request, info *BlobInfo, t *token.Token) {
	ctx := r.Context()

	closeValue, loaded := c.mutCache.LoadOrStore(info.Blobs, make(chan struct{}))
	closeCh := closeValue.(chan struct{})
	for loaded {
		select {
		case <-ctx.Done():
			err := ctx.Err().Error()
			c.logger.Error("context done", "error", err)
			http.Error(rw, err, http.StatusInternalServerError)
			return
		case <-closeCh:
		}
		closeValue, loaded = c.mutCache.LoadOrStore(info.Blobs, make(chan struct{}))
		closeCh = closeValue.(chan struct{})
	}

	doneCache := func() {
		c.mutCache.Delete(info.Blobs)
		close(closeCh)
	}

	stat, err := c.cache.StatBlob(ctx, info.Blobs)
	if err == nil {
		doneCache()

		size := stat.Size()
		if r.Method == http.MethodHead {
			rw.Header().Set("Content-Length", strconv.FormatInt(size, 10))
			rw.Header().Set("Content-Type", "application/octet-stream")
			return
		}

		if !t.NoRateLimit {
			sleepDuration(float64(size), float64(t.RateLimitPerSecond))
		}

		err = c.redirect(rw, r, info.Blobs, info)
		if err != nil {
			c.logger.Error("failed to redirect", "digest", info.Blobs, "error", err)
			c.errorResponse(rw, r, ctx.Err())
		}
		return
	}
	c.logger.Info("Cache miss", "digest", info.Blobs)

	type signal struct {
		err  error
		size int64
	}
	signalCh := make(chan signal, 1)

	go func() {
		defer doneCache()
		size, err := c.cacheBlob(r, info, func(size int64) {
			signalCh <- signal{
				size: size,
			}
		})
		signalCh <- signal{
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

		if !t.NoRateLimit {
			sleepDuration(float64(signal.size), float64(t.RateLimitPerSecond))
		}

		select {
		case <-ctx.Done():
			return
		case <-signalCh:
			err = c.redirect(rw, r, info.Blobs, info)
			if err != nil {
				c.logger.Error("failed to redirect", "digest", info.Blobs, "error", err)
			}
		}
		return
	}
}

func sleepDuration(size, limit float64) {
	if limit <= 0 {
		return
	}

	sd := time.Duration(size / limit * float64(time.Second))
	if sd > time.Second/10 {
		time.Sleep(sd)
	}
}

func (c *Agent) cacheBlob(r *http.Request, info *BlobInfo, stats func(int64)) (int64, error) {
	u := url.URL{
		Scheme: "https",
		Host:   info.Host,
		Path:   fmt.Sprintf("/v2/%s/blobs/%s", info.Image, info.Blobs),
	}
	r, err := http.NewRequestWithContext(context.Background(), r.Method, u.String(), nil)
	if err != nil {
		return 0, err
	}

	resp, err := c.httpClient.Do(r)
	if err != nil {
		return 0, err
	}
	defer func() {
		resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return 0, errcode.ErrorCodeDenied
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return 0, errcode.ErrorCodeUnknown.WithMessage(fmt.Sprintf("source response code %d: %s", resp.StatusCode, u.String()))
	}

	if stats != nil {
		stats(resp.ContentLength)
	}

	return c.cache.PutBlob(context.Background(), info.Blobs, resp.Body)
}

func (c *Agent) errorResponse(rw http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		e := err.Error()
		c.logger.Warn("error response", "remoteAddr", r.RemoteAddr, "error", e)
	}

	if err == nil {
		err = errcode.ErrorCodeUnknown
	}

	errcode.ServeJSON(rw, err)
}

func (c *Agent) redirect(rw http.ResponseWriter, r *http.Request, blob string, info *BlobInfo) error {
	referer := r.RemoteAddr
	if info != nil {
		referer += fmt.Sprintf(":%s/%s", info.Host, info.Image)
	}

	u, err := c.cache.RedirectBlob(r.Context(), blob, referer)
	if err != nil {
		return err
	}
	c.logger.Info("Cache hit", "digest", blob, "url", u)
	http.Redirect(rw, r, u, http.StatusFound)
	return nil
}
