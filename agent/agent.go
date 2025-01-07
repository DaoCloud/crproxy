package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/daocloud/crproxy/cache"
	"github.com/daocloud/crproxy/internal/unique"
	"github.com/daocloud/crproxy/internal/utils"
	"github.com/daocloud/crproxy/token"
	"github.com/docker/distribution/registry/api/errcode"
)

var (
	prefix = "/v2/"
)

type BlobInfo struct {
	Host  string
	Image string

	Blobs string
}

type Agent struct {
	uniq       unique.Unique[string]
	httpClient *http.Client
	logger     *slog.Logger
	cache      *cache.Cache

	blobCacheDuration time.Duration
	blobCache         *blobCache
	authenticator     *token.Authenticator

	blobsLENoAgent int
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

func WithBlobsLENoAgent(blobsLENoAgent int) Option {
	return func(c *Agent) error {
		c.blobsLENoAgent = blobsLENoAgent
		return nil
	}
}

func WithBlobCacheDuration(blobCacheDuration time.Duration) Option {
	return func(c *Agent) error {
		c.blobCacheDuration = blobCacheDuration
		return nil
	}
}

func NewAgent(opts ...Option) (*Agent, error) {
	c := &Agent{
		logger:            slog.Default(),
		httpClient:        http.DefaultClient,
		blobCacheDuration: time.Hour,
	}

	for _, opt := range opts {
		opt(c)
	}

	c.blobCache = newBlobCache(c.blobCacheDuration)
	c.blobCache.Start(context.Background(), c.logger)

	return c, nil
}

// /v2/{source}/{path...}/blobs/sha256:{digest}

func parsePath(path string) (string, string, string, bool) {
	path = strings.TrimPrefix(path, prefix)
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
	oriPath := r.URL.Path
	if !strings.HasPrefix(oriPath, prefix) {
		http.NotFound(rw, r)
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		utils.ServeError(rw, r, errcode.ErrorCodeUnsupported, 0)
		return
	}

	if oriPath == prefix {
		utils.ResponseAPIBase(rw, r)
		return
	}

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
			utils.ServeError(rw, r, errcode.ErrorCodeDenied.WithMessage(err.Error()), 0)
			return
		}
	}

	if t.Block {
		if t.BlockMessage != "" {
			utils.ServeError(rw, r, errcode.ErrorCodeDenied.WithMessage(t.BlockMessage), 0)
		} else {
			utils.ServeError(rw, r, errcode.ErrorCodeDenied, 0)
		}
		return
	}

	c.Serve(rw, r, info, &t)
}

func (c *Agent) Serve(rw http.ResponseWriter, r *http.Request, info *BlobInfo, t *token.Token) {
	ctx := r.Context()

	var start time.Time
	if !t.NoRateLimit {
		start = time.Now()
	}

	err := c.uniq.Do(ctx, info.Blobs,
		func(ctx context.Context) (passCtx context.Context, done bool) {
			value, ok := c.blobCache.Get(info.Blobs)
			if ok {
				if value.Error != nil {
					utils.ServeError(rw, r, value.Error, 0)
					return ctx, true
				}
				c.serveCachedBlob(rw, r, info.Blobs, info, t, value.Size, start)
				return ctx, true
			}
			stat, err := c.cache.StatBlob(ctx, info.Blobs)
			if err != nil {
				return ctx, false
			}
			c.serveCachedBlob(rw, r, info.Blobs, info, t, stat.Size(), start)
			return ctx, true
		},
		func(ctx context.Context) (err error) {
			if ctx.Err() != nil {
				return nil
			}
			size, sc, err := c.cacheBlob(info)
			if err != nil {
				utils.ServeError(rw, r, err, sc)
				return nil
			}
			c.serveCachedBlob(rw, r, info.Blobs, info, t, size, start)
			return nil
		},
	)
	if err != nil {
		c.logger.Warn("error response", "remoteAddr", r.RemoteAddr, "error", err)
		c.blobCache.PutError(info.Blobs, err)
		utils.ServeError(rw, r, err, 0)
		return
	}
}

func sleepDuration(ctx context.Context, size, limit float64, start time.Time) error {
	if limit <= 0 {
		return nil
	}
	sd := time.Duration(size/limit*float64(time.Second)) - time.Since(start)
	if sd < time.Second/10 {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(sd):
	}
	return nil
}

func (c *Agent) cacheBlob(info *BlobInfo) (int64, int, error) {
	ctx := context.Background()
	u := &url.URL{
		Scheme: "https",
		Host:   info.Host,
		Path:   fmt.Sprintf("/v2/%s/blobs/%s", info.Image, info.Blobs),
	}
	forwardReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		c.logger.Warn("failed to new request", "url", u.String(), "error", err)
		return 0, 0, err
	}

	forwardReq.Header.Set("Accept", "*/*")

	resp, err := c.httpClient.Do(forwardReq)
	if err != nil {
		c.logger.Warn("failed to request", "url", u.String(), "error", err)
		return 0, 0, errcode.ErrorCodeUnknown
	}
	defer func() {
		resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return 0, 0, errcode.ErrorCodeDenied
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		c.logger.Error("upstream denied", "statusCode", resp.StatusCode, "url", u.String())
		return 0, 0, errcode.ErrorCodeDenied
	}
	if resp.StatusCode < http.StatusOK ||
		(resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest) {
		c.logger.Error("upstream unkown code", "statusCode", resp.StatusCode, "url", u.String())
		return 0, 0, errcode.ErrorCodeUnknown
	}

	if resp.StatusCode >= http.StatusBadRequest {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err != nil {
			c.logger.Error("failed to get body", "statusCode", resp.StatusCode, "url", u.String(), "error", err)
			return 0, 0, errcode.ErrorCodeUnknown
		}
		if !json.Valid(body) {
			c.logger.Error("invalid body", "statusCode", resp.StatusCode, "url", u.String(), "body", string(body))
			return 0, 0, errcode.ErrorCodeDenied
		}
		var retErrs errcode.Errors
		err = retErrs.UnmarshalJSON(body)
		if err != nil {
			c.logger.Error("failed to unmarshal body", "statusCode", resp.StatusCode, "url", u.String(), "body", string(body))
			return 0, 0, errcode.ErrorCodeUnknown
		}
		return 0, resp.StatusCode, retErrs
	}

	size, err := c.cache.PutBlob(ctx, info.Blobs, resp.Body)
	if err != nil {
		return 0, 0, err
	}
	return size, 0, nil
}

func (c *Agent) serveCachedBlob(rw http.ResponseWriter, r *http.Request, blob string, info *BlobInfo, t *token.Token, size int64, start time.Time) {
	if size != 0 && r.Method == http.MethodHead {
		rw.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		rw.Header().Set("Content-Type", "application/octet-stream")
		return
	}

	if !t.NoRateLimit {
		err := sleepDuration(r.Context(), float64(size), float64(t.RateLimitPerSecond), start)
		if err != nil {
			return
		}
	}

	if c.blobsLENoAgent < 0 || int64(c.blobsLENoAgent) > size {
		data, err := c.cache.GetBlob(r.Context(), info.Blobs)
		if err != nil {
			c.logger.Info("failed to get blob", "digest", blob, "error", err)
			c.blobCache.Remove(info.Blobs)
			utils.ServeError(rw, r, errcode.ErrorCodeUnknown, 0)
			return
		}
		defer data.Close()

		c.blobCache.Put(info.Blobs, size)

		rw.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		rw.Header().Set("Content-Type", "application/octet-stream")
		io.Copy(rw, data)
		return
	}

	referer := r.RemoteAddr
	if info != nil {
		referer += fmt.Sprintf("%d:%s/%s", t.UserID, info.Host, info.Image)
	}

	u, err := c.cache.RedirectBlob(r.Context(), blob, referer)
	if err != nil {
		c.logger.Info("failed to redirect blob", "digest", blob, "error", err)
		c.blobCache.Remove(info.Blobs)
		utils.ServeError(rw, r, errcode.ErrorCodeUnknown, 0)
		return
	}

	c.blobCache.Put(info.Blobs, size)

	c.logger.Info("Cache hit", "digest", blob, "url", u)
	http.Redirect(rw, r, u, http.StatusTemporaryRedirect)
}
