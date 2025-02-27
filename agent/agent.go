package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/daocloud/crproxy/cache"
	"github.com/daocloud/crproxy/internal/queue"
	"github.com/daocloud/crproxy/internal/seeker"
	"github.com/daocloud/crproxy/internal/throttled"
	"github.com/daocloud/crproxy/internal/utils"
	"github.com/daocloud/crproxy/queue/client"
	"github.com/daocloud/crproxy/queue/model"
	"github.com/daocloud/crproxy/token"
	"github.com/docker/distribution/registry/api/errcode"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"golang.org/x/time/rate"
)

var (
	prefix = "/v2/"
)

type BlobInfo struct {
	Host  string
	Image string

	Blobs string
}

type downloadBlob struct {
	ContinueFunc func() error
	Finish       func()
	Info         BlobInfo
}

type Agent struct {
	concurrency int
	queue       *queue.WeightQueue[BlobInfo]

	groupQueue []*queue.WeightQueue[*downloadBlob]

	httpClient *http.Client
	logger     *slog.Logger
	cache      *cache.Cache

	bigCacheSize int
	bigCache     *cache.Cache

	blobCacheDuration time.Duration
	blobCache         *blobCache
	authenticator     *token.Authenticator

	blobNoRedirectSize             int
	blobNoRedirectMaxSizePerSecond int
	blobNoRedirectLimit            *rate.Limiter
	forceBlobNoRedirect            bool

	queueClient *client.MessageClient
}

type Option func(c *Agent) error

func WithCache(cache *cache.Cache) Option {
	return func(c *Agent) error {
		c.cache = cache
		return nil
	}
}

func WithBigCache(cache *cache.Cache, size int) Option {
	return func(c *Agent) error {
		c.bigCache = cache
		c.bigCacheSize = size
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

func WithForceBlobNoRedirect(forceBlobNoRedirect bool) Option {
	return func(c *Agent) error {
		c.forceBlobNoRedirect = forceBlobNoRedirect
		return nil
	}
}

func WithBlobNoRedirectSize(blobNoRedirectSize int) Option {
	return func(c *Agent) error {
		c.blobNoRedirectSize = blobNoRedirectSize
		return nil
	}
}

func WithBlobNoRedirectMaxSizePerSecond(blobNoRedirectMaxSizePerSecond int) Option {
	return func(c *Agent) error {
		if blobNoRedirectMaxSizePerSecond > 0 {
			c.blobNoRedirectLimit = rate.NewLimiter(rate.Limit(blobNoRedirectMaxSizePerSecond), 32*1024)
		} else {
			c.blobNoRedirectLimit = nil
		}
		c.blobNoRedirectMaxSizePerSecond = blobNoRedirectMaxSizePerSecond
		return nil
	}
}

func WithBlobCacheDuration(blobCacheDuration time.Duration) Option {
	return func(c *Agent) error {
		if blobCacheDuration < 10*time.Second {
			blobCacheDuration = 10 * time.Second
		}
		c.blobCacheDuration = blobCacheDuration
		return nil
	}
}

func WithConcurrency(concurrency int) Option {
	return func(c *Agent) error {
		if concurrency < 1 {
			concurrency = 1
		}
		c.concurrency = concurrency
		return nil
	}
}

func WithQueueClient(queueClient *client.MessageClient) Option {
	return func(c *Agent) error {
		c.queueClient = queueClient
		return nil
	}
}

func NewAgent(opts ...Option) (*Agent, error) {
	c := &Agent{
		logger:            slog.Default(),
		httpClient:        http.DefaultClient,
		blobCacheDuration: time.Hour,
		queue:             queue.NewWeightQueue[BlobInfo](),
		groupQueue:        make([]*queue.WeightQueue[*downloadBlob], 4),
		concurrency:       10,
	}

	for _, opt := range opts {
		opt(c)
	}

	ctx := context.Background()

	c.blobCache = newBlobCache(c.blobCacheDuration)
	c.blobCache.Start(ctx, c.logger)

	for i := 0; i <= c.concurrency; i++ {
		go c.worker(ctx)
	}

	for i := range c.groupQueue {
		q := queue.NewWeightQueue[*downloadBlob]()
		c.groupQueue[i] = q
		go c.downloadBlobWorker(ctx, q)
	}

	for i := 0; i <= c.concurrency*8/10; i++ {
		q := queue.NewWeightQueue[*downloadBlob]()
		c.groupQueue[0] = q
		go c.downloadBlobWorker(ctx, q)
	}

	for i := 0; i <= c.concurrency*1/10; i++ {
		q := queue.NewWeightQueue[*downloadBlob]()
		c.groupQueue[1] = q
		go c.downloadBlobWorker(ctx, q)
	}

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

func (c *Agent) worker(ctx context.Context) {
	for {
		info, weight, finish, ok := c.queue.GetOrWaitWithDone(ctx.Done())
		if !ok {
			return
		}

		if c.queueClient != nil {
			_, err := c.waitingQueue(ctx, info.Blobs, weight, &info)
			if err == nil {
				finish()
				continue
			}
			c.logger.Warn("waitingQueue error", "info", info, "error", err)
		}
		size, continueFunc, sc, err := c.cacheBlob(&info)
		if err != nil {
			c.logger.Warn("failed download file request", "info", info, "error", err)
			c.blobCache.PutError(info.Blobs, err, sc)
			finish()
			continue
		}

		group, ew := sizeToGroupAndWeight(size)
		if group >= uint(len(c.groupQueue)) {
			group = uint(len(c.groupQueue)) - 1
		}

		c.groupQueue[group].AddWeight(&downloadBlob{
			ContinueFunc: continueFunc,
			Finish:       finish,
			Info:         info,
		}, weight+ew)
	}
}

func (c *Agent) downloadBlobWorker(ctx context.Context, queue *queue.WeightQueue[*downloadBlob]) {
	for {
		bb, _, finish, ok := queue.GetOrWaitWithDone(ctx.Done())
		if !ok {
			return
		}
		err := bb.ContinueFunc()
		if err != nil {
			c.logger.Warn("failed download file", "info", bb.Info, "error", err)
			c.blobCache.PutError(bb.Info.Blobs, err, 0)
		} else {
			c.logger.Info("finish download file", "info", bb.Info)
		}
		finish()
		bb.Finish()
	}
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

	value, ok := c.blobCache.Get(info.Blobs)
	if ok {
		if value.Error != nil {
			utils.ServeError(rw, r, value.Error, 0)
			return
		}

		if c.serveCachedBlobHead(rw, r, value.Size) {
			return
		}

		if value.BigCache {
			c.serveBigCachedBlob(rw, r, info.Blobs, info, t, value.ModTime, value.Size, start)
			return
		}

		c.serveCachedBlob(rw, r, info.Blobs, info, t, value.ModTime, value.Size, start)
		return
	}

	stat, err := c.cache.StatBlob(ctx, info.Blobs)
	if err == nil {
		if c.bigCache != nil && stat.Size() >= int64(c.bigCacheSize) {
			stat, err := c.bigCache.StatBlob(ctx, info.Blobs)
			if err == nil {
				if c.serveCachedBlobHead(rw, r, stat.Size()) {
					return
				}

				c.serveBigCachedBlob(rw, r, info.Blobs, info, t, stat.ModTime(), stat.Size(), start)
				return
			}
		} else {
			if c.serveCachedBlobHead(rw, r, stat.Size()) {
				return
			}

			c.serveCachedBlob(rw, r, info.Blobs, info, t, stat.ModTime(), stat.Size(), start)
			return
		}
	} else {
		if c.bigCache != nil {
			stat, err := c.bigCache.StatBlob(ctx, info.Blobs)
			if err == nil {
				if c.serveCachedBlobHead(rw, r, stat.Size()) {
					return
				}

				c.serveBigCachedBlob(rw, r, info.Blobs, info, t, stat.ModTime(), stat.Size(), start)
				return
			}
		}
	}

	select {
	case <-ctx.Done():
		return
	case <-c.queue.AddWeight(*info, t.Weight):
	}

	value, ok = c.blobCache.Get(info.Blobs)
	if ok {
		if value.Error != nil {
			utils.ServeError(rw, r, value.Error, 0)
			return
		}

		if c.serveCachedBlobHead(rw, r, value.Size) {
			return
		}

		if value.BigCache {
			c.serveBigCachedBlob(rw, r, info.Blobs, info, t, value.ModTime, value.Size, start)
			return
		}
		c.serveCachedBlob(rw, r, info.Blobs, info, t, value.ModTime, value.Size, start)
		return
	}

	if c.bigCache != nil {
		stat, err = c.bigCache.StatBlob(ctx, info.Blobs)
		if err == nil {
			if c.serveCachedBlobHead(rw, r, stat.Size()) {
				return
			}

			c.serveBigCachedBlob(rw, r, info.Blobs, info, t, stat.ModTime(), stat.Size(), start)
			return
		}
	}

	stat, err = c.cache.StatBlob(ctx, info.Blobs)
	if err == nil {
		if c.serveCachedBlobHead(rw, r, stat.Size()) {
			return
		}

		c.serveCachedBlob(rw, r, info.Blobs, info, t, stat.ModTime(), stat.Size(), start)
		return
	}

	c.logger.Error("here should never be executed", "info", info)
	utils.ServeError(rw, r, errcode.ErrorCodeUnknown, 0)
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

func (c *Agent) cacheBlob(info *BlobInfo) (int64, func() error, int, error) {
	ctx := context.Background()
	u := &url.URL{
		Scheme: "https",
		Host:   info.Host,
		Path:   fmt.Sprintf("/v2/%s/blobs/%s", info.Image, info.Blobs),
	}
	forwardReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		c.logger.Warn("failed to new request", "url", u.String(), "error", err)
		return 0, nil, 0, err
	}

	forwardReq.Header.Set("Accept", "*/*")

	resp, err := c.httpClient.Do(forwardReq)
	if err != nil {
		var tErr *transport.Error
		if errors.As(err, &tErr) {
			return 0, nil, http.StatusForbidden, errcode.ErrorCodeDenied
		}
		c.logger.Warn("failed to request", "url", u.String(), "error", err)
		return 0, nil, 0, errcode.ErrorCodeUnknown
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		resp.Body.Close()
		return 0, nil, 0, errcode.ErrorCodeDenied
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		resp.Body.Close()
		c.logger.Error("upstream denied", "statusCode", resp.StatusCode, "url", u.String())
		return 0, nil, 0, errcode.ErrorCodeDenied
	}
	if resp.StatusCode < http.StatusOK ||
		(resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest) {
		resp.Body.Close()
		c.logger.Error("upstream unkown code", "statusCode", resp.StatusCode, "url", u.String())
		return 0, nil, 0, errcode.ErrorCodeUnknown
	}

	if resp.StatusCode >= http.StatusBadRequest {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		resp.Body.Close()
		if err != nil {
			c.logger.Error("failed to get body", "statusCode", resp.StatusCode, "url", u.String(), "error", err)
			return 0, nil, 0, errcode.ErrorCodeUnknown
		}
		if !json.Valid(body) {
			c.logger.Error("invalid body", "statusCode", resp.StatusCode, "url", u.String(), "body", string(body))
			return 0, nil, 0, errcode.ErrorCodeDenied
		}
		var retErrs errcode.Errors
		err = retErrs.UnmarshalJSON(body)
		if err != nil {
			c.logger.Error("failed to unmarshal body", "statusCode", resp.StatusCode, "url", u.String(), "body", string(body))
			return 0, nil, 0, errcode.ErrorCodeUnknown
		}
		return 0, nil, resp.StatusCode, retErrs
	}

	continueFunc := func() error {
		defer resp.Body.Close()

		if c.bigCache != nil && c.bigCacheSize > 0 && resp.ContentLength > int64(c.bigCacheSize) {
			size, err := c.bigCache.PutBlob(ctx, info.Blobs, resp.Body)
			if err != nil {
				return fmt.Errorf("Put to big cache: %w", err)
			}

			stat, err := c.cache.StatBlob(ctx, info.Blobs)
			if err != nil {
				return err
			}

			if size != stat.Size() {
				return fmt.Errorf("size mismatch: expected %d, got %d", stat.Size(), size)
			}
			c.blobCache.PutNoTTL(info.Blobs, stat.ModTime(), size, true)
			return nil
		}

		size, err := c.cache.PutBlob(ctx, info.Blobs, resp.Body)
		if err != nil {
			return err
		}

		stat, err := c.cache.StatBlob(ctx, info.Blobs)
		if err != nil {
			return err
		}

		if size != stat.Size() {
			return fmt.Errorf("size mismatch: expected %d, got %d", stat.Size(), size)
		}
		c.blobCache.Put(info.Blobs, stat.ModTime(), size, false)
		return nil
	}

	return resp.ContentLength, continueFunc, 0, nil
}

func (c *Agent) rateLimit(rw http.ResponseWriter, r *http.Request, blob string, info *BlobInfo, t *token.Token, size int64, start time.Time) {
	if !t.NoRateLimit {
		err := sleepDuration(r.Context(), float64(size), float64(t.RateLimitPerSecond), start)
		if err != nil {
			return
		}
	}
}

func (c *Agent) serveCachedBlobHead(rw http.ResponseWriter, r *http.Request, size int64) bool {
	if size != 0 && r.Method == http.MethodHead {
		rw.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		rw.Header().Set("Content-Type", "application/octet-stream")
		return true
	}
	return false
}

func (c *Agent) serveBigCachedBlob(rw http.ResponseWriter, r *http.Request, blob string, info *BlobInfo, t *token.Token, modTime time.Time, size int64, start time.Time) {
	c.rateLimit(rw, r, info.Blobs, info, t, size, start)

	referer := r.RemoteAddr
	if info != nil {
		referer = fmt.Sprintf("%d-%d:%s:%s/%s", t.RegistryID, t.TokenID, referer, info.Host, info.Image)
	}

	u, err := c.bigCache.RedirectBlob(r.Context(), blob, referer)
	if err != nil {
		c.logger.Info("failed to redirect blob", "digest", blob, "error", err)
		c.blobCache.Remove(info.Blobs)
		utils.ServeError(rw, r, errcode.ErrorCodeUnknown, 0)
		return
	}

	c.blobCache.PutNoTTL(info.Blobs, modTime, size, true)

	c.logger.Info("Big Cache hit", "digest", blob, "url", u)
	http.Redirect(rw, r, u, http.StatusTemporaryRedirect)
	return
}

func (c *Agent) serveCachedBlob(rw http.ResponseWriter, r *http.Request, blob string, info *BlobInfo, t *token.Token, modTime time.Time, size int64, start time.Time) {
	if t.AlwaysRedirect {
		c.serveCachedBlobRedirect(rw, r, blob, info, t, modTime, size, start)
		return
	}

	if size > int64(c.blobNoRedirectSize) {
		c.serveCachedBlobRedirect(rw, r, blob, info, t, modTime, size, start)
		return
	}

	ctx := r.Context()

	if c.blobNoRedirectLimit != nil {
		if c.blobNoRedirectLimit.Reserve().Delay() != 0 {
			c.serveCachedBlobRedirect(rw, r, blob, info, t, modTime, size, start)
			return
		}

		err := c.blobNoRedirectLimit.Wait(ctx)
		if err != nil {
			c.logger.Info("failed to wait limit", "error", err)
			return
		}
	}

	rw.Header().Set("Content-Type", "application/octet-stream")

	rs := seeker.NewReadSeekCloser(func(start int64) (io.ReadCloser, error) {
		data, err := c.cache.GetBlobWithOffset(ctx, info.Blobs, start)
		if err != nil {
			return nil, err
		}

		var body io.Reader = data
		if t.RateLimitPerSecond > 0 {
			limit := rate.NewLimiter(rate.Limit(t.RateLimitPerSecond), 16*1024)
			body = throttled.NewThrottledReader(ctx, body, limit)
		}

		if c.blobNoRedirectLimit != nil {
			body = throttled.NewThrottledReader(ctx, body, c.blobNoRedirectLimit)
		}

		return struct {
			io.Reader
			io.Closer
		}{
			Reader: body,
			Closer: data,
		}, nil
	}, size)
	defer rs.Close()

	http.ServeContent(rw, r, "", modTime, rs)

	c.blobCache.Put(info.Blobs, modTime, size, false)

	return
}

func (c *Agent) serveCachedBlobRedirect(rw http.ResponseWriter, r *http.Request, blob string, info *BlobInfo, t *token.Token, modTime time.Time, size int64, start time.Time) {
	c.rateLimit(rw, r, info.Blobs, info, t, size, start)

	referer := r.RemoteAddr
	if info != nil {
		referer = fmt.Sprintf("%d-%d:%s:%s/%s", t.RegistryID, t.TokenID, referer, info.Host, info.Image)
	}

	u, err := c.cache.RedirectBlob(r.Context(), blob, referer)
	if err != nil {
		c.logger.Info("failed to redirect blob", "digest", blob, "error", err)
		c.blobCache.Remove(info.Blobs)
		utils.ServeError(rw, r, errcode.ErrorCodeUnknown, 0)
		return
	}

	c.blobCache.Put(info.Blobs, modTime, size, false)

	c.logger.Info("Cache hit", "digest", blob, "url", u)
	http.Redirect(rw, r, u, http.StatusTemporaryRedirect)
}

func (c *Agent) waitingQueue(ctx context.Context, msg string, weight int, info *BlobInfo) (client.MessageResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mr, err := c.queueClient.Create(ctx, msg, weight+1, model.MessageAttr{
		Host:  info.Host,
		Image: info.Image,
	})
	if err != nil {
		return client.MessageResponse{}, fmt.Errorf("failed to create queue: %w", err)
	}

	if mr.Status == model.StatusPending || mr.Status == model.StatusProcessing {
		c.logger.Info("watching message from queue", "msg", msg)

		chMr, err := c.queueClient.Watch(ctx, mr.MessageID)
		if err != nil {
			return client.MessageResponse{}, fmt.Errorf("failed to watch message: %w", err)
		}
	watiQueue:
		for {
			select {
			case <-ctx.Done():
				return client.MessageResponse{}, ctx.Err()
			case m, ok := <-chMr:
				if !ok {
					if mr.Status != model.StatusPending && mr.Status != model.StatusProcessing {
						break watiQueue
					}

					time.Sleep(1 * time.Second)
					chMr, err = c.queueClient.Watch(ctx, mr.MessageID)
					if err != nil {
						return client.MessageResponse{}, fmt.Errorf("failed to re-watch message: %w", err)
					}
				} else {
					mr = m
				}
			}
		}
	}

	switch mr.Status {
	case model.StatusCompleted:
		return mr, nil
	case model.StatusFailed:
		return client.MessageResponse{}, fmt.Errorf("%q Queue Error: %s", msg, mr.Data.Error)
	default:
		return client.MessageResponse{}, fmt.Errorf("unexpected status %d for message %q", mr.Status, msg)
	}
}
