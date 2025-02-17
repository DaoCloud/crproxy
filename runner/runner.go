package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daocloud/crproxy/cache"
	"github.com/daocloud/crproxy/internal/spec"
	"github.com/daocloud/crproxy/queue/client"
	"github.com/daocloud/crproxy/queue/model"
	csync "github.com/daocloud/crproxy/sync"
	"github.com/wzshiming/httpseek"
	"github.com/wzshiming/sss"
)

type Runner struct {
	resumeSize int

	bigCacheSize  int
	bigCache      *cache.Cache
	manifestCache *cache.Cache

	caches      []*cache.Cache
	httpClient  *http.Client
	queueClient *client.MessageClient
	syncManager *csync.SyncManager
	lease       string

	pendingMut  sync.Mutex
	blobPending map[int64]client.MessageResponse
	syncBlobCh  chan struct{}

	manifestPending map[int64]client.MessageResponse
	syncManifestCh  chan struct{}

	filterPlatform func(pf spec.Platform) bool

	logger *slog.Logger
}

type Option func(r *Runner)

func WithHttpClient(httpClient *http.Client) Option {
	return func(r *Runner) {
		r.httpClient = httpClient
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(r *Runner) {
		r.logger = logger
	}
}

func WithCaches(caches ...*cache.Cache) Option {
	return func(r *Runner) {
		r.caches = caches
	}
}

func WithFilterPlatform(filterPlatform func(pf spec.Platform) bool) Option {
	return func(r *Runner) {
		r.filterPlatform = filterPlatform
	}
}

func WithQueueClient(queueClient *client.MessageClient) Option {
	return func(r *Runner) {
		r.queueClient = queueClient
	}
}

func WithLease(lease string) Option {
	return func(r *Runner) {
		r.lease = lease
	}
}

func WithBigCache(cache *cache.Cache, size int) Option {
	return func(c *Runner) {
		c.bigCache = cache
		c.bigCacheSize = size
	}
}

func WithManifestCache(cache *cache.Cache) Option {
	return func(c *Runner) {
		c.manifestCache = cache
	}
}

func WithResumeSize(resumeSize int) Option {
	return func(c *Runner) {
		c.resumeSize = resumeSize
	}
}

func NewRunner(opts ...Option) (*Runner, error) {
	r := &Runner{
		httpClient:      http.DefaultClient,
		blobPending:     map[int64]client.MessageResponse{},
		syncBlobCh:      make(chan struct{}, 1),
		manifestPending: map[int64]client.MessageResponse{},
		syncManifestCh:  make(chan struct{}, 1),
	}

	for _, opt := range opts {
		opt(r)
	}

	if r.queueClient == nil {
		return nil, fmt.Errorf("queueClient must not be nil")
	}

	if r.lease == "" {
		return nil, fmt.Errorf("lease must not be empty")
	}

	if len(r.caches) == 0 {
		return nil, fmt.Errorf("at least one cache must be provided")
	}

	return r, nil

}

func (r *Runner) Run(ctx context.Context) error {
	r.logger.Info("lease", "id", r.lease)

	r.sync(ctx)
	return ctx.Err()
}

func (r *Runner) watch(ctx context.Context) {
	for ctx.Err() == nil {
		err := r.runWatch(ctx)
		if err != nil {
			r.logger.Error("watch", "error", err)
		}
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return
		}
	}
}

func (r *Runner) sync(ctx context.Context) {
	watchCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go r.watch(watchCtx)

	wg := sync.WaitGroup{}

	wg.Add(3)
	go func() {
		defer wg.Done()
		r.runBlobSync(ctx)
	}()
	for i := 0; i != 2; i++ {
		go func() {
			defer wg.Done()
			r.runManifestSync(ctx)
		}()
	}
	wg.Wait()
}

func (r *Runner) runBlobSync(ctx context.Context) {
	for {
		err := r.runOnceBlobSync(context.Background())
		if err != nil {
			if err != errWait {
				r.logger.Warn("runOnceBlobSync", "error", err)
				select {
				case <-time.After(time.Second):
				case <-ctx.Done():
					return
				}
			} else {
				select {
				case <-r.syncBlobCh:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (r *Runner) runManifestSync(ctx context.Context) {
	for {
		err := r.runOnceManifestSync(context.Background())
		if err != nil {
			if err != errWait {
				r.logger.Warn("runOnceManifestSync", "error", err)
				select {
				case <-time.After(time.Second):
				case <-ctx.Done():
					return
				}
			} else {
				select {
				case <-r.syncManifestCh:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (r *Runner) runWatch(ctx context.Context) error {
	ch, err := r.queueClient.WatchList(ctx)
	if err != nil {
		return err
	}

	r.pendingMut.Lock()
	clear(r.blobPending)
	clear(r.manifestPending)
	r.pendingMut.Unlock()

	for msg := range ch {
		if strings.HasPrefix(msg.Content, "sha256:") {
			r.pendingMut.Lock()
			if msg.Status == model.StatusPending {
				r.blobPending[msg.MessageID] = msg
			} else {
				delete(r.blobPending, msg.MessageID)
			}
			r.pendingMut.Unlock()

			if msg.Status == model.StatusPending {
				select {
				case r.syncBlobCh <- struct{}{}:
				default:
				}
			}
		} else {
			r.pendingMut.Lock()
			if msg.Status == model.StatusPending {
				r.manifestPending[msg.MessageID] = msg
			} else {
				delete(r.manifestPending, msg.MessageID)
			}
			r.pendingMut.Unlock()

			if msg.Status == model.StatusPending {
				select {
				case r.syncManifestCh <- struct{}{}:
				default:
				}
			}
		}
	}
	return nil
}

func (r *Runner) getBlobPending() []client.MessageResponse {
	r.pendingMut.Lock()
	defer r.pendingMut.Unlock()

	var pendingMessages []client.MessageResponse
	for _, msg := range r.blobPending {
		if msg.Status == model.StatusPending {
			pendingMessages = append(pendingMessages, msg)
		}
	}

	sort.Slice(pendingMessages, func(i, j int) bool {
		a := pendingMessages[i]
		b := pendingMessages[j]

		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		return a.MessageID < b.MessageID
	})

	return pendingMessages
}

func (r *Runner) getManifestPending() []client.MessageResponse {
	r.pendingMut.Lock()
	defer r.pendingMut.Unlock()

	var pendingMessages []client.MessageResponse
	for _, msg := range r.manifestPending {
		if msg.Status == model.StatusPending {
			pendingMessages = append(pendingMessages, msg)
		}
	}

	sort.Slice(pendingMessages, func(i, j int) bool {
		a := pendingMessages[i]
		b := pendingMessages[j]

		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		return a.MessageID < b.MessageID
	})

	return pendingMessages
}

var errWait = fmt.Errorf("no message received and no errors occurred")

func (r *Runner) runOnceBlobSync(ctx context.Context) error {
	var (
		err  error
		errs []error
		resp client.MessageResponse
	)

	pending := r.getBlobPending()
	if len(pending) == 0 {
		return errWait
	}

	for _, msg := range pending {
		resp, err = r.queueClient.Consume(ctx, msg.MessageID, r.lease)
		if err != nil {
			errs = append(errs, err)
		} else {
			break
		}
	}

	if resp.MessageID == 0 || resp.Content == "" {
		if len(errs) == 0 {
			return errWait
		}
		return errors.Join(errs...)
	}

	return r.blobSync(ctx, resp)
}

func (r *Runner) runOnceManifestSync(ctx context.Context) error {
	var (
		err  error
		errs []error
		resp client.MessageResponse
	)

	pending := r.getManifestPending()
	if len(pending) == 0 {
		return errWait
	}

	for _, msg := range pending {
		resp, err = r.queueClient.Consume(ctx, msg.MessageID, r.lease)
		if err != nil {
			errs = append(errs, err)
		} else {
			break
		}
	}

	if resp.MessageID == 0 || resp.Content == "" {
		if len(errs) == 0 {
			return errWait
		}
		return errors.Join(errs...)
	}

	return r.manifestSync(ctx, resp)
}

func (r *Runner) blob(ctx context.Context, host, name, blob string, size int64, gotSize, progress *atomic.Int64) error {
	u := &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   fmt.Sprintf("/v2/%s/blobs/%s", name, blob),
	}

	if size == 0 {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
		if err != nil {
			return err
		}
		resp, err := r.httpClient.Do(req)
		if err != nil {
			return err
		}
		if resp.Body != nil {
			_ = resp.Body.Close()
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to head blob: status code %d", resp.StatusCode)
		}
		size = resp.ContentLength
	}

	if size > 0 {
		gotSize.Store(size)
	}

	var caches []*cache.Cache

	if r.bigCache != nil && r.bigCacheSize > 0 && size >= int64(r.bigCacheSize) {
		caches = append([]*cache.Cache{r.bigCache}, r.caches...)
	} else {
		caches = append(caches, r.caches...)
	}

	var subCaches []*cache.Cache
	for _, cache := range caches {
		stat, err := cache.StatBlob(ctx, blob)
		if err == nil {
			gotSize := stat.Size()
			if size == gotSize {
				continue
			}
			r.logger.Error("size is not meeting expectations", "digest", blob, "size", size, "gotSize", gotSize)
		}
		subCaches = append(subCaches, cache)
	}

	if len(subCaches) == 0 {
		r.logger.Info("skip blob by cache", "digest", blob)
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}

	if r.resumeSize != 0 && size > int64(r.resumeSize) {
		if len(subCaches) == 1 {
			f, err := subCaches[0].BlobWriter(ctx, blob, true)
			if err == nil {

				seeker := httpseek.NewSeeker(ctx, r.httpClient.Transport, req)

				_, err = seeker.Seek(f.Size(), 0)
				if err != nil {
					return err
				}

				progress.Store(f.Size())

				body := &readerCounter{
					r:       seeker,
					counter: progress,
				}
				_, err = io.Copy(f, body)
				if err != nil {
					return err
				}

				err = f.Commit(ctx)
				if err != nil {
					return err
				}

				fi, err := subCaches[0].StatBlob(ctx, blob)
				if err != nil {
					return err
				}

				if fi.Size() != size {
					err := subCaches[0].DeleteBlob(ctx, blob)
					if err != nil {
						return fmt.Errorf("%s is %d, but expected %d: %w", blob, fi.Size(), size, err)
					}
					return fmt.Errorf("%s is %d, but expected %d", blob, fi.Size(), size)
				}
				return nil
			}
		} else {
			var offset int64 = math.MaxInt

			rbws := []sss.FileWriter{}
			for _, cache := range subCaches {
				f, err := cache.BlobWriter(ctx, blob, true)
				if err == nil {
					if offset != 0 {
						offset = min(offset, f.Size())
					}
					rbws = append(rbws, f)

				} else {
					offset = 0
					f, err = cache.BlobWriter(ctx, blob, false)
					if err != nil {
						return err
					}
					rbws = append(rbws, f)
				}
			}

			var writers []io.Writer
			for _, w := range rbws {
				n := w.Size() - offset
				if n == 0 {
					writers = append(writers, w)
				} else if n > 0 {
					writers = append(writers, &skipWriter{
						writer: w,
						offset: uint64(n),
					})
				} else {
					panic("crproxy.runner: resume write blob error")
				}
			}

			seeker := httpseek.NewSeeker(ctx, r.httpClient.Transport, req)

			_, err := seeker.Seek(offset, 0)
			if err != nil {
				return err
			}

			progress.Store(offset)

			body := &readerCounter{
				r:       seeker,
				counter: progress,
			}

			n, err := io.Copy(io.MultiWriter(writers...), body)
			if err != nil {
				return fmt.Errorf("copy blob failed: %w", err)
			}

			if offset+n != size {
				return fmt.Errorf("copy blob failed: expected size %d, got offset %d, append %d", size, offset, n)
			}

			var errs []error
			for _, c := range rbws {
				err := c.Commit(ctx)
				if err != nil {
					errs = append(errs, err)
				}
			}

			for _, cache := range subCaches {
				fi, err := cache.StatBlob(ctx, blob)
				if err != nil {
					errs = append(errs, err)
					continue
				}

				if fi.Size() != size {
					if err := cache.DeleteBlob(ctx, blob); err != nil {
						errs = append(errs, fmt.Errorf("%s is %d, but expected %d: %w", blob, fi.Size(), size, err))
					} else {
						errs = append(errs, fmt.Errorf("%s is %d, but expected %d", blob, fi.Size(), size))
					}
				}
			}

			return errors.Join(errs...)
		}
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get blob: status code %d", resp.StatusCode)
	}

	r.logger.Info("start sync blob", "digest", blob, "url", u.String())

	if resp.ContentLength > 0 && size > 0 {
		if resp.ContentLength != size {
			return fmt.Errorf("failed to retrieve blob: expected size %d, got %d", size, resp.ContentLength)
		}
	}

	body := &readerCounter{
		r:       resp.Body,
		counter: progress,
	}

	if len(subCaches) == 1 {
		n, err := subCaches[0].PutBlob(ctx, blob, body)
		if err != nil {
			return fmt.Errorf("put blob failed: %w", err)
		}

		r.logger.Info("finish sync blob", "digest", blob, "size", n)
		return nil
	}

	var writers []io.Writer
	var closers []io.Closer
	var wg sync.WaitGroup

	for _, ca := range subCaches {
		pr, pw := io.Pipe()
		writers = append(writers, pw)
		closers = append(closers, pw)
		wg.Add(1)
		go func(cache *cache.Cache, pr io.Reader) {
			defer wg.Done()
			_, err := cache.PutBlob(ctx, blob, pr)
			if err != nil {
				r.logger.Error("put blob failed", "digest", blob, "error", err)
				io.Copy(io.Discard, pr)
				return
			}
		}(ca, pr)
	}

	n, err := io.Copy(io.MultiWriter(writers...), body)
	if err != nil {
		return fmt.Errorf("copy blob failed: %w", err)
	}
	for _, c := range closers {
		c.Close()
	}

	wg.Wait()

	r.logger.Info("finish sync blob", "digest", blob, "size", n)
	return nil
}

func (r *Runner) blobSync(ctx context.Context, resp client.MessageResponse) error {
	var errCh = make(chan error, 1)

	var gotSize, progress atomic.Int64

	go func() {
		errCh <- r.blob(ctx, resp.Data.Host, resp.Data.Image, resp.Content, resp.Data.Size, &gotSize, &progress)
	}()

	return r.heartbeat(ctx, resp.MessageID, &gotSize, &progress, errCh)
}

func (r *Runner) manifestSync(ctx context.Context, resp client.MessageResponse) error {
	var fullImage string
	var tagOrBlob string
	if i := strings.Index(resp.Content, "@"); i > 0 {
		fullImage = resp.Content[:i]
		tagOrBlob = resp.Content[i+1:]
	} else if i := strings.Index(resp.Content, ":"); i > 0 {
		fullImage = resp.Content[:i]
		tagOrBlob = resp.Content[i+1:]
	} else {
		_ = r.queueClient.Failed(ctx, resp.MessageID, client.FailedRequest{
			Lease: r.lease,
			Data: model.MessageAttr{
				Error: "invalid content format",
			},
		})
		return fmt.Errorf("invalid content format: %s", resp.Content)
	}

	hostAndImage := strings.SplitN(fullImage, "/", 2)
	if len(hostAndImage) != 2 {
		_ = r.queueClient.Failed(ctx, resp.MessageID, client.FailedRequest{
			Lease: r.lease,
			Data: model.MessageAttr{
				Error: "invalid content format",
			},
		})
		return fmt.Errorf("invalid content format: %s", resp.Content)
	}
	host := hostAndImage[0]
	image := hostAndImage[1]

	var errCh = make(chan error, 1)
	var gotSize, progress atomic.Int64
	go func() {
		errCh <- r.manifest(ctx, resp.MessageID, host, image, tagOrBlob, resp.Priority, &gotSize, &progress)
	}()

	return r.heartbeat(ctx, resp.MessageID, &gotSize, &progress, errCh)
}

func (r *Runner) heartbeat(ctx context.Context, messageID int64, gotSize, progress *atomic.Int64, errCh chan error) error {
	ticker := time.NewTicker(time.Millisecond * time.Duration(100+rand.Int32N(900)))
	defer ticker.Stop()

	var prevProgress int64 = -1

	for {
		select {
		case <-ticker.C:
			p := progress.Load()
			if prevProgress == p {
				prevProgress = -1
				continue
			}

			prevProgress = p

			err := r.queueClient.Heartbeat(ctx, messageID, client.HeartbeatRequest{
				Lease: r.lease,
				Data: model.MessageAttr{
					Size:     gotSize.Load(),
					Progress: p,
				},
			})

			if err != nil {
				r.logger.Error("Heartbeat", "error", err)
			}

			ticker.Reset(10*time.Second + time.Millisecond*time.Duration(rand.UintN(1000)))
		case err := <-errCh:
			if err == nil {
				_ = r.queueClient.Heartbeat(ctx, messageID, client.HeartbeatRequest{
					Lease: r.lease,
					Data: model.MessageAttr{
						Size:     gotSize.Load(),
						Progress: progress.Load(),
					},
				})
				return r.queueClient.Complete(ctx, messageID, client.CompletedRequest{
					Lease: r.lease,
				})
			}

			if errors.Is(err, context.Canceled) {
				err0 := r.queueClient.Cancel(ctx, messageID, client.CancelRequest{
					Lease: r.lease,
				})
				if err0 != nil {
					return errors.Join(err, err0)
				}

				return err
			}

			err0 := r.queueClient.Failed(ctx, messageID, client.FailedRequest{
				Lease: r.lease,
				Data: model.MessageAttr{
					Error: err.Error(),
				},
			})
			if err0 != nil {
				return errors.Join(err, err0)
			}

			return err
		case <-ctx.Done():
			return r.queueClient.Cancel(ctx, messageID, client.CancelRequest{
				Lease: r.lease,
			})
		}
	}
}

var acceptsStr = "application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"

func (r *Runner) manifest(ctx context.Context, messageID int64, host, image, tagOrBlob string, priority int, gotSize, progress *atomic.Int64) error {

	u := &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   fmt.Sprintf("/v2/%s/manifests/%s", image, tagOrBlob),
	}

	var caches []*cache.Cache

	if r.manifestCache != nil {
		caches = append([]*cache.Cache{r.manifestCache}, r.caches...)
	} else {
		caches = append(caches, r.caches...)
	}

	var subCaches []*cache.Cache

	if strings.HasPrefix(tagOrBlob, "sha256:") {
		for _, cache := range caches {
			exist, _ := cache.StatManifest(ctx, host, image, tagOrBlob)
			if !exist {
				subCaches = append(subCaches, cache)
			}
		}
	} else if u.Host != "ollama.com" {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", acceptsStr)
		resp, err := r.httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.Body != nil {
			_ = resp.Body.Close()
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to head manifest: status code %d", resp.StatusCode)
		}

		digest := resp.Header.Get("Docker-Content-Digest")
		if digest != "" {
			for _, cache := range caches {
				exist, _ := cache.StatOrRelinkManifest(ctx, host, image, tagOrBlob, digest)
				if !exist {
					subCaches = append(subCaches, cache)
				}
			}
		} else {
			for _, cache := range caches {
				exist, _ := cache.StatManifest(ctx, host, image, tagOrBlob)
				if !exist {
					subCaches = append(subCaches, cache)
				}
			}
		}
	} else {
		for _, cache := range caches {
			exist, _ := cache.StatManifest(ctx, host, image, tagOrBlob)
			if !exist {
				subCaches = append(subCaches, cache)
			}
		}
	}

	if len(subCaches) == 0 {
		r.logger.Info("skip manifest by cache", "host", host, "image", image, "tagOrBlob", tagOrBlob)
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", acceptsStr)
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get manifest: status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	_ = r.queueClient.Heartbeat(ctx, messageID, client.HeartbeatRequest{
		Lease: r.lease,
		Data: model.MessageAttr{
			Host:  host,
			Image: image,
			Spec:  body,
		},
	})
	r.logger.Info("start sync maifest", "url", u.String())

	{
		m := spec.IndexManifestLayers{}
		json.Unmarshal(body, &m)
		if len(m.Manifests) != 0 {
			wg := sync.WaitGroup{}

			for _, l := range m.Manifests {
				if r.filterPlatform != nil {
					if !r.filterPlatform(l.Platform) {
						continue
					}
				}

				msg := fmt.Sprintf("%s/%s@%s", host, image, l.Digest)
				r.logger.Info("Create manifest", "msg", msg)
				mr, err := r.queueClient.Create(ctx, msg, priority, model.MessageAttr{
					Host:  host,
					Image: image,
					Size:  l.Size,
				})
				if err != nil {
					return err
				}

				mrCh, err := r.queueClient.Watch(ctx, mr.MessageID)
				if err != nil {
					return err
				}

				wg.Add(1)
				go func() {
					defer wg.Done()
					var prevSize int64
					var prevProgress int64
					for m := range mrCh {
						progress.Add(m.Data.Progress - prevProgress)
						prevProgress = m.Data.Progress

						gotSize.Add(m.Data.Size - prevSize)
						prevSize = m.Data.Size
					}

					progress.Add(prevSize - prevProgress)
				}()
			}
			wg.Wait()

			for _, cache := range subCaches {
				_, _, _, err := cache.PutManifestContent(ctx, host, image, tagOrBlob, body)
				if err != nil {
					r.logger.Error("PutManifest", "error", err)
				}
			}
			return nil
		}
	}

	{
		m := spec.ManifestLayers{}
		json.Unmarshal(body, &m)
		if len(m.Layers) != 0 {
			wg := sync.WaitGroup{}

			for _, l := range m.Layers {
				gotSize.Add(l.Size)

				r.logger.Info("Create blob", "msg", l.Digest)
				mr, err := r.queueClient.Create(ctx, l.Digest, priority, model.MessageAttr{
					Host:  host,
					Image: image,
					Size:  l.Size,
				})
				if err != nil {
					return err
				}

				mrCh, err := r.queueClient.Watch(ctx, mr.MessageID)
				if err != nil {
					return err
				}

				wg.Add(1)
				go func() {
					defer wg.Done()
					var prevProgress int64
					for m := range mrCh {
						progress.Add(m.Data.Progress - prevProgress)
						prevProgress = m.Data.Progress
					}

					progress.Add(l.Size - prevProgress)
				}()
			}

			l := m.Config

			gotSize.Add(l.Size)

			r.logger.Info("Create config blob", "msg", l.Digest)
			mr, err := r.queueClient.Create(ctx, l.Digest, priority, model.MessageAttr{
				Host:  host,
				Image: image,
				Size:  l.Size,
			})
			if err != nil {
				return err
			}
			mrCh, err := r.queueClient.Watch(ctx, mr.MessageID)
			if err != nil {
				return err
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				var prevProgress int64
				for m := range mrCh {
					progress.Add(m.Data.Progress - prevProgress)
					prevProgress = m.Data.Progress
				}

				progress.Add(l.Size - prevProgress)
			}()

			wg.Wait()

			for _, cache := range subCaches {
				_, _, _, err := cache.PutManifestContent(ctx, host, image, tagOrBlob, body)
				if err != nil {
					r.logger.Error("PutManifest", "error", err)
				}
			}

			return nil
		}
	}

	return fmt.Errorf("failed to sync manifest content: no valid manifest layers found")
}

type readerCounter struct {
	r       io.Reader
	counter *atomic.Int64
}

func (r *readerCounter) Read(b []byte) (int, error) {
	n, err := r.r.Read(b)

	r.counter.Add(int64(n))
	return n, err
}

type skipWriter struct {
	writer  io.Writer
	offset  uint64
	skipped uint64
}

func (w *skipWriter) Write(p []byte) (int, error) {
	if w.skipped >= w.offset {
		return w.writer.Write(p)
	}

	remaining := w.offset - w.skipped
	if uint64(len(p)) <= remaining {
		w.skipped += uint64(len(p))
		return len(p), nil
	}

	w.skipped = w.offset
	written, err := w.writer.Write(p[remaining:])
	return int(remaining) + written, err
}
