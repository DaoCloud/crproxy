package runner

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/daocloud/crproxy/queue/client"
	"github.com/daocloud/crproxy/queue/model"
	csync "github.com/daocloud/crproxy/sync"
)

type Runner struct {
	client      *client.MessageClient
	syncManager *csync.SyncManager
	lease       string
	pendingMut  sync.Mutex
	pending     map[int64]client.MessageResponse
	syncCh      chan struct{}
}

func identity() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("unable to get hostname: %w", err)
	}
	hnHex := hex.EncodeToString([]byte(hostname))
	return fmt.Sprintf("%s-%d", hnHex[:16], time.Now().Unix()), nil
}

func NewRunner(httpClient *http.Client, baseURL string, adminToken string, syncManager *csync.SyncManager) (*Runner, error) {
	id, err := identity()
	if err != nil {
		return nil, err
	}
	cli := client.NewMessageClient(httpClient, baseURL, adminToken)

	return &Runner{
		client:      cli,
		lease:       id,
		syncManager: syncManager,
		pending:     make(map[int64]client.MessageResponse),
		syncCh:      make(chan struct{}),
	}, nil
}

func (r *Runner) Run(ctx context.Context, logger *slog.Logger) error {
	logger.Info("lease", "id", r.lease)
	go r.watch(ctx, logger)

	r.sync(ctx, r.lease, logger)
	return ctx.Err()
}

func (r *Runner) watch(ctx context.Context, logger *slog.Logger) {
	for ctx.Err() == nil {
		if err := r.runWatch(ctx); err != nil {
			logger.Error("watch", "error", err)
		}
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return
		}
	}
}

func (r *Runner) sync(ctx context.Context, id string, logger *slog.Logger) {
	for i := 0; ctx.Err() == nil; i++ {
		if err := r.runOnceSync(context.Background(), id, logger); err != nil {
			if err != errWait {
				logger.Error("sync", "error", err)
			} else {
				select {
				case <-r.syncCh:
				case <-ctx.Done():
					return
				}
				continue
			}
		}
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return
		}
	}
}

func (r *Runner) runWatch(ctx context.Context) error {
	ch, err := r.client.WatchList(ctx)
	if err != nil {
		return err
	}

	r.pendingMut.Lock()
	clear(r.pending)
	r.pendingMut.Unlock()

	for msg := range ch {
		r.pendingMut.Lock()
		if msg.Status == model.StatusPending {
			r.pending[msg.MessageID] = msg
		} else {
			delete(r.pending, msg.MessageID)
		}
		r.pendingMut.Unlock()

		if msg.Status == model.StatusPending {
			select {
			case r.syncCh <- struct{}{}:
			default:
			}
		}
	}
	return nil
}

func (r *Runner) getPending() []client.MessageResponse {
	r.pendingMut.Lock()
	defer r.pendingMut.Unlock()

	var pendingMessages []client.MessageResponse
	for _, msg := range r.pending {
		if msg.Status == model.StatusPending {
			pendingMessages = append(pendingMessages, msg)
		}
	}

	sort.Slice(pendingMessages, func(i, j int) bool {
		return pendingMessages[i].Priority > pendingMessages[j].Priority
	})

	return pendingMessages
}

var errWait = fmt.Errorf("no message received and no errors occurred")

func (r *Runner) runOnceSync(ctx context.Context, id string, logger *slog.Logger) error {
	var (
		err  error
		errs []error
		resp client.MessageResponse
	)

	pending := r.getPending()
	if len(pending) == 0 {
		return errWait
	}

	for _, msg := range pending {
		resp, err = r.client.Consume(ctx, msg.MessageID, id)
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

	var bmMut sync.Mutex
	var bm []model.Blob

	var errCh = make(chan error, 1)

	go func() {
		errCh <- r.syncManager.ImageWithCallback(ctx, resp.Content, func(blob string, progress, size int64) {
			bmMut.Lock()
			defer bmMut.Unlock()
			for i, m := range bm {
				if m.Digest == blob {
					bm[i].Progress = progress
					bm[i].Size = size
					return
				}
			}
			bm = append(bm, model.Blob{
				Digest:   blob,
				Progress: progress,
				Size:     size,
			})
		})
	}()

	ticker := time.NewTicker(10 * time.Second)

	for {
		select {
		case <-ticker.C:
			bmMut.Lock()
			nbm := append([]model.Blob{}, bm...)
			bmMut.Unlock()

			err := r.client.Heartbeat(ctx, resp.MessageID, client.HeartbeatRequest{
				Lease: id,
				Data: model.MessageAttr{
					Blobs: nbm,
				},
			})

			if err != nil {
				logger.Error("Heartbeat", "error", err)
			}

		case err := <-errCh:
			if err == nil {
				return r.client.Complete(ctx, resp.MessageID, client.CompletedRequest{
					Lease: id,
				})
			}

			if errors.Is(err, context.Canceled) {
				return r.client.Cancel(ctx, resp.MessageID, client.CancelRequest{
					Lease: id,
				})
			}

			return r.client.Failed(ctx, resp.MessageID, client.FailedRequest{
				Lease: id,
				Data: model.MessageAttr{
					Error: err.Error(),
				},
			})
		case <-ctx.Done():
			return r.client.Cancel(ctx, resp.MessageID, client.CancelRequest{
				Lease: id,
			})
		}
	}
}
