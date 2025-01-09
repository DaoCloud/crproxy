package agent

import (
	"context"
	"log/slog"
	"time"

	"github.com/wzshiming/imc"
)

type blobCache struct {
	digest   *imc.Cache[string, blobValue]
	duration time.Duration
}

func newBlobCache(duration time.Duration) *blobCache {
	return &blobCache{
		digest:   imc.NewCache[string, blobValue](),
		duration: duration,
	}
}

func (m *blobCache) Start(ctx context.Context, logger *slog.Logger) {
	go m.digest.RunEvict(ctx, func(key string, value blobValue) bool {
		if value.Error != nil {
			logger.Info("evict blob error", "key", key, "error", value.Error)
		} else {
			logger.Info("evict blob", "key", key)
		}
		return true
	})

}

func (m *blobCache) Get(key string) (blobValue, bool) {
	return m.digest.Get(key)
}

func (m *blobCache) Remove(key string) {
	m.digest.Remove(key)
}

func (m *blobCache) PutError(key string, err error, sc int) {
	m.digest.SetWithTTL(key, blobValue{
		Error:      err,
		StatusCode: sc,
	}, m.duration)
}

func (m *blobCache) Put(key string, size int64) {
	m.digest.SetWithTTL(key, blobValue{
		Size: size,
	}, m.duration)
}

type blobValue struct {
	Size       int64
	Error      error
	StatusCode int
}
