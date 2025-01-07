package gateway

import (
	"context"
	"log/slog"
	"time"

	"github.com/wzshiming/imc"
)

type manifestCache struct {
	tag      *imc.Cache[cacheKey, cacheTagValue]
	digest   *imc.Cache[cacheKey, cacheDigestValue]
	duration time.Duration
}

func newManifestCache(duration time.Duration) *manifestCache {
	return &manifestCache{
		tag:      imc.NewCache[cacheKey, cacheTagValue](),
		digest:   imc.NewCache[cacheKey, cacheDigestValue](),
		duration: duration,
	}
}

func (m *manifestCache) Start(ctx context.Context, logger *slog.Logger) {
	go m.digest.RunEvict(ctx, func(key cacheKey, value cacheDigestValue) bool {
		if value.Error != nil {
			logger.Info("evict manifest digest error", "key", key, "error", value.Error)
		} else {
			logger.Info("evict manifest digest", "key", key)
		}
		return true
	})

	go m.tag.RunEvict(ctx, func(key cacheKey, value cacheTagValue) bool {
		if value.Error != nil {
			logger.Info("evict manifest tag error", "key", key, "error", value.Error)
		} else {
			logger.Info("evict manifest tag", "key", key)
		}
		return true
	})
}

func (m *manifestCache) Get(info *PathInfo) (cacheValue, bool) {
	key := manifestCacheKey(info)
	if !info.IsDigestManifests {
		val, ok := m.tag.Get(key)
		if !ok {
			return cacheValue{}, false
		}
		if val.Error != nil {
			return cacheValue{
				Error:      val.Error,
				StatusCode: val.StatusCode,
			}, true
		}
		key.Tag = val.Digest
	}
	val, ok := m.digest.Get(key)
	if !ok {
		return cacheValue{}, false
	}
	if val.Error != nil {
		return cacheValue{
			Error:      val.Error,
			StatusCode: val.StatusCode,
		}, true
	}

	return cacheValue{
		Digest:    key.Tag,
		MediaType: val.MediaType,
		Length:    val.Length,
	}, true
}

func (m *manifestCache) PutError(info *PathInfo, err error, sc int) {
	key := manifestCacheKey(info)
	if !info.IsDigestManifests {
		m.tag.SetWithTTL(key, cacheTagValue{
			Error:      err,
			StatusCode: sc,
		}, m.duration)
	} else {
		m.digest.SetWithTTL(key, cacheDigestValue{
			Error:      err,
			StatusCode: sc,
		}, m.duration)
	}
}

func (m *manifestCache) Put(info *PathInfo, val cacheValue) {
	key := manifestCacheKey(info)
	if !info.IsDigestManifests {
		m.tag.SetWithTTL(key, cacheTagValue{
			Digest: val.Digest,
		}, m.duration)

		if val.Digest != "" {
			key.Tag = val.Digest
		}
	}

	m.digest.SetWithTTL(key, cacheDigestValue{
		MediaType: val.MediaType,
		Length:    val.Length,
	}, m.duration)

}

type cacheKey struct {
	Host  string
	Image string
	Tag   string
}

type cacheTagValue struct {
	Digest     string
	Error      error
	StatusCode int
}

type cacheDigestValue struct {
	MediaType  string
	Length     string
	Error      error
	StatusCode int
}

type cacheValue struct {
	Digest     string
	MediaType  string
	Length     string
	Error      error
	StatusCode int
}

func manifestCacheKey(info *PathInfo) cacheKey {
	return cacheKey{
		Host:  info.Host,
		Image: info.Image,
		Tag:   info.Manifests,
	}
}
