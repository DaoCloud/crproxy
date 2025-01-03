package gateway

import (
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

func (m *manifestCache) Evict(info *PathInfo) {
	if info.IsDigestManifests {
		m.digest.Evict(nil)
	} else {
		m.tag.Evict(nil)
	}
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
				Error: val.Error,
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
			Error: val.Error,
		}, true
	}

	return cacheValue{
		Digest:    key.Tag,
		MediaType: val.MediaType,
		Length:    val.Length,
	}, true
}

func (m *manifestCache) PutError(info *PathInfo, err error) {
	key := manifestCacheKey(info)
	if !info.IsDigestManifests {
		m.tag.SetWithTTL(key, cacheTagValue{
			Error: err,
		}, m.duration)
	} else {
		m.digest.SetWithTTL(key, cacheDigestValue{
			Error: err,
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
	Digest string
	Error  error
}

type cacheDigestValue struct {
	MediaType string
	Length    string
	Error     error
}

type cacheValue struct {
	Digest    string
	MediaType string
	Length    string
	Error     error
}

func manifestCacheKey(info *PathInfo) cacheKey {
	return cacheKey{
		Host:  info.Host,
		Image: info.Image,
		Tag:   info.Manifests,
	}
}
