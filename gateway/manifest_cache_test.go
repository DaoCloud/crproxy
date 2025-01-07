package gateway

import (
	"errors"
	"testing"
	"time"
)

func TestManifestCache(t *testing.T) {
	duration := 5 * time.Second
	cache := newManifestCache(duration)

	info := &PathInfo{Host: "localhost", Image: "test-image", Manifests: "latest", IsDigestManifests: false}
	val := cacheValue{Digest: "test-digest", MediaType: "application/json", Length: "123"}

	cache.Put(info, val)

	retrievedVal, ok := cache.Get(info)
	if !ok || retrievedVal.Digest != val.Digest {
		t.Errorf("Expected %v, got %v", val.Digest, retrievedVal.Digest)
	}

	err := errors.New("test error")
	cache.PutError(info, err, 0)
	retrievedVal, ok = cache.Get(info)
	if !ok || retrievedVal.Error == nil {
		t.Error("Expected an error to be returned")
	}

	info.IsDigestManifests = true
	cache.Put(info, cacheValue{MediaType: "application/json", Length: "123"})
	retrievedVal, ok = cache.Get(info)
	if !ok || retrievedVal.MediaType != "application/json" {
		t.Errorf("Expected media type %v, got %v", "application/json", retrievedVal.MediaType)
	}

	nonExistentInfo := &PathInfo{Host: "localhost", Image: "non-existent-image", Manifests: "latest", IsDigestManifests: false}
	_, ok = cache.Get(nonExistentInfo)
	if ok {
		t.Error("Expected cache to be empty for non-existent key")
	}
}
