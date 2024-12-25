package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

func (c *Cache) PutManifestContent(ctx context.Context, host, image, tagOrBlob string, content []byte) (int64, string, error) {
	h := sha256.New()
	h.Write(content)
	hash := hex.EncodeToString(h.Sum(nil)[:])

	isHash := strings.HasPrefix(tagOrBlob, "sha256:")
	if isHash {
		tagOrBlob = tagOrBlob[7:]
		if tagOrBlob != hash {
			return 0, "", fmt.Errorf("expected hash %s is not same to %s", tagOrBlob, hash)
		}
	} else {
		manifestLinkPath := manifestTagCachePath(host, image, tagOrBlob)
		err := c.PutContent(ctx, manifestLinkPath, []byte("sha256:"+hash))
		if err != nil {
			return 0, "", fmt.Errorf("put manifest link path %s error: %w", manifestLinkPath, err)
		}
	}

	manifestLinkPath := manifestRevisionsCachePath(host, image, hash)
	err := c.PutContent(ctx, manifestLinkPath, []byte("sha256:"+hash))
	if err != nil {
		return 0, "", fmt.Errorf("put manifest revisions path %s error: %w", manifestLinkPath, err)
	}

	n, err := c.PutBlobContent(ctx, hash, content)
	if err != nil {
		return 0, "", fmt.Errorf("put manifest blob path %s error: %w", hash, err)
	}
	return n, hash, nil
}

func (c *Cache) GetManifestContent(ctx context.Context, host, image, tagOrBlob string) ([]byte, string, string, error) {
	var manifestLinkPath string
	isHash := strings.HasPrefix(tagOrBlob, "sha256:")
	if isHash {
		manifestLinkPath = manifestRevisionsCachePath(host, image, tagOrBlob[7:])
	} else {
		manifestLinkPath = manifestTagCachePath(host, image, tagOrBlob)
	}

	digestContent, err := c.GetContent(ctx, manifestLinkPath)
	if err != nil {
		return nil, "", "", fmt.Errorf("get manifest link path %s error: %w", manifestLinkPath, err)
	}
	digest := string(digestContent)
	content, err := c.GetBlobContent(ctx, digest)
	if err != nil {
		return nil, "", "", err
	}

	mt := struct {
		MediaType string `json:"mediaType"`
	}{}
	err = json.Unmarshal(content, &mt)
	if err != nil {
		return nil, "", "", err
	}

	mediaType := mt.MediaType
	if mediaType == "" {
		mediaType = "application/vnd.docker.distribution.manifest.v1+json"
	}

	return content, digest, mediaType, nil
}

func manifestRevisionsCachePath(host, image, tagOrBlob string) string {
	return path.Join("/docker/registry/v2/repositories", host, image, "_manifests/revisions/sha256", tagOrBlob, "link")
}

func manifestTagCachePath(host, image, tagOrBlob string) string {
	return path.Join("/docker/registry/v2/repositories", host, image, "_manifests/tags", tagOrBlob, "current/link")
}
