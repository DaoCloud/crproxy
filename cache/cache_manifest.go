package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
)

func (c *Cache) RelinkManifest(ctx context.Context, host, image, tag string, blob string) error {
	blob = cleanDigest(blob)

	_, err := c.StatBlob(ctx, blob)
	if err != nil {
		return err
	}

	manifestLinkPath := manifestTagCachePath(host, image, tag)
	err = c.PutContent(ctx, manifestLinkPath, []byte("sha256:"+blob))
	if err != nil {
		return fmt.Errorf("put manifest link path %s error: %w", manifestLinkPath, err)
	}

	manifestBlobLinkPath := manifestRevisionsCachePath(host, image, blob)
	err = c.PutContent(ctx, manifestBlobLinkPath, []byte("sha256:"+blob))
	if err != nil {
		return fmt.Errorf("put manifest revisions path %s error: %w", manifestLinkPath, err)
	}

	return nil
}

func (c *Cache) PutManifestContent(ctx context.Context, host, image, tagOrBlob string, content []byte) (int64, string, string, error) {
	mt := struct {
		MediaType string `json:"mediaType"`
	}{}
	err := json.Unmarshal(content, &mt)
	if err != nil {
		return 0, "", "", fmt.Errorf("invalid content: %w: %s", err, string(content))
	}

	mediaType := mt.MediaType
	if mediaType == "" {
		mediaType = "application/vnd.docker.distribution.manifest.v1+json"
	}

	h := sha256.New()
	h.Write(content)
	hash := hex.EncodeToString(h.Sum(nil)[:])

	isHash := strings.HasPrefix(tagOrBlob, "sha256:")
	if isHash {
		tagOrBlob = tagOrBlob[7:]
		if tagOrBlob != hash {
			return 0, "", "", fmt.Errorf("expected hash %s is not same to %s", tagOrBlob, hash)
		}
	} else {
		manifestLinkPath := manifestTagCachePath(host, image, tagOrBlob)
		err := c.PutContent(ctx, manifestLinkPath, []byte("sha256:"+hash))
		if err != nil {
			return 0, "", "", fmt.Errorf("put manifest link path %s error: %w", manifestLinkPath, err)
		}
	}

	manifestLinkPath := manifestRevisionsCachePath(host, image, hash)
	err = c.PutContent(ctx, manifestLinkPath, []byte("sha256:"+hash))
	if err != nil {
		return 0, "", "", fmt.Errorf("put manifest revisions path %s error: %w", manifestLinkPath, err)
	}

	n, err := c.PutBlobContent(ctx, hash, content)
	if err != nil {
		return 0, "", "", fmt.Errorf("put manifest blob path %s error: %w", hash, err)
	}
	return n, hash, mediaType, nil
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
		cleanErr := c.DeleteBlob(ctx, digest)
		if cleanErr != nil {
			err = errors.Join(err, cleanErr)
		}
		cleanErr = c.Delete(ctx, manifestLinkPath)
		if cleanErr != nil {
			err = errors.Join(err, cleanErr)
		}
		return nil, "", "", fmt.Errorf("invalid content: %w: %s", err, string(content))
	}

	mediaType := mt.MediaType
	if mediaType == "" {
		mediaType = "application/vnd.docker.distribution.manifest.v1+json"
	}

	return content, digest, mediaType, nil
}

func (c *Cache) StatManifest(ctx context.Context, host, image, tagOrBlob string) (bool, error) {
	var manifestLinkPath string
	isHash := strings.HasPrefix(tagOrBlob, "sha256:")
	if isHash {
		manifestLinkPath = manifestRevisionsCachePath(host, image, tagOrBlob[7:])
	} else {
		manifestLinkPath = manifestTagCachePath(host, image, tagOrBlob)
	}

	digestContent, err := c.GetContent(ctx, manifestLinkPath)
	if err != nil {
		return false, fmt.Errorf("get manifest link path %s error: %w", manifestLinkPath, err)
	}
	digest := string(digestContent)
	stat, err := c.StatBlob(ctx, digest)
	if err != nil {
		return false, err
	}

	return stat.Size() != 0, nil
}

func manifestRevisionsCachePath(host, image, blob string) string {
	blob = cleanDigest(blob)
	return path.Join("/docker/registry/v2/repositories", host, image, "_manifests/revisions/sha256", blob, "link")
}

func manifestTagCachePath(host, image, tag string) string {
	return path.Join("/docker/registry/v2/repositories", host, image, "_manifests/tags", tag, "current/link")
}
