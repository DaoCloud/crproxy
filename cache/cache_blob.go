package cache

import (
	"bytes"
	"context"
	"io"
	"path"
	"strings"

	storagedriver "github.com/docker/distribution/registry/storage/driver"
)

func (c *Cache) RedirectBlob(ctx context.Context, blob string, referer string) (string, error) {
	return c.Redirect(ctx, blobCachePath(blob), referer)
}

func (c *Cache) StatBlob(ctx context.Context, blob string) (storagedriver.FileInfo, error) {
	return c.Stat(ctx, blobCachePath(blob))
}

func (c *Cache) PutBlob(ctx context.Context, blob string, r io.Reader) (int64, error) {
	cachePath := blobCachePath(blob)
	return c.PutWithHash(ctx, cachePath, r, cleanDigest(blob), 0)
}

func (c *Cache) PutBlobContent(ctx context.Context, blob string, content []byte) (int64, error) {
	cachePath := blobCachePath(blob)
	return c.PutWithHash(ctx, cachePath, bytes.NewBuffer(content), cleanDigest(blob), int64(len(content)))
}

func (c *Cache) GetBlob(ctx context.Context, blob string) (io.ReadCloser, error) {
	cachePath := blobCachePath(blob)
	return c.Get(ctx, cachePath)
}

func (c *Cache) GetBlobContent(ctx context.Context, blob string) ([]byte, error) {
	r, err := c.GetBlob(ctx, blob)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func cleanDigest(blob string) string {
	return strings.TrimPrefix(blob, "sha256:")
}

func blobCachePath(blob string) string {
	blob = cleanDigest(blob)
	return path.Join("/docker/registry/v2/blobs/sha256", blob[:2], blob, "data")
}
