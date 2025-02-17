package cache

import (
	"bytes"
	"context"
	"io"
	"path"
	"strings"

	"github.com/wzshiming/sss"
)

func (c *Cache) RedirectBlob(ctx context.Context, blob string, referer string) (string, error) {
	return c.Redirect(ctx, blobCachePath(blob), referer)
}

func (c *Cache) StatBlob(ctx context.Context, blob string) (sss.FileInfo, error) {
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

func (c *Cache) GetBlobWithOffset(ctx context.Context, blob string, offset int64) (io.ReadCloser, error) {
	cachePath := blobCachePath(blob)
	return c.GetWithOffset(ctx, cachePath, offset)
}

func (c *Cache) DeleteBlob(ctx context.Context, blob string) error {
	cachePath := blobCachePath(blob)
	return c.Delete(ctx, cachePath)
}

func (c *Cache) GetBlobContent(ctx context.Context, blob string) ([]byte, error) {
	r, err := c.GetBlob(ctx, blob)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func cleanDigest(blob string) string {
	return strings.TrimPrefix(blob, "sha256:")
}

func ensureDigestPrefix(blob string) string {
	if !strings.HasPrefix(blob, "sha256:") {
		return "sha256:" + blob
	}
	return blob
}

func blobCachePath(blob string) string {
	blob = cleanDigest(blob)
	return path.Join("/docker/registry/v2/blobs/sha256", blob[:2], blob, "data")
}
