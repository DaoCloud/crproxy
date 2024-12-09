package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	storagedriver "github.com/docker/distribution/registry/storage/driver"
)

type Cache struct {
	bytesPool     sync.Pool
	storageDriver storagedriver.StorageDriver
	linkExpires   time.Duration
	redirectLinks *url.URL
}

type Option func(c *Cache)

func WithLinkExpires(d time.Duration) Option {
	return func(c *Cache) {
		c.linkExpires = d
	}
}

func WithRedirectLinks(l *url.URL) Option {
	return func(c *Cache) {
		c.redirectLinks = l
	}
}

func WithStorageDriver(storageDriver storagedriver.StorageDriver) Option {
	return func(c *Cache) {
		c.storageDriver = storageDriver
	}
}

func NewCache(opts ...Option) (*Cache, error) {
	c := &Cache{
		bytesPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024)
			},
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

func (c *Cache) Redirect(ctx context.Context, blobPath string, referer string, ip string) (string, error) {
	options := map[string]interface{}{
		"method": http.MethodGet,
	}

	linkExpires := c.linkExpires
	if linkExpires > 0 {
		options["expiry"] = time.Now().Add(linkExpires)
	}

	if ip != "" {
		options["ip"] = ip
	}

	if referer != "" {
		options["referer"] = referer
	}
	u, err := c.storageDriver.URLFor(ctx, blobPath, options)
	if err != nil {
		return "", err
	}
	return u, nil
}

func (c *Cache) put(ctx context.Context, cachePath string, r io.Reader, checkFunc func(int64) error) (int64, error) {
	fw, err := c.storageDriver.Writer(ctx, cachePath, false)
	if err != nil {
		return 0, err
	}

	buf := c.bytesPool.Get().([]byte)
	defer c.bytesPool.Put(buf)

	n, err := io.CopyBuffer(fw, r, buf)
	if err != nil {
		fw.Cancel()
		return 0, err
	}

	if checkFunc != nil {
		err = checkFunc(n)
		if err != nil {
			fw.Cancel()
			return 0, err
		}
	}

	err = fw.Commit()
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (c *Cache) Put(ctx context.Context, cachePath string, r io.Reader) (int64, error) {
	return c.put(ctx, cachePath, r, nil)
}

func (c *Cache) PutContent(ctx context.Context, cachePath string, content []byte) error {
	return c.storageDriver.PutContent(ctx, cachePath, content)
}

func (c *Cache) PutWithHash(ctx context.Context, cachePath string, r io.Reader, cacheHash string, cacheSize int64) (int64, error) {
	h := sha256.New()
	return c.put(ctx, cachePath, io.TeeReader(r, h), func(i int64) error {
		if cacheSize > 0 && i != cacheSize {
			return fmt.Errorf("expected %d bytes, got %d", cacheSize, i)
		}
		hash := hex.EncodeToString(h.Sum(nil)[:])
		if cacheHash != hash {
			return fmt.Errorf("expected %s hash, got %s", cacheHash, hash)
		}
		return nil
	})
}

func (c *Cache) Get(ctx context.Context, cachePath string) (io.ReadCloser, error) {
	return c.storageDriver.Reader(ctx, cachePath, 0)
}

func (c *Cache) GetContent(ctx context.Context, cachePath string) ([]byte, error) {
	return c.storageDriver.GetContent(ctx, cachePath)
}

func (c *Cache) Stat(ctx context.Context, cachePath string) (storagedriver.FileInfo, error) {
	return c.storageDriver.Stat(ctx, cachePath)
}
