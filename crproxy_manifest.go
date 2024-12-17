package crproxy

import (
	"context"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/daocloud/crproxy/token"
	"github.com/docker/distribution/registry/api/errcode"
)

func (c *CRProxy) cacheManifestResponse(rw http.ResponseWriter, r *http.Request, info *PathInfo, t *token.Token) {
	if c.tryFirstServeCachedManifest(rw, r, info) {
		return
	}

	cli := c.client.GetClientset(info.Host, info.Image)
	resp, err := c.client.DoWithAuth(cli, r, info.Host)
	if err != nil {
		if c.fallbackServeCachedManifest(rw, r, info) {
			return
		}
		c.logger.Error("failed to request", "host", info.Host, "image", info.Image, "error", err)
		errcode.ServeJSON(rw, errcode.ErrorCodeUnknown)
		return
	}
	defer func() {
		resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		if c.fallbackServeCachedManifest(rw, r, info) {
			c.logger.Error("origin manifest response 40x, but hit caches", "host", info.Host, "image", info.Image, "error", err, "response", dumpResponse(resp))
			return
		}
		c.logger.Error("origin manifest response 40x", "host", info.Host, "image", info.Image, "error", err, "response", dumpResponse(resp))
		errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
		return
	}

	if resp.StatusCode >= http.StatusBadRequest && resp.StatusCode < http.StatusInternalServerError {
		if c.fallbackServeCachedManifest(rw, r, info) {
			c.logger.Error("origin manifest response 4xx, but hit caches", "host", info.Host, "image", info.Image, "error", err, "response", dumpResponse(resp))
			return
		}
		c.logger.Error("origin manifest response 4xx", "host", info.Host, "image", info.Image, "error", err, "response", dumpResponse(resp))
	} else if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusInternalServerError {
		if c.fallbackServeCachedManifest(rw, r, info) {
			c.logger.Error("origin manifest response 5xx, but hit caches", "host", info.Host, "image", info.Image, "error", err, "response", dumpResponse(resp))
			return
		}
		c.logger.Error("origin manifest response 5xx", "host", info.Host, "image", info.Image, "error", err, "response", dumpResponse(resp))
	}

	resp.Header.Del("Docker-Ratelimit-Source")

	header := rw.Header()
	for k, v := range resp.Header {
		key := textproto.CanonicalMIMEHeaderKey(k)
		header[key] = v
	}

	rw.WriteHeader(resp.StatusCode)

	if r.Method == http.MethodHead {
		return
	}

	if resp.StatusCode >= http.StatusOK || resp.StatusCode < http.StatusMultipleChoices {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			c.errorResponse(rw, r, err)
			return
		}

		_, _, err = c.cache.PutManifestContent(context.Background(), info.Host, info.Image, info.Manifests, body)
		if err != nil {
			c.errorResponse(rw, r, err)
			return
		}
		rw.Write(body)
	} else {
		io.Copy(rw, resp.Body)
	}
}

func (c *CRProxy) tryFirstServeCachedManifest(rw http.ResponseWriter, r *http.Request, info *PathInfo) bool {
	isHash := strings.HasPrefix(info.Manifests, "sha256:")

	if !isHash && c.manifestCacheDuration > 0 {
		last, ok := c.manifestCache.Load(manifestCacheKey(info))
		if !ok {
			return false
		}

		if time.Since(last) > c.manifestCacheDuration {
			return false
		}
	}

	return c.serveCachedManifest(rw, r, info)
}

func (c *CRProxy) fallbackServeCachedManifest(rw http.ResponseWriter, r *http.Request, info *PathInfo) bool {
	isHash := strings.HasPrefix(info.Manifests, "sha256:")
	if isHash {
		return false
	}

	return c.serveCachedManifest(rw, r, info)
}

func (c *CRProxy) serveCachedManifest(rw http.ResponseWriter, r *http.Request, info *PathInfo) bool {
	ctx := r.Context()

	content, digest, mediaType, err := c.cache.GetManifestContent(ctx, info.Host, info.Image, info.Manifests)
	if err != nil {
		c.logger.Error("Manifest cache missed", "error", err)
		return false
	}

	c.logger.Info("Manifest blob cache hit", "digest", digest)
	rw.Header().Set("Docker-Content-Digest", digest)
	rw.Header().Set("Content-Type", mediaType)
	rw.Header().Set("Content-Length", strconv.FormatInt(int64(len(content)), 10))
	if r.Method != http.MethodHead {
		rw.Write(content)
	}

	if c.manifestCacheDuration > 0 {
		c.manifestCache.Store(manifestCacheKey(info), time.Now())
	}
	return true
}

type cacheKey struct {
	Host   string
	Image  string
	Digest string
}

func manifestCacheKey(info *PathInfo) cacheKey {
	return cacheKey{
		Host:   info.Host,
		Image:  info.Image,
		Digest: info.Manifests,
	}
}
