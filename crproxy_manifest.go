package crproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/docker/distribution/registry/api/errcode"
)

func manifestRevisionsCachePath(host, image, tagOrBlob string) string {
	return path.Join("/docker/registry/v2/repositories", host, image, "_manifests/revisions/sha256", tagOrBlob, "link")
}

func manifestTagCachePath(host, image, tagOrBlob string) string {
	return path.Join("/docker/registry/v2/repositories", host, image, "_manifests/tags", tagOrBlob, "current/link")
}

func (c *CRProxy) cacheManifestResponse(rw http.ResponseWriter, r *http.Request, info *PathInfo) {
	if c.cachedManifest(rw, r, info, true) {
		return
	}

	cli := c.getClientset(info.Host, info.Image)
	resp, err := c.doWithAuth(cli, r, info.Host)
	if err != nil {
		if c.cachedManifest(rw, r, info, false) {
			return
		}
		if c.logger != nil {
			c.logger.Println("failed to request", info.Host, info.Image, err)
		}
		errcode.ServeJSON(rw, errcode.ErrorCodeUnknown)
		return
	}
	defer func() {
		resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		if c.cachedManifest(rw, r, info, false) {
			if c.logger != nil {
				c.logger.Println("origin manifest response 40x, but hit caches", info.Host, info.Image, err, dumpResponse(resp))
			}
			return
		}
		if c.logger != nil {
			c.logger.Println("origin manifest response 40x", info.Host, info.Image, err, dumpResponse(resp))
		}
		errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
		return
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusBadRequest {
		if c.cachedManifest(rw, r, info, false) {
			if c.logger != nil {
				c.logger.Println("origin manifest response 5xx, but hit caches", info.Host, info.Image, err, dumpResponse(resp))
			}
			return
		}
		if c.logger != nil {
			c.logger.Println("origin manifest response 5xx", info.Host, info.Image, err, dumpResponse(resp))
		}
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		c.errorResponse(rw, r, fmt.Errorf("origin response 429"))
		return
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

		err = c.cacheManifestContent(context.Background(), info, body)
		if err != nil {
			c.errorResponse(rw, r, err)
			return
		}
		rw.Write(body)
	} else {
		io.Copy(rw, resp.Body)
	}
}

func (c *CRProxy) cacheManifestContent(ctx context.Context, info *PathInfo, content []byte) error {
	h := sha256.New()
	h.Write(content)
	hash := hex.EncodeToString(h.Sum(nil)[:])

	if strings.HasPrefix(info.Manifests, "sha256:") {
		if info.Manifests[7:] != hash {
			return fmt.Errorf("expected hash %s is not same to %s", info.Manifests[7:], hash)
		}
	} else {
		manifestLinkPath := manifestTagCachePath(info.Host, info.Image, info.Manifests)
		err := c.storageDriver.PutContent(ctx, manifestLinkPath, []byte("sha256:"+hash))
		if err != nil {
			return err
		}
	}

	manifestLinkPath := manifestRevisionsCachePath(info.Host, info.Image, hash)
	err := c.storageDriver.PutContent(ctx, manifestLinkPath, []byte("sha256:"+hash))
	if err != nil {
		return err
	}

	blobCachePath := blobCachePath(hash)
	err = c.storageDriver.PutContent(ctx, blobCachePath, content)
	if err != nil {
		return err
	}

	if c.manifestCacheDuration > 0 {
		c.manifestCache.Store(manifestLinkPath, time.Now())
	}
	return nil
}

func (c *CRProxy) cachedManifest(rw http.ResponseWriter, r *http.Request, info *PathInfo, try bool) bool {
	if try && c.manifestCacheDuration == 0 {
		return false
	}

	ctx := r.Context()
	var manifestLinkPath string
	if strings.HasPrefix(info.Manifests, "sha256:") {
		manifestLinkPath = manifestRevisionsCachePath(info.Host, info.Image, info.Manifests[7:])
	} else {
		manifestLinkPath = manifestTagCachePath(info.Host, info.Image, info.Manifests)
	}

	if try {
		last, ok := c.manifestCache.Load(manifestLinkPath)
		if !ok {
			return false
		}

		if time.Since(last) > c.manifestCacheDuration {
			return false
		}
	}

	content, err := c.storageDriver.GetContent(ctx, manifestLinkPath)
	if err == nil {
		digest := string(content)
		blobCachePath := blobCachePath(digest)
		content, err := c.storageDriver.GetContent(ctx, blobCachePath)
		if err == nil {

			mt := struct {
				MediaType string `json:"mediaType"`
			}{}
			err := json.Unmarshal(content, &mt)
			if err != nil {
				if c.logger != nil {
					c.logger.Println("Manifest blob cache err", blobCachePath, err)
				}
				return false
			}
			if c.logger != nil {
				c.logger.Println("Manifest blob cache hit", blobCachePath)
			}
			rw.Header().Set("docker-content-digest", digest)
			rw.Header().Set("Content-Type", mt.MediaType)
			rw.Header().Set("Content-Length", strconv.FormatInt(int64(len(content)), 10))
			if r.Method != http.MethodHead {
				rw.Write(content)
			}
			return true
		}
		if c.logger != nil {
			c.logger.Println("Manifest blob cache missed", blobCachePath, err)
		}
	} else {
		if c.logger != nil {
			c.logger.Println("Manifest cache missed", manifestLinkPath, err)
		}
	}

	return false
}
