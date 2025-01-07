package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/daocloud/crproxy/internal/utils"
	"github.com/docker/distribution/registry/api/errcode"
)

func (c *Gateway) cacheManifestResponse(rw http.ResponseWriter, r *http.Request, info *PathInfo) {
	ctx := r.Context()

	var fallback bool
	var cancel func()
	defer func() {
		if cancel != nil {
			cancel()
		}
	}()

	key := manifestCacheKey(info)
	err := c.uniq.Do(ctx, key,
		func(ctx context.Context) (passCtx context.Context, done bool) {
			done, fallback = c.tryFirstServeCachedManifest(rw, r, info)
			if fallback &&
				cancel == nil &&
				c.recacheMaxWait > 0 &&
				c.checkCachedManifest(rw, r, info) {
				ctx, cancel = context.WithTimeout(ctx, c.recacheMaxWait)
			}
			return ctx, done
		},
		func(ctx context.Context) error {
			if ctx.Err() != nil {
				return errcode.ErrorCodeUnknown
			}
			sc, err := c.cacheManifest(info)
			if err != nil {
				c.manifestCache.PutError(info, err, sc)
				utils.ServeError(rw, r, err, sc)
				return nil
			}
			if ctx.Err() != nil {
				return errcode.ErrorCodeUnknown
			}
			if c.serveCachedManifest(rw, r, info, "missed") {
				return nil
			}
			return errcode.ErrorCodeUnknown
		},
	)
	if err != nil {
		if fallback && c.serveCachedManifest(rw, r, info, "fallback") {
			return
		}

		c.manifestCache.PutError(info, err, 0)
		utils.ServeError(rw, r, err, 0)
		return
	}
}

func (c *Gateway) cacheManifest(info *PathInfo) (int, error) {
	ctx := context.Background()
	u := &url.URL{
		Scheme: "https",
		Host:   info.Host,
		Path:   fmt.Sprintf("/v2/%s/manifests/%s", info.Image, info.Manifests),
	}

	if !info.IsDigestManifests {
		forwardReq, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
		if err != nil {
			return 0, err
		}
		// Never trust a client's Accept !!!
		forwardReq.Header.Set("Accept", c.acceptsStr)

		resp, err := c.httpClient.Do(forwardReq)
		if err != nil {
			return 0, err
		}
		if resp.Body != nil {
			resp.Body.Close()
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return 0, errcode.ErrorCodeDenied
		}
		if resp.StatusCode < http.StatusOK ||
			(resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest) {
			return 0, errcode.ErrorCodeUnknown
		}

		digest := resp.Header.Get("Docker-Content-Digest")
		if digest == "" {
			return 0, errcode.ErrorCodeDenied
		}

		err = c.cache.RelinkManifest(ctx, info.Host, info.Image, info.Manifests, digest)
		if err != nil {
			c.logger.Warn("failed relink manifest", "url", u.String(), "error", err)
		} else {
			c.logger.Info("relink manifest", "url", u.String())
			return 0, nil
		}
		u.Path = fmt.Sprintf("/v2/%s/manifests/%s", info.Image, digest)
	}

	forwardReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, err
	}
	// Never trust a client's Accept !!!
	forwardReq.Header.Set("Accept", c.acceptsStr)

	resp, err := c.httpClient.Do(forwardReq)
	if err != nil {
		c.logger.Warn("failed to request", "url", u.String(), "error", err)
		return 0, errcode.ErrorCodeUnknown
	}
	defer func() {
		resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		c.logger.Error("upstream denied", "statusCode", resp.StatusCode, "url", u.String(), "response", dumpResponse(resp))
		return 0, errcode.ErrorCodeDenied
	}
	if resp.StatusCode < http.StatusOK ||
		(resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest) {
		c.logger.Error("upstream unkown code", "statusCode", resp.StatusCode, "url", u.String(), "response", dumpResponse(resp))
		return 0, errcode.ErrorCodeUnknown
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		c.logger.Error("failed to get body", "statusCode", resp.StatusCode, "url", u.String(), "error", err)
		return 0, errcode.ErrorCodeUnknown
	}
	if !json.Valid(body) {
		c.logger.Error("invalid body", "statusCode", resp.StatusCode, "url", u.String(), "body", string(body))
		return 0, errcode.ErrorCodeDenied
	}

	if resp.StatusCode >= http.StatusBadRequest {
		var retErrs errcode.Errors
		err = retErrs.UnmarshalJSON(body)
		if err != nil {
			c.logger.Error("failed to unmarshal body", "statusCode", resp.StatusCode, "url", u.String(), "body", string(body))
			return 0, errcode.ErrorCodeUnknown
		}
		return resp.StatusCode, retErrs
	}

	_, _, err = c.cache.PutManifestContent(ctx, info.Host, info.Image, info.Manifests, body)
	if err != nil {
		return 0, err
	}
	return 0, nil
}

func (c *Gateway) tryFirstServeCachedManifest(rw http.ResponseWriter, r *http.Request, info *PathInfo) (done bool, fallback bool) {
	val, ok := c.manifestCache.Get(info)
	if !ok {
		if info.IsDigestManifests {
			return c.serveCachedManifest(rw, r, info, "try"), false
		}
		return false, true
	}
	if val.Error != nil {
		utils.ServeError(rw, r, val.Error, val.StatusCode)
		return true, false
	}

	if r.Method == http.MethodHead {
		rw.Header().Set("Docker-Content-Digest", val.Digest)
		rw.Header().Set("Content-Type", val.MediaType)
		rw.Header().Set("Content-Length", val.Length)
		return true, false
	}

	return c.serveCachedManifest(rw, r, info, "hit"), false
}

func (c *Gateway) checkCachedManifest(rw http.ResponseWriter, r *http.Request, info *PathInfo) bool {
	ok, _ := c.cache.StatManifest(r.Context(), info.Host, info.Image, info.Manifests)
	return ok
}

func (c *Gateway) serveCachedManifest(rw http.ResponseWriter, r *http.Request, info *PathInfo, phase string) bool {
	ctx := r.Context()

	content, digest, mediaType, err := c.cache.GetManifestContent(ctx, info.Host, info.Image, info.Manifests)
	if err != nil {
		c.logger.Warn("manifest missed", "phase", phase, "host", info.Host, "image", info.Image, "manifest", info.Manifests, "error", err)
		return false
	}

	c.logger.Info("manifest hit", "phase", phase, "host", info.Host, "image", info.Image, "manifest", info.Manifests, "digest", digest)

	length := strconv.FormatInt(int64(len(content)), 10)

	c.manifestCache.Put(info, cacheValue{
		Digest:    digest,
		MediaType: mediaType,
		Length:    length,
	})

	rw.Header().Set("Docker-Content-Digest", digest)
	rw.Header().Set("Content-Type", mediaType)
	rw.Header().Set("Content-Length", length)

	if r.Method != http.MethodHead {
		rw.Write(content)
	}

	return true
}
