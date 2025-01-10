package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/daocloud/crproxy/internal/utils"
	"github.com/daocloud/crproxy/token"
	"github.com/docker/distribution/registry/api/errcode"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

func (c *Gateway) worker(ctx context.Context) {
	for {
		info, _, finish, ok := c.queue.GetOrWaitWithDone(ctx.Done())
		if !ok {
			return
		}

		sc, err := c.cacheManifest(&info)
		if err != nil {
			c.manifestCache.PutError(&info, err, sc)
		}
		finish()
	}
}

func (c *Gateway) cacheManifestResponse(rw http.ResponseWriter, r *http.Request, info *PathInfo, t *token.Token) {
	ctx := r.Context()

	var fallback bool
	var cancel func()

	done, fallback := c.tryFirstServeCachedManifest(rw, r, info)
	if done {
		return
	}
	if fallback {
		ctx, cancel = context.WithTimeout(ctx, c.recacheMaxWait)
		defer cancel()
	}

	select {
	case <-ctx.Done():
		if fallback && c.serveCachedManifest(rw, r, info, true, "fallback") {
			return
		}
		return
	case <-c.queue.AddWeight(*info, t.Weight):
	}

	if c.missServeCachedManifest(rw, r, info) {
		return
	}

	c.logger.Error("here should never be executed", "info", info)
	utils.ServeError(rw, r, errcode.ErrorCodeUnknown, 0)
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
			var tErr *transport.Error
			if errors.As(err, &tErr) {
				return http.StatusForbidden, errcode.ErrorCodeDenied
			}
			c.logger.Warn("failed to request", "url", u.String(), "error", err)
			return 0, errcode.ErrorCodeUnknown
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
			c.manifestCache.Put(info, cacheValue{
				Digest: digest,
			})
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
		var tErr *transport.Error
		if errors.As(err, &tErr) {
			return http.StatusForbidden, errcode.ErrorCodeDenied
		}
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

	size, digest, mediaType, err := c.cache.PutManifestContent(ctx, info.Host, info.Image, info.Manifests, body)
	if err != nil {
		return 0, err
	}

	c.manifestCache.Put(info, cacheValue{
		Digest:    digest,
		MediaType: mediaType,
		Length:    strconv.FormatInt(size, 10),
	})
	return 0, nil
}

func (c *Gateway) tryFirstServeCachedManifest(rw http.ResponseWriter, r *http.Request, info *PathInfo) (done bool, fallback bool) {
	val, ok := c.manifestCache.Get(info)
	if ok {
		if val.Error != nil {
			utils.ServeError(rw, r, val.Error, val.StatusCode)
			return true, false
		}

		if val.MediaType == "" || val.Length == "" {
			return c.serveCachedManifest(rw, r, info, true, "hit"), false
		}

		if r.Method == http.MethodHead {
			rw.Header().Set("Docker-Content-Digest", val.Digest)
			rw.Header().Set("Content-Type", val.MediaType)
			rw.Header().Set("Content-Length", val.Length)
			return true, false
		}
		return c.serveCachedManifest(rw, r, info, false, "hit"), false
	}

	if info.IsDigestManifests {
		return c.serveCachedManifest(rw, r, info, true, "try"), false
	}

	if c.recacheMaxWait > 0 &&
		c.checkCachedManifest(rw, r, info) {
		return false, true
	}

	return false, false
}

func (c *Gateway) missServeCachedManifest(rw http.ResponseWriter, r *http.Request, info *PathInfo) (done bool) {
	val, ok := c.manifestCache.Get(info)
	if ok {
		if val.Error != nil {
			utils.ServeError(rw, r, val.Error, val.StatusCode)
			return true
		}

		if val.MediaType == "" || val.Length == "" {
			return c.serveCachedManifest(rw, r, info, true, "miss")
		}

		if r.Method == http.MethodHead {
			rw.Header().Set("Docker-Content-Digest", val.Digest)
			rw.Header().Set("Content-Type", val.MediaType)
			rw.Header().Set("Content-Length", val.Length)
			return true
		}
		return c.serveCachedManifest(rw, r, info, true, "miss")
	}

	return false
}

func (c *Gateway) checkCachedManifest(rw http.ResponseWriter, r *http.Request, info *PathInfo) bool {
	ok, _ := c.cache.StatManifest(r.Context(), info.Host, info.Image, info.Manifests)
	return ok
}

func (c *Gateway) serveCachedManifest(rw http.ResponseWriter, r *http.Request, info *PathInfo, recache bool, phase string) bool {
	ctx := r.Context()

	content, digest, mediaType, err := c.cache.GetManifestContent(ctx, info.Host, info.Image, info.Manifests)
	if err != nil {
		c.logger.Warn("manifest missed", "phase", phase, "host", info.Host, "image", info.Image, "manifest", info.Manifests, "error", err)
		return false
	}

	c.logger.Info("manifest hit", "phase", phase, "host", info.Host, "image", info.Image, "manifest", info.Manifests, "digest", digest)

	length := strconv.FormatInt(int64(len(content)), 10)

	if recache {
		c.manifestCache.Put(info, cacheValue{
			Digest:    digest,
			MediaType: mediaType,
			Length:    length,
		})
	}

	rw.Header().Set("Docker-Content-Digest", digest)
	rw.Header().Set("Content-Type", mediaType)
	rw.Header().Set("Content-Length", length)

	if r.Method != http.MethodHead {
		rw.Write(content)
	}

	return true
}
