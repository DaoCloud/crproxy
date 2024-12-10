package crproxy

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/daocloud/crproxy/token"
	"github.com/docker/distribution/registry/api/errcode"
)

func (c *CRProxy) cacheBlobResponse(rw http.ResponseWriter, r *http.Request, info *PathInfo, t *token.Token) {
	ctx := r.Context()

	closeValue, loaded := c.mutCache.LoadOrStore(info.Blobs, make(chan struct{}))
	closeCh := closeValue.(chan struct{})
	for loaded {
		select {
		case <-ctx.Done():
			err := ctx.Err().Error()
			c.logger.Error("context done", "error", err)
			http.Error(rw, err, http.StatusInternalServerError)
			return
		case <-closeCh:
		}
		closeValue, loaded = c.mutCache.LoadOrStore(info.Blobs, make(chan struct{}))
		closeCh = closeValue.(chan struct{})
	}

	doneCache := func() {
		c.mutCache.Delete(info.Blobs)
		close(closeCh)
	}

	stat, err := c.cache.StatBlob(ctx, info.Blobs)
	if err == nil {
		doneCache()

		size := stat.Size()
		if r.Method == http.MethodHead {
			rw.Header().Set("Content-Length", strconv.FormatInt(size, 10))
			rw.Header().Set("Content-Type", "application/octet-stream")
			return
		}

		if !t.NoRateLimit {
			c.accumulativeLimit(r, info, size)
			if !c.waitForLimit(r, info, size) {
				c.errorResponse(rw, r, nil)
				return
			}
		}

		err = c.redirect(rw, r, info.Blobs, info)
		if err == nil {
			return
		}
		c.errorResponse(rw, r, ctx.Err())
		return
	}
	c.logger.Info("Cache miss", "digest", info.Blobs)

	type repo struct {
		err  error
		size int64
	}
	signalCh := make(chan repo, 1)

	go func() {
		defer doneCache()
		size, err := c.cacheBlobContent(context.Background(), r, info)
		signalCh <- repo{
			err:  err,
			size: size,
		}
	}()

	select {
	case <-ctx.Done():
		c.errorResponse(rw, r, ctx.Err())
		return
	case signal := <-signalCh:
		if signal.err != nil {
			c.errorResponse(rw, r, signal.err)
			return
		}
		if r.Method == http.MethodHead {
			rw.Header().Set("Content-Length", strconv.FormatInt(signal.size, 10))
			rw.Header().Set("Content-Type", "application/octet-stream")
			return
		}

		if !t.NoRateLimit {
			c.accumulativeLimit(r, info, signal.size)
			if !c.waitForLimit(r, info, signal.size) {
				c.errorResponse(rw, r, nil)
				return
			}
		}

		err = c.redirect(rw, r, info.Blobs, info)
		if err != nil {
			c.logger.Error("failed to redirect", "digest", info.Blobs, "error", err)
		}
		return
	}
}

func (c *CRProxy) cacheBlobContent(ctx context.Context, r *http.Request, info *PathInfo) (int64, error) {
	resp, err := c.httpClient.Do(r)
	if err != nil {
		return 0, err
	}
	defer func() {
		resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return 0, errcode.ErrorCodeDenied
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return 0, errcode.ErrorCodeUnknown.WithMessage(fmt.Sprintf("Source response code %d", resp.StatusCode))
	}

	return c.cache.PutBlob(ctx, info.Blobs, resp.Body)
}

func (c *CRProxy) redirectBlobResponse(rw http.ResponseWriter, r *http.Request, info *PathInfo) {
	r = r.WithContext(withCtxValue(r.Context()))

	resp, err := c.httpClient.Do(r)
	if err != nil {
		c.logger.Error("failed to request", "host", info.Host, "image", info.Image, "error", err)
		errcode.ServeJSON(rw, errcode.ErrorCodeUnknown)
		return
	}
	defer func() {
		resp.Body.Close()
	}()

	switch resp.StatusCode {
	default:
		c.logger.Error("failed to redirect blob", "host", info.Host, "image", info.Image, "status", resp.StatusCode)
		errcode.ServeJSON(rw, errcode.ErrorCodeUnavailable)
		return
	case http.StatusUnauthorized, http.StatusForbidden:
		errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
		return
	case http.StatusTemporaryRedirect, http.StatusPermanentRedirect, http.StatusMovedPermanently, http.StatusFound:
		location := resp.Header.Get("Location")
		http.Redirect(rw, r, location, http.StatusFound)
		return
	case http.StatusOK:
		v := getCtxValue(r.Context())
		if v != nil && v.LastRedirect != "" {
			http.Redirect(rw, r, v.LastRedirect, http.StatusFound)
			return
		}
		errcode.ServeJSON(rw, errcode.ErrorCodeUnavailable)
		return
	}
}

func (c *CRProxy) isRedirectToOriginBlob(r *http.Request, info *ImageInfo) bool {
	if c.redirectToOriginBlobFunc == nil {
		return false
	}

	return c.redirectToOriginBlobFunc(r, info)
}
