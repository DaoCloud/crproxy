package crproxy

import (
	"net/http"
	"strconv"
	"time"

	"github.com/docker/distribution/registry/api/errcode"
	"github.com/wzshiming/geario"
)

func (c *CRProxy) isPrivileged(r *http.Request, info *ImageInfo) bool {
	if c.privilegedFunc == nil {
		return false
	}
	return c.privilegedFunc(r, info)
}

func (c *CRProxy) checkLimit(rw http.ResponseWriter, r *http.Request, info *PathInfo) bool {
	if c.ipsSpeedLimit != nil && info.Blobs != "" {
		bps, _ := c.speedLimitRecord.LoadOrStore(r.RemoteAddr, geario.NewBPSAver(c.ipsSpeedLimitDuration))
		aver := bps.Aver()
		if aver > *c.ipsSpeedLimit {
			c.logger.Error("exceed limit", "remoteAddr", r.RemoteAddr, "aver", aver, "limit", *c.ipsSpeedLimit)
			if c.limitDelay {
				for bps.Aver() > *c.ipsSpeedLimit {
					wait := time.Second
					n := bps.Next()
					if !n.IsZero() {
						wait = bps.Next().Sub(time.Now())
						if wait < time.Second {
							wait = time.Second
						}
					}
					select {
					case <-r.Context().Done():
						return false
					case <-time.After(wait):
					}
				}
			} else {
				err := errcode.ErrorCodeTooManyRequests
				rw.Header().Set("X-Retry-After", strconv.FormatInt(bps.Next().Unix(), 10))
				errcode.ServeJSON(rw, err)
				return false
			}
		}
	}

	return true
}

func (c *CRProxy) waitForLimit(r *http.Request, info *PathInfo, size int64) bool {
	if c.blobsSpeedLimit != nil && info.Blobs != "" {
		dur := GetSleepDuration(geario.B(size), *c.blobsSpeedLimit, c.blobsSpeedLimitDuration)
		if dur > 0 {
			c.logger.Info("delay request", "remoteAddr", r.RemoteAddr, "size", geario.B(size), "duration", dur)
			select {
			case <-r.Context().Done():
				return false
			case <-time.After(dur):
			}
		}
	}

	return true
}

func (c *CRProxy) accumulativeLimit(r *http.Request, info *PathInfo, size int64) {
	if c.ipsSpeedLimit != nil && info.Blobs != "" {
		bps, ok := c.speedLimitRecord.Load(r.RemoteAddr)
		if ok {
			bps.Add(geario.B(size))
		}
	}
}
