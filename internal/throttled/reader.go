package throttled

import (
	"context"
	"io"

	"golang.org/x/time/rate"
)

type throttledReader struct {
	r       io.Reader
	limiter *rate.Limiter
	ctx     context.Context

	burst int
}

func NewThrottledReader(ctx context.Context, r io.Reader, limiter *rate.Limiter) io.Reader {
	return &throttledReader{
		r:       r,
		limiter: limiter,
		ctx:     ctx,
		burst:   limiter.Burst(),
	}
}

func (r *throttledReader) Read(p []byte) (n int, err error) {
	n, err = r.r.Read(p[:min(len(p), r.burst)])
	if err != nil {
		return n, err
	}

	if err := r.limiter.WaitN(r.ctx, n); err != nil {
		return n, err
	}

	return n, nil
}
