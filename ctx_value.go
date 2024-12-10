package crproxy

import (
	"context"
)

type infoCtxKey struct{}
type infoCtxValue struct {
	LastRedirect string
}

func withCtxValue(ctx context.Context) context.Context {
	return context.WithValue(ctx, infoCtxKey{}, &infoCtxValue{})
}

func getCtxValue(ctx context.Context) *infoCtxValue {
	v, ok := ctx.Value(infoCtxKey{}).(*infoCtxValue)
	if !ok {
		return nil
	}
	return v
}
