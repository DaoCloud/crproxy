package crproxy

import (
	"context"
)

type infoCtxKey struct{}
type InfoCtxValue struct {
	LastRedirect string
}

func withCtxValue(ctx context.Context) context.Context {
	return context.WithValue(ctx, infoCtxKey{}, &InfoCtxValue{})
}

func GetCtxValue(ctx context.Context) *InfoCtxValue {
	v, ok := ctx.Value(infoCtxKey{}).(*InfoCtxValue)
	if !ok {
		return nil
	}
	return v
}
