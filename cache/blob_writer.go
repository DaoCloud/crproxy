package cache

import (
	"context"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/wzshiming/sss"
)

type blobWriter struct {
	sss.FileWriter
	cacheHash string
	h         hash.Hash
}

func (bw *blobWriter) Commit(ctx context.Context) error {
	hash := hex.EncodeToString(bw.h.Sum(nil)[:])
	if bw.cacheHash != hash {
		return fmt.Errorf("expected %s hash, got %s", bw.cacheHash, hash)
	}
	return bw.FileWriter.Commit(ctx)
}

func (bw *blobWriter) Write(p []byte) (int, error) {
	bw.h.Write(p)
	return bw.FileWriter.Write(p)
}
