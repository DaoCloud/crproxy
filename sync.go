package crproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/manifest/manifestlist"
	"github.com/distribution/distribution/v3/manifest/ocischema"
	"github.com/distribution/distribution/v3/manifest/schema1"
	"github.com/distribution/distribution/v3/manifest/schema2"
	"github.com/distribution/distribution/v3/reference"
	"github.com/distribution/distribution/v3/registry/api/errcode"
	"github.com/distribution/distribution/v3/registry/client"
	"github.com/opencontainers/go-digest"
)

type namedWithoutDomain struct {
	reference.Reference
	name string
}

func (n namedWithoutDomain) Name() string {
	return n.name
}

func newNameWithoutDomain(name reference.Named) reference.Named {
	return namedWithoutDomain{
		Reference: name,
		name:      reference.Path(name),
	}
}

func (c *CRProxy) Sync(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut || c.storageDriver == nil {
		errcode.ServeJSON(rw, errcode.ErrorCodeUnsupported)
		return
	}

	query := r.URL.Query()

	images := query["image"]
	for _, image := range images {
		if image == "" {
			continue
		}
		err := c.SyncImageLayer(r.Context(), image, nil)
		if err != nil {
			c.errorResponse(rw, r, err)
		}
	}
}

func (c *CRProxy) SyncImageLayer(ctx context.Context, image string, filter func(pf manifestlist.PlatformSpec) bool) error {
	ref, err := reference.Parse(image)
	if err != nil {
		return err
	}

	named, ok := ref.(reference.Named)
	if !ok {
		return fmt.Errorf("%s is not a name", ref)
	}

	host := reference.Domain(named)

	host = c.getDomainAlias(host)

	err = c.ping(host)
	if err != nil {
		return err
	}

	name := newNameWithoutDomain(named)

	cli := c.getClientset(host, name.Name())

	repo, err := client.NewRepository(name, c.hostURL(host), cli.Transport)
	if err != nil {
		return err
	}

	ms, err := repo.Manifests(ctx)
	if err != nil {
		return err
	}

	bs := repo.Blobs(ctx)

	buf := c.bytesPool.Get().([]byte)
	defer c.bytesPool.Put(buf)

	err = getLayerFromManifestList(ctx, ms, ref, filter, func(dgst digest.Digest, size int64) error {
		blobPath := blobCachePath(dgst.String())
		stat, err := c.storageDriver.Stat(ctx, blobPath)
		if err == nil {
			if size > 0 {
				gotSize := stat.Size()
				if size == gotSize {
					if c.logger != nil {
						c.logger.Println("skip blob", dgst)
					}
					return nil
				}
				if c.logger != nil {
					c.logger.Println("size is not meeting expectations", dgst, size, gotSize)
				}
				return nil
			} else {
				if c.logger != nil {
					c.logger.Println("skip blob", dgst)
				}
				return nil
			}
		}

		f, err := bs.Open(ctx, dgst)
		if err != nil {
			return err
		}
		defer f.Close()

		fw, err := c.storageDriver.Writer(ctx, blobPath, false)
		if err != nil {
			return err
		}

		h := sha256.New()
		n, err := io.CopyBuffer(fw, io.TeeReader(f, h), buf)
		if err != nil {
			fw.Cancel()
			return err
		}
		if wantSize := fw.Size(); n != wantSize {
			fw.Cancel()
			return fmt.Errorf("expected %d bytes, got %d", wantSize, n)
		}

		hash := hex.EncodeToString(h.Sum(nil)[:])
		if hex := dgst.Hex(); hex != hash {
			fw.Cancel()
			return fmt.Errorf("expected %s hash, got %s", hex, hash)
		}

		err = fw.Commit()
		if err != nil {
			return err
		}

		if c.logger != nil {
			c.logger.Println("sync blob", dgst)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func getLayerFromManifestList(ctx context.Context, ms distribution.ManifestService, ref reference.Reference, filter func(pf manifestlist.PlatformSpec) bool, cb func(dgst digest.Digest, size int64) error) error {
	var (
		m   distribution.Manifest
		err error
	)
	switch r := ref.(type) {
	case reference.Digested:
		m, err = ms.Get(ctx, r.Digest())
		if err != nil {
			return err
		}
	case reference.Tagged:
		m, err = ms.Get(ctx, "", distribution.WithTag(r.Tag()))
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s no reference to any source", ref)
	}

	uniq := map[digest.Digest]struct{}{}
	cb0 := func(dgst digest.Digest, size int64) error {
		_, ok := uniq[dgst]
		if ok {
			return nil
		}
		uniq[dgst] = struct{}{}
		return cb(dgst, size)
	}

	switch m := m.(type) {
	case *manifestlist.DeserializedManifestList:
		for _, mfest := range m.ManifestList.Manifests {
			if filter != nil && !filter(mfest.Platform) {
				continue
			}

			m0, err := ms.Get(ctx, mfest.Digest)
			if err != nil {
				return err
			}
			err = getLayerFromManifest(m0, cb0)
			if err != nil {
				return err
			}
		}
		return nil
	default:
		return getLayerFromManifest(m, cb0)
	}
}

func getLayerFromManifest(m distribution.Manifest, cb func(dgst digest.Digest, size int64) error) error {
	switch m := m.(type) {
	case *ocischema.DeserializedManifest:
		for _, layer := range m.Layers {
			if layer.Size == 0 {
				continue
			}
			err := cb(layer.Digest, layer.Size)
			if err != nil {
				return err
			}
		}
	case *schema2.DeserializedManifest:
		for _, layer := range m.Layers {
			if layer.Size == 0 {
				continue
			}
			err := cb(layer.Digest, layer.Size)
			if err != nil {
				return err
			}
		}
	case *schema1.SignedManifest:
		for _, layer := range m.FSLayers {
			err := cb(layer.BlobSum, -1)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
