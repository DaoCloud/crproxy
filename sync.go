package crproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/distribution/reference"
	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/manifestlist"
	"github.com/docker/distribution/manifest/ocischema"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/docker/distribution/registry/api/errcode"
	"github.com/docker/distribution/registry/client"
	"github.com/opencontainers/go-digest"
)

type namedWithoutDomain struct {
	reference.Reference
	name string
}

func (n namedWithoutDomain) Name() string {
	return n.name
}

func newNameWithoutDomain(named reference.Named, name string) reference.Named {
	return namedWithoutDomain{
		Reference: named,
		name:      name,
	}
}

func (c *CRProxy) Sync(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut || c.cache == nil {
		errcode.ServeJSON(rw, errcode.ErrorCodeUnsupported)
		return
	}

	query := r.URL.Query()

	rw.Header().Set("Content-Type", "application/json")

	images := query["image"]

	flusher, _ := rw.(http.Flusher)

	encoder := json.NewEncoder(rw)
	for _, image := range images {
		if image == "" {
			continue
		}
		err := c.SyncImageLayer(r.Context(), r.RemoteAddr, image, nil, func(sp SyncProgress) error {
			err := encoder.Encode(sp)
			if err != nil {
				return err
			}

			if flusher != nil {
				flusher.Flush()
			}

			return nil
		})
		if err != nil {
			c.errorResponse(rw, r, err)
			return
		}
	}
}

type SyncProgress struct {
	Digest   string                     `json:"digest,omitempty"`
	Size     int64                      `json:"size,omitempty"`
	Status   string                     `json:"status,omitempty"`
	Platform *manifestlist.PlatformSpec `json:"platform,omitempty"`
}

func (c *CRProxy) SyncImageLayer(ctx context.Context, ip, image string, filter func(pf manifestlist.PlatformSpec) bool, cb func(sp SyncProgress) error) error {
	ref, err := reference.Parse(image)
	if err != nil {
		return err
	}

	named, ok := ref.(reference.Named)
	if !ok {
		return fmt.Errorf("%s is not a name", ref)
	}

	host := reference.Domain(named)

	var name reference.Named

	info := &ImageInfo{
		Host: host,
		Name: reference.Path(named),
	}
	if c.modify != nil {
		info = c.modify(info)
		name = newNameWithoutDomain(named, info.Name)
	} else {
		name = newNameWithoutDomain(named, info.Name)
	}

	if c.blockFunc != nil {
		blockMessage, block := c.block(&BlockInfo{
			IP:   ip,
			Host: info.Host,
			Name: info.Name,
		})
		if block {
			if blockMessage != "" {
				return errcode.ErrorCodeDenied.WithMessage(blockMessage)
			} else {
				return errcode.ErrorCodeDenied
			}
		}
	}

	host = c.getDomainAlias(host)
	info.Host = host

	err = c.client.Ping(host)
	if err != nil {
		return err
	}

	cli := c.client.GetClientset(host, name.Name())

	repo, err := client.NewRepository(name, c.client.HostURL(host), cli.Transport)
	if err != nil {
		return err
	}

	ms, err := repo.Manifests(ctx)
	if err != nil {
		return err
	}

	bs := repo.Blobs(ctx)

	uniq := map[digest.Digest]struct{}{}
	blobCallback := func(dgst digest.Digest, size int64, pf *manifestlist.PlatformSpec) error {
		_, ok := uniq[dgst]
		if ok {
			if cb != nil {
				err = cb(SyncProgress{
					Digest:   dgst.String(),
					Size:     size,
					Status:   "SKIP",
					Platform: pf,
				})
				if err != nil {
					return err
				}
			}
			return nil
		}
		uniq[dgst] = struct{}{}
		blob := dgst.String()

		stat, err := c.cache.StatBlob(ctx, blob)
		if err == nil {
			if size > 0 {
				gotSize := stat.Size()
				if size == gotSize {
					c.logger.Info("skip blob", "digest", dgst)

					if cb != nil {
						err = cb(SyncProgress{
							Digest:   blob,
							Size:     size,
							Status:   "SKIP",
							Platform: pf,
						})
						if err != nil {
							return err
						}
					}
					return nil
				}
				c.logger.Error("size is not meeting expectations", "digest", dgst, "size", size, "gotSize", gotSize)
			} else {
				c.logger.Info("skip blob", "digest", dgst)
				if cb != nil {
					err = cb(SyncProgress{
						Digest:   dgst.String(),
						Size:     -1,
						Status:   "SKIP",
						Platform: pf,
					})
					if err != nil {
						return err
					}
				}
				return nil
			}
		}

		f, err := bs.Open(ctx, dgst)
		if err != nil {
			return err
		}
		defer f.Close()

		n, err := c.cache.PutBlob(ctx, blob, f)
		if err != nil {
			return err
		}

		c.logger.Info("sync blob", "digest", dgst)

		if cb != nil {
			err = cb(SyncProgress{
				Digest:   dgst.String(),
				Size:     n,
				Status:   "CACHE",
				Platform: pf,
			})
			if err != nil {
				return err
			}
		}
		return nil
	}

	manifestCallback := func(tagOrHash string, m distribution.Manifest) error {
		_, playload, err := m.Payload()
		if err != nil {
			return err
		}

		_, _, err = c.cache.PutManifestContent(ctx, info.Host, info.Name, tagOrHash, playload)
		if err != nil {
			return err
		}
		return nil
	}

	err = getLayerFromManifestList(ctx, ms, ref, filter, blobCallback, manifestCallback)
	if err != nil {
		return err
	}
	return nil
}

func getLayerFromManifestList(ctx context.Context, ms distribution.ManifestService, ref reference.Reference, filter func(pf manifestlist.PlatformSpec) bool,
	digestCallback func(dgst digest.Digest, size int64, pf *manifestlist.PlatformSpec) error,
	manifestCallback func(tagOrHash string, m distribution.Manifest) error) error {
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
		err = manifestCallback(r.Digest().String(), m)
		if err != nil {
			return err
		}
	case reference.Tagged:
		tag := r.Tag()
		m, err = ms.Get(ctx, "", distribution.WithTag(r.Tag()))
		if err != nil {
			return err
		}
		err = manifestCallback(tag, m)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s no reference to any source", ref)
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
			err = manifestCallback(mfest.Digest.String(), m0)
			if err != nil {
				return err
			}
			err = getLayerFromManifest(m0, func(dgst digest.Digest, size int64) error {
				return digestCallback(dgst, size, &mfest.Platform)
			})
			if err != nil {
				return err
			}
		}
		return nil
	default:
		return getLayerFromManifest(m, func(dgst digest.Digest, size int64) error {
			return digestCallback(dgst, size, nil)
		})
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
