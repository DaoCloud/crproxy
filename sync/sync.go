package crproxy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/daocloud/crproxy/cache"
	"github.com/daocloud/crproxy/clientset"
	"github.com/distribution/reference"
	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/manifestlist"
	"github.com/docker/distribution/manifest/ocischema"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/distribution/manifest/schema2"
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

type Progress struct {
	Digest   string                     `json:"digest,omitempty"`
	Size     int64                      `json:"size,omitempty"`
	Status   string                     `json:"status,omitempty"`
	Platform *manifestlist.PlatformSpec `json:"platform,omitempty"`
	Name     string                     `json:"name,omitempty"`
}

type SyncManager struct {
	client      *clientset.Clientset
	cache       *cache.Cache
	logger      *slog.Logger
	domainAlias map[string]string
}

func (c *SyncManager) getDomainAlias(host string) string {
	if c.domainAlias == nil {
		return host
	}
	h, ok := c.domainAlias[host]
	if !ok {
		return host
	}
	return h
}

type Option func(*SyncManager)

func WithDomainAlias(domainAlias map[string]string) Option {
	return func(c *SyncManager) {
		c.domainAlias = domainAlias
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(c *SyncManager) {
		c.logger = logger
	}
}

func WithCache(cache *cache.Cache) Option {
	return func(c *SyncManager) {
		c.cache = cache
	}
}

func WithClient(client *clientset.Clientset) Option {
	return func(c *SyncManager) {
		c.client = client
	}
}

func NewSyncManager(opts ...Option) (*SyncManager, error) {
	c := &SyncManager{
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.client == nil {
		return nil, fmt.Errorf("client is required")
	}

	if c.cache == nil {
		return nil, fmt.Errorf("cache is required")
	}

	return c, nil
}

func (c *SyncManager) Image(ctx context.Context, image string, filter func(pf manifestlist.PlatformSpec) bool, cb func(sp Progress) error) error {
	ref, err := reference.Parse(image)
	if err != nil {
		return fmt.Errorf("parse image failed: %w", err)
	}

	named, ok := ref.(reference.Named)
	if !ok {
		return fmt.Errorf("%s is not a name", ref)
	}

	host := reference.Domain(named)

	path := reference.Path(named)

	host = c.getDomainAlias(host)

	name := newNameWithoutDomain(named, path)

	err = c.client.Ping(host)
	if err != nil {
		return fmt.Errorf("ping registry failed: %w", err)
	}

	cli := c.client.GetClientset(host, path)

	repo, err := client.NewRepository(name, c.client.HostURL(host), cli.Transport)
	if err != nil {
		return fmt.Errorf("create repository failed: %w", err)
	}

	ms, err := repo.Manifests(ctx)
	if err != nil {
		return fmt.Errorf("get manifests failed: %w", err)
	}

	bs := repo.Blobs(ctx)

	uniq := map[digest.Digest]struct{}{}
	blobCallback := func(dgst digest.Digest, size int64, pf *manifestlist.PlatformSpec, name string) error {
		_, ok := uniq[dgst]
		if ok {
			if cb != nil {
				err = cb(Progress{
					Digest:   dgst.String(),
					Size:     size,
					Status:   "SKIP",
					Platform: pf,
					Name:     name,
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
						err = cb(Progress{
							Digest:   blob,
							Size:     size,
							Status:   "SKIP",
							Platform: pf,
							Name:     name,
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
					err = cb(Progress{
						Digest:   dgst.String(),
						Size:     -1,
						Status:   "SKIP",
						Platform: pf,
						Name:     name,
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
			return fmt.Errorf("open blob failed: %w", err)
		}
		defer f.Close()

		n, err := c.cache.PutBlob(ctx, blob, f)
		if err != nil {
			return fmt.Errorf("put blob failed: %w", err)
		}

		c.logger.Info("sync blob", "digest", dgst)

		if cb != nil {
			err = cb(Progress{
				Digest:   dgst.String(),
				Size:     n,
				Status:   "CACHE",
				Platform: pf,
				Name:     name,
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
			return fmt.Errorf("get manifest payload failed: %w", err)
		}

		_, _, err = c.cache.PutManifestContent(ctx, host, path, tagOrHash, playload)
		if err != nil {
			return fmt.Errorf("put manifest content failed: %w", err)
		}
		return nil
	}

	switch ref.(type) {
	case reference.Digested, reference.Tagged:
		err = c.syncLayerFromManifestList(ctx, ms, ref, filter, blobCallback, manifestCallback, host+"/"+ref.String())
		if err != nil {
			return fmt.Errorf("sync layer from manifest list failed: %w", err)
		}
	default:
		t := repo.Tags(ctx)
		tags, err := t.All(ctx)
		if err != nil {
			return fmt.Errorf("get tags failed: %w", err)
		}

		for _, tag := range tags {
			t, err := reference.WithTag(name, tag)
			if err != nil {
				return fmt.Errorf("with tag failed: %w", err)
			}
			err = c.syncLayerFromManifestList(ctx, ms, t, filter, blobCallback, manifestCallback, host+"/"+t.String())
			if err != nil {
				return fmt.Errorf("sync layer from manifest list failed: %w", err)
			}
		}
	}

	return nil
}

func (c *SyncManager) syncLayerFromManifestList(ctx context.Context, ms distribution.ManifestService, ref reference.Reference, filter func(pf manifestlist.PlatformSpec) bool,
	digestCallback func(dgst digest.Digest, size int64, pf *manifestlist.PlatformSpec, name string) error,
	manifestCallback func(tagOrHash string, m distribution.Manifest) error, name string) error {
	var (
		m   distribution.Manifest
		err error
	)
	switch r := ref.(type) {
	case reference.Digested:
		m, err = ms.Get(ctx, r.Digest())
		if err != nil {
			return fmt.Errorf("get manifest digest failed: %w", err)
		}
		err = manifestCallback(r.Digest().String(), m)
		if err != nil {
			return fmt.Errorf("manifest callback failed: %w", err)
		}
	case reference.Tagged:
		tag := r.Tag()
		m, err = ms.Get(ctx, "", distribution.WithTag(tag))
		if err != nil {
			return fmt.Errorf("get manifest tag failed: %w", err)
		}
		err = manifestCallback(tag, m)
		if err != nil {
			return fmt.Errorf("manifest callback failed: %w", err)
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
				return fmt.Errorf("get manifest failed: %w", err)
			}
			err = manifestCallback(mfest.Digest.String(), m0)
			if err != nil {
				return fmt.Errorf("manifest callback failed: %w", err)
			}
			err = c.syncLayerFromManifest(m0, func(dgst digest.Digest, size int64) error {
				return digestCallback(dgst, size, &mfest.Platform, name)
			})
			if err != nil {
				return fmt.Errorf("get layer from manifest failed: %w", err)
			}
		}
		return nil
	default:
		return c.syncLayerFromManifest(m, func(dgst digest.Digest, size int64) error {
			return digestCallback(dgst, size, nil, name)
		})
	}
}

func (c *SyncManager) syncLayerFromManifest(m distribution.Manifest, cb func(dgst digest.Digest, size int64) error) error {
	switch m := m.(type) {
	case *ocischema.DeserializedManifest:
		if m.Config.Size != 0 {
			err := cb(m.Config.Digest, m.Config.Size)
			if err != nil {
				return fmt.Errorf("digest callback failed: %w", err)
			}
		}
		for _, layer := range m.Layers {
			if layer.Size == 0 {
				continue
			}
			err := cb(layer.Digest, layer.Size)
			if err != nil {
				return fmt.Errorf("digest callback failed: %w", err)
			}
		}
	case *schema2.DeserializedManifest:
		if m.Config.Size != 0 {
			err := cb(m.Config.Digest, m.Config.Size)
			if err != nil {
				return fmt.Errorf("digest callback failed: %w", err)
			}
		}
		for _, layer := range m.Layers {
			if layer.Size == 0 {
				continue
			}
			err := cb(layer.Digest, layer.Size)
			if err != nil {
				return fmt.Errorf("digest callback failed: %w", err)
			}
		}
	case *schema1.SignedManifest:
		for _, layer := range m.FSLayers {
			err := cb(layer.BlobSum, -1)
			if err != nil {
				return fmt.Errorf("digest callback failed: %w", err)
			}
		}
	}
	return nil
}
