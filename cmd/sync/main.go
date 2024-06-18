package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/manifest/manifestlist"
	"github.com/distribution/distribution/v3/manifest/ocischema"
	"github.com/distribution/distribution/v3/manifest/schema1"
	"github.com/distribution/distribution/v3/manifest/schema2"
	"github.com/distribution/distribution/v3/reference"
	"github.com/distribution/distribution/v3/registry/client"
	"github.com/distribution/distribution/v3/registry/client/auth"
	"github.com/distribution/distribution/v3/registry/client/auth/challenge"
	"github.com/distribution/distribution/v3/registry/client/transport"
	"github.com/opencontainers/go-digest"
)

func main() {

	ctx := context.Background()

	err := ListLayer(ctx, "registry-1.docker.io/library/nginx:latest", func(pf manifestlist.PlatformSpec) bool {
		return pf.OS == "linux" && pf.Architecture == "amd64"
	})
	if err != nil {
		panic(err)
	}
}

func ListLayer(ctx context.Context, image string, filter func(pf manifestlist.PlatformSpec) bool) error {

	tail := strings.SplitN(image, "/", 2)
	baseURL := "https://" + tail[0]
	ref, err := reference.Parse(tail[1])
	if err != nil {
		return err
	}

	named := ref.(reference.Named)

	dt := http.DefaultTransport

	challengeManager := challenge.NewSimpleManager()
	_, err = ping(challengeManager, baseURL+"/v2/", "")
	if err != nil {
		return err
	}

	tkopts := auth.TokenHandlerOptions{
		Transport:   dt,
		Credentials: &credentialStore{},
		Scopes: []auth.Scope{
			auth.RepositoryScope{
				Repository: named.Name(),
				Actions:    []string{"pull"},
			},
		},
	}

	tr := transport.NewTransport(dt,
		auth.NewAuthorizer(challengeManager,
			auth.NewTokenHandlerWithOptions(tkopts)))

	repo, err := client.NewRepository(reference.TrimNamed(named), baseURL, tr)
	if err != nil {
		return err
	}

	ms, err := repo.Manifests(ctx)
	if err != nil {
		return err
	}

	//	bs := repo.Blobs(ctx)

	err = getLayerFromManifestList(ctx, ms, ref, filter, func(dgst digest.Digest) error {
		//f, err := bs.Open(ctx, dgst)
		//if err != nil {
		//	return err
		//}
		fmt.Println(dgst)
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func getLayerFromManifestList(ctx context.Context, ms distribution.ManifestService, ref reference.Reference, filter func(pf manifestlist.PlatformSpec) bool, cb func(dgst digest.Digest) error) error {
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
	cb0 := func(dgst digest.Digest) error {
		_, ok := uniq[dgst]
		if ok {
			return nil
		}
		uniq[dgst] = struct{}{}
		return cb(dgst)
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

func getLayerFromManifest(m distribution.Manifest, cb func(dgst digest.Digest) error) error {
	switch m := m.(type) {
	case *ocischema.DeserializedManifest:
		for _, layer := range m.Layers {
			if layer.Size == 0 {
				continue
			}
			err := cb(layer.Digest)
			if err != nil {
				return err
			}
		}
	case *schema2.DeserializedManifest:
		for _, layer := range m.Layers {
			if layer.Size == 0 {
				continue
			}
			err := cb(layer.Digest)
			if err != nil {
				return err
			}
		}
	case *schema1.SignedManifest:
		for _, layer := range m.FSLayers {
			err := cb(layer.BlobSum)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func ping(manager challenge.Manager, endpoint, versionHeader string) ([]auth.APIVersion, error) {
	resp, err := http.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := manager.AddResponse(resp); err != nil {
		return nil, err
	}

	return auth.APIVersions(resp, versionHeader), err
}

type credentialStore struct {
	username      string
	password      string
	refreshTokens map[string]string
}

func (tcs *credentialStore) Basic(*url.URL) (string, string) {
	return tcs.username, tcs.password
}

func (tcs *credentialStore) RefreshToken(u *url.URL, service string) string {
	return tcs.refreshTokens[service]
}

func (tcs *credentialStore) SetRefreshToken(u *url.URL, service string, token string) {
	if tcs.refreshTokens != nil {
		tcs.refreshTokens[service] = token
	}
}
