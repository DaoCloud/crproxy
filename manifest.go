package crproxy

import (
	"github.com/distribution/distribution/v3"

	_ "github.com/distribution/distribution/v3/manifest/manifestlist"
	_ "github.com/distribution/distribution/v3/manifest/ocischema"
	_ "github.com/distribution/distribution/v3/manifest/schema1"
	_ "github.com/distribution/distribution/v3/manifest/schema2"
)

func UnmarshalManifest(ctHeader string, p []byte) (distribution.Manifest, distribution.Descriptor, error) {
	return distribution.UnmarshalManifest(ctHeader, p)
}
