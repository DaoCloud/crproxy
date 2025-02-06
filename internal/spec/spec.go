package spec

type ManifestLayers struct {
	Config Layer   `json:"config"`
	Layers []Layer `json:"layers"`
}

type Layer struct {
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

type IndexManifestLayers struct {
	Manifests []ManifestLayer `json:"manifests"`
}

type ManifestLayer struct {
	Size     int64    `json:"size"`
	Digest   string   `json:"digest"`
	Platform Platform `json:"platform"`
}

type Platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}
