package token

import (
	"encoding/json"
	"time"

	"github.com/daocloud/crproxy/signing"
)

type Encoder struct {
	signer *signing.Signer
}

func NewEncoder(signer *signing.Signer) *Encoder {
	return &Encoder{
		signer: signer,
	}
}

type Decoder struct {
	verifier *signing.Verifier
}

func NewDecoder(verifier *signing.Verifier) *Decoder {
	return &Decoder{
		verifier: verifier,
	}
}

type Token struct {
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	Service   string    `json:"service,omitempty"`
	Account   string    `json:"account,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Image     string    `json:"image,omitempty"`

	Attribute `json:"attribute,omitempty"`
}

type Attribute struct {
	UserID     int64 `json:"user_id,omitempty"`
	RegistryID int64 `json:"registry_id,omitempty"`
	TokenID    int64 `json:"token_id,omitempty"`

	NoRateLimit        bool   `json:"no_rate_limit,omitempty"`
	RateLimitPerSecond uint64 `json:"rate_limit_per_second,omitempty"`

	NoAllowlist   bool `json:"no_allowlist,omitempty"`
	NoBlock       bool `json:"no_block,omitempty"`
	AllowTagsList bool `json:"allow_tags_list,omitempty"`

	Host  string `json:"host,omitempty"`
	Image string `json:"image,omitempty"`

	BlobsURL string `json:"blobs_url,omitempty"`

	Block        bool   `json:"block,omitempty"`
	BlockMessage string `json:"block_message,omitempty"`
}

func (p *Encoder) Encode(t Token) (code string, err error) {
	data, err := json.Marshal(t)
	if err != nil {
		return "", err
	}

	return p.signer.Sign(data)
}

func (p *Decoder) Decode(code string) (t Token, err error) {
	data, err := p.verifier.Verify(code)
	if err != nil {
		return t, err
	}

	err = json.Unmarshal(data, &t)
	if err != nil {
		return t, err
	}

	return t, nil
}
