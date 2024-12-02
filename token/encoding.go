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

	Account string `json:"account,omitempty"`
	Image   string `json:"image,omitempty"`

	Attribute `json:"attribute,omitempty"`
}

type Attribute struct {
	NoRateLimit   bool `json:"no_rate_limit,omitempty"`
	NoAllowlist   bool `json:"no_allowlist,omitempty"`
	NoBlock       bool `json:"no_block,omitempty"`
	AllowTagsList bool `json:"allow_tags_list,omitempty"`
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
