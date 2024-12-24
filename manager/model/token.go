package model

import (
	"database/sql/driver"
)

type Token struct {
	TokenID int64
	UserID  int64

	Account  string
	Password string
	Data     TokenAttr
}

type TokenAttr struct {
	NoRateLimit        bool   `json:"no_rate_limit,omitempty"`
	RateLimitPerSecond uint64 `json:"rate_limit_per_second,omitempty"`
	AllowTagsList      bool   `json:"allow_tags_list,omitempty"`
	NoAllowlist        bool   `json:"no_allowlist,omitempty"`
	NoBlock            bool   `json:"no_block,omitempty"`

	BlobsURL string `json:"blobs_url,omitempty"`

	Block        bool   `json:"block,omitempty"`
	BlockMessage string `json:"block_message,omitempty"`
}

func (n *TokenAttr) Scan(value any) error {
	if value == nil {
		return nil
	}
	*n = unmarshal[TokenAttr](asString(value))
	return nil
}

func (n TokenAttr) Value() (driver.Value, error) {
	return marshal(n), nil
}
