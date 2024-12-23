package model

import (
	"database/sql/driver"
)

type User struct {
	UserID   int64
	Nickname string

	Data UserAttr
}

type UserAttr struct {
	NoRateLimit        bool   `json:"no_rate_limit"`
	RateLimitPerSecond uint64 `json:"rate_limit_per_second"`
	NoAllowlist        bool   `json:"no_allowlist"`
	NoBlock            bool   `json:"no_block"`
	AllowTagsList      bool   `json:"allow_tags_list"`
}

func (n *UserAttr) Scan(value any) error {
	if value == nil {
		return nil
	}
	*n = unmarshal[UserAttr](asString(value))
	return nil
}

func (n UserAttr) Value() (driver.Value, error) {
	return marshal(n), nil
}
