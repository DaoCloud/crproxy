package model

import (
	"database/sql/driver"
)

type Registry struct {
	RegistryID int64
	UserID     int64

	Domain string
	Data   RegistryAttr
}

type RegistryAttr struct {
	TTLSecond      uint64    `json:"ttl_second"`
	AllowAnonymous bool      `json:"allow_anonymous"`
	Anonymous      TokenAttr `json:"anonymous"`

	AllowPrefix bool   `json:"allow_prefix"`
	Source      string `json:"source"`

	EnableAllowlist      bool     `json:"enable_allowlist"`
	Allowlist            []string `json:"allowlist"`
	AllowlisBlockMessage string   `json:"allowlist_block_message"`

	SpecialIPs map[string]TokenAttr `json:"special_ips"`
}

func (n *RegistryAttr) Scan(value any) error {
	if value == nil {
		return nil
	}
	*n = unmarshal[RegistryAttr](asString(value))
	return nil
}

func (n RegistryAttr) Value() (driver.Value, error) {
	return marshal(n), nil
}
