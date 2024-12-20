package storage

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/docker/distribution/registry/storage/driver"
	"github.com/docker/distribution/registry/storage/driver/factory"
)

type StorageDriver = driver.StorageDriver

func NewStorage(uri string) (StorageDriver, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	parameters := map[string]interface{}{}
	query := u.Query()
	for k := range query {
		parameters[k] = query.Get(k)
	}

	if u.User != nil {
		parameters["accesskeyid"] = u.User.Username()
		parameters["accesskeysecret"], _ = u.User.Password()
	}

	if u.Host != "" {
		part := strings.Split(u.Host, ".")
		if len(part) != 2 {
			return nil, fmt.Errorf("invalid host %q", u.Host)
		}

		parameters["bucket"] = part[0]
		parameters["region"] = part[1]
	}

	sd, err := factory.Create(u.Scheme, parameters)
	if err != nil {
		return nil, fmt.Errorf("create storage driver failed: %w", err)
	}
	return sd, nil
}
