package storage

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/docker/distribution/registry/storage/driver"
	"github.com/docker/distribution/registry/storage/driver/factory"
)

type (
	FileWriter    = driver.FileWriter
	StorageDriver = driver.StorageDriver
)

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
		parameters["accesskey"] = u.User.Username()
		parameters["secretkey"], _ = u.User.Password()
	}

	if u.Host != "" {
		part := strings.SplitN(u.Host, ".", 2)
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
