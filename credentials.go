package crproxy

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/distribution/distribution/v3/registry/client/auth/challenge"
)

type Userpass struct {
	Username string
	Password string
}

type basicCredentials struct {
	credentials map[string]Userpass
}

func newBasicCredentials(cred map[string]Userpass, domainAlias func(string) string, hostScheme func(string) string) (*basicCredentials, error) {
	bc := &basicCredentials{
		credentials: map[string]Userpass{},
	}
	for domain, c := range cred {
		urls, err := getAuthURLs(hostScheme(domain)+"://"+domain, domainAlias)
		if err != nil {
			return nil, err
		}
		for _, u := range urls {
			bc.credentials[u] = c
		}
	}
	return bc, nil
}

func (c *basicCredentials) Basic(u *url.URL) (string, string) {
	up := c.credentials[u.String()]

	return up.Username, up.Password
}

func (c *basicCredentials) RefreshToken(u *url.URL, service string) string {
	return ""
}

func (c *basicCredentials) SetRefreshToken(u *url.URL, service, token string) {
}

func getAuthURLs(remoteURL string, domainAlias func(string) string) ([]string, error) {
	authURLs := []string{}

	u, err := url.Parse(remoteURL)
	if err != nil {
		return nil, err
	}
	if domainAlias != nil {
		u.Host = domainAlias(u.Host)
	}
	remoteURL = u.String()

	resp, err := http.Get(remoteURL + "/v2/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	for _, c := range challenge.ResponseChallenges(resp) {
		if strings.EqualFold(c.Scheme, "bearer") {
			authURLs = append(authURLs, c.Parameters["realm"])
		}
	}

	return authURLs, nil
}
