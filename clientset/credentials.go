package clientset

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/docker/distribution/registry/client/auth/challenge"
)

type Userpass struct {
	Username string
	Password string
}

func ToUserAndPass(userpass []string) (map[string]Userpass, error) {
	bc := map[string]Userpass{}
	for _, up := range userpass {
		s := strings.SplitN(up, "@", 3)
		if len(s) != 2 {
			return nil, fmt.Errorf("invalid userpass %q", up)
		}

		u := strings.SplitN(s[0], ":", 3)
		if len(s) != 2 {
			return nil, fmt.Errorf("invalid userpass %q", up)
		}
		host := s[1]
		user := u[0]
		pwd := u[1]
		bc[host] = Userpass{
			Username: user,
			Password: pwd,
		}
	}
	return bc, nil
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
