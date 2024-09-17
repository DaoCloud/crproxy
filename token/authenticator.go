package token

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/docker/distribution/registry/api/errcode"
)

type Authenticator struct {
	tokenDecoder *Decoder
	tokenURL     string
}

func NewAuthenticator(
	tokenDecoder *Decoder,
	tokenURL string,
) *Authenticator {
	return &Authenticator{
		tokenDecoder: tokenDecoder,
		tokenURL:     tokenURL,
	}
}

func (c *Authenticator) Authenticate(rw http.ResponseWriter, r *http.Request) {
	tokenURL := c.tokenURL
	if tokenURL == "" {
		var scheme = "http"
		if r.TLS != nil || r.URL.Scheme == "https" {
			scheme = "https"
		}
		tokenURL = scheme + "://" + r.Host + "/auth/token"
	}
	header := fmt.Sprintf("Bearer realm=%q,service=%q", tokenURL, r.Host)
	rw.Header().Set("WWW-Authenticate", header)
	errcode.ServeJSON(rw, errcode.ErrorCodeUnauthorized)
}

func (c *Authenticator) Authorization(r *http.Request) (Token, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return Token{}, fmt.Errorf("no authorization header found")
	}

	if !strings.HasPrefix(auth, "Bearer ") {
		return Token{}, fmt.Errorf("invalid authorization header: %q", auth)
	}

	t, err := c.tokenDecoder.Decode(auth[7:])
	if err != nil {
		return Token{}, err
	}

	if t.ExpiresAt.Before(time.Now()) {
		return Token{}, fmt.Errorf("%s token expired", t.Account)
	}

	r.Header.Del("Authorization")
	return t, nil
}
