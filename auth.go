package crproxy

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/distribution/distribution/v3/registry/api/errcode"
)

func (c *CRProxy) AuthToken(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errcode.ServeJSON(rw, errcode.ErrorCodeUnsupported)
		return
	}
	if !c.simpleAuth {
		errcode.ServeJSON(rw, errcode.ErrorCodeUnsupported)
		return
	}
	query := r.URL.Query()
	scope := query.Get("scope")
	service := query.Get("service")

	if c.simpleAuthUserpassFunc != nil {
		authorization := r.Header.Get("Authorization")
		auth := strings.SplitN(authorization, " ", 2)
		if len(auth) != 2 {
			if c.logger != nil {
				c.logger.Println("Login failed", authorization)
			}
			errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
			return
		}
		switch auth[0] {
		case "Basic":
			user, pass, ok := parseBasicAuth(auth[1])
			if user == "" || pass == "" {
				errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
				return
			}

			var u *url.Userinfo
			if ok {
				u = url.UserPassword(user, pass)
			} else {
				u = url.User(user)
			}
			if !c.simpleAuthUserpassFunc(r, u) {
				if c.logger != nil {
					c.logger.Println("Login failed user and password", u)
				}
				errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
				return
			}

			if c.logger != nil {
				c.logger.Println("Login succeed user", u.Username())
			}
		default:
			if c.logger != nil {
				c.logger.Println("Unsupported authorization", authorization)
			}
			errcode.ServeJSON(rw, errcode.ErrorCodeDenied)
			return
		}
	}

	rw.Header().Set("Content-Type", "application/json")

	now := time.Now()
	expiresIn := 60
	token := defaultTokenManager.Encode(Token{
		Service:   service,
		Scope:     scope,
		ExpiresAt: now.Add(time.Duration(expiresIn) * time.Second),
	})

	json.NewEncoder(rw).Encode(tokenInfo{
		Token:     token,
		ExpiresIn: int64(expiresIn),
		IssuedAt:  now,
	})
}

func (c *CRProxy) authenticate(rw http.ResponseWriter, r *http.Request) {
	tokenURL := c.tokenURL
	if tokenURL == "" {
		var scheme = "http"
		if c.tokenAuthForceTLS || r.TLS != nil || r.URL.Scheme == "https" {
			scheme = "https"
		}
		tokenURL = scheme + "://" + r.Host + "/auth/token"
	}
	header := fmt.Sprintf("Bearer realm=%q,service=%q", tokenURL, r.Host)
	rw.Header().Set("WWW-Authenticate", header)
	c.errorResponse(rw, r, errcode.ErrorCodeUnauthorized)
}

func (c *CRProxy) authorization(rw http.ResponseWriter, r *http.Request) bool {
	if c.privilegedNoAuth && c.isPrivileged(r, nil) {
		r.Header.Del("Authorization")
		return true
	}

	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false
	}

	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}

	token, ok := defaultTokenManager.Decode(auth[7:])
	if !ok {
		return false
	}

	if token.ExpiresAt.Before(time.Now()) {
		return false
	}

	r.Header.Del("Authorization")
	return true
}

type tokenInfo struct {
	Token     string    `json:"token,omitempty"`
	ExpiresIn int64     `json:"expires_in,omitempty"`
	IssuedAt  time.Time `json:"issued_at,omitempty"`
}

var defaultTokenManager = &tokenManager{
	NewHash:        sha256.New,
	RandReader:     rand.Reader,
	HashSize:       sha256.Size,
	RandSize:       16,
	EncodeToString: base64.RawURLEncoding.EncodeToString,
	DecodeString:   base64.RawURLEncoding.DecodeString,
}

type tokenManager struct {
	NewHash        func() hash.Hash
	RandReader     io.Reader
	HashSize       int
	RandSize       int
	EncodeToString func([]byte) string
	DecodeString   func(string) ([]byte, error)
}

type Token struct {
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	Service   string    `json:"service,omitempty"`
}

func (p *tokenManager) Encode(t Token) (code string) {
	sum := make([]byte, p.RandSize+p.HashSize)
	io.ReadFull(p.RandReader, sum[:p.RandSize])
	hashSum := p.NewHash()
	data, _ := json.Marshal(t)
	hashSum.Write(data)
	hashSum.Write(sum[:p.RandSize])
	sum = hashSum.Sum(sum[:p.RandSize])
	return p.EncodeToString(sum) + "." + p.EncodeToString(data)
}

func (p *tokenManager) Decode(code string) (t Token, b bool) {
	cs := strings.Split(code, ".")
	if len(cs) != 2 {
		return t, false
	}

	sum, err := p.DecodeString(cs[0])
	if err != nil {
		return t, false
	}
	if len(sum) != p.HashSize+p.RandSize {
		return t, false
	}
	data, err := p.DecodeString(cs[1])
	if err != nil {
		return t, false
	}
	hashSum := p.NewHash()
	hashSum.Write(data)
	hashSum.Write(sum[:p.RandSize])
	newSum := hashSum.Sum(nil)
	if !bytes.Equal(sum[p.RandSize:], newSum) {
		return t, false
	}

	err = json.Unmarshal(data, &t)
	if err != nil {
		return t, false
	}

	return t, true
}

func parseBasicAuth(auth string) (username, password string, ok bool) {
	c, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false
	}
	return username, password, true
}
