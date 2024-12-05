package token

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/docker/distribution/registry/api/errcode"
)

type Generator struct {
	authFunc     func(r *http.Request, userinfo *url.Userinfo) (Attribute, bool)
	logger       *slog.Logger
	tokenEncoder *Encoder
}

func NewGenerator(
	tokenEncoder *Encoder,
	authFunc func(r *http.Request, userinfo *url.Userinfo) (Attribute, bool),
	logger *slog.Logger,
) *Generator {
	return &Generator{
		authFunc:     authFunc,
		logger:       logger,
		tokenEncoder: tokenEncoder,
	}
}

func (g *Generator) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errcode.ServeJSON(rw, errcode.ErrorCodeUnsupported)
		return
	}

	t, err := g.getToken(r)
	if err != nil {
		errcode.ServeJSON(rw, err)
		return
	}

	rw.Header().Set("Content-Type", "application/json")

	now := time.Now()
	expiresIn := 60

	t.ExpiresAt = now.Add((time.Duration(expiresIn) + 10) * time.Second)

	code, err := g.tokenEncoder.Encode(*t)
	if err != nil {
		g.logger.Error("Error encoding token", "error", err)
		errcode.ServeJSON(rw, errcode.ErrorCodeUnknown)
		return
	}

	json.NewEncoder(rw).Encode(tokenInfo{
		Token:     code,
		ExpiresIn: int64(expiresIn),
		IssuedAt:  now,
	})
}

func (g *Generator) getToken(r *http.Request) (*Token, error) {
	query := r.URL.Query()
	account := query.Get("account")
	scope := query.Get("scope")
	service := query.Get("service")

	t := Token{
		Service: service,
		Scope:   scope,
		Account: account,
	}

	if scope != "" {
		scopeSlice := strings.SplitN(scope, ":", 4)
		if len(scopeSlice) != 3 {
			return nil, errcode.ErrorCodeDenied
		}

		if scopeSlice[2] != "pull" {
			return nil, errcode.ErrorCodeDenied
		}

		t.Image = scopeSlice[1]
	}

	if g.authFunc == nil {
		t.Account = ""
		return &t, nil
	}

	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		attribute, login := g.authFunc(r, nil)
		if !login {
			return nil, errcode.ErrorCodeDenied
		}
		t.Attribute = attribute
		return &t, nil
	}
	auth := strings.SplitN(authorization, " ", 2)
	if len(auth) != 2 {
		g.logger.Error("Login failed", "authorization", authorization)
		return nil, errcode.ErrorCodeDenied
	}
	switch auth[0] {
	case "Basic":
		user, pass, ok := parseBasicAuth(auth[1])
		if user == "" || pass == "" {
			return nil, errcode.ErrorCodeDenied
		}

		if account != "" && account != user {
			return nil, errcode.ErrorCodeDenied
		}

		var u *url.Userinfo
		if ok {
			u = url.UserPassword(user, pass)
		} else {
			u = url.User(user)
		}

		attribute, login := g.authFunc(r, u)
		if !login {
			g.logger.Error("Login failed user and password", "user", u.Username())
			return nil, errcode.ErrorCodeDenied
		}
		t.Attribute = attribute

		g.logger.Info("Login succeed user and password", "user", u.Username())
	default:
		g.logger.Error("Unsupported authorization", "authorization", authorization)
		return nil, errcode.ErrorCodeDenied
	}

	return &t, nil
}

type tokenInfo struct {
	Token     string    `json:"token,omitempty"`
	ExpiresIn int64     `json:"expires_in,omitempty"`
	IssuedAt  time.Time `json:"issued_at,omitempty"`
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
