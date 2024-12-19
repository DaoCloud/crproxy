package controller

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/daocloud/crproxy/signing"
	"github.com/emicklei/go-restful/v3"
)

type Session struct {
	UserID int64 `json:"user_id"`
}

func validJWT(key *rsa.PrivateKey, authHeader string) (Session, error) {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return Session{}, errors.New("invalid token")
	}

	jwtToken := strings.Split(authHeader, " ")
	if len(jwtToken) != 2 {
		return Session{}, errors.New("invalid token format")
	}

	data, err := signing.NewVerifier(&key.PublicKey).Verify(jwtToken[1])
	if err != nil {
		return Session{}, fmt.Errorf("failed to decode signature: %w", err)
	}

	var session Session
	err = json.Unmarshal(data, &session)
	if err != nil {
		return Session{}, fmt.Errorf("failed to unmarshal session: %w", err)
	}
	return session, nil
}

func generateJWT(key *rsa.PrivateKey, session Session) (string, error) {
	data, err := json.Marshal(session)
	if err != nil {
		return "", err
	}

	return signing.NewSigner(key).Sign(data)
}

func unauthorizedResponse(resp *restful.Response) {
	resp.AddHeader("WWW-Authenticate", `Bearer realm="/users/login"`)
	resp.WriteHeader(http.StatusUnauthorized)
}

func getSession(key *rsa.PrivateKey, req *restful.Request) (Session, error) {
	authHeader := req.HeaderParameter("Authorization")
	return validJWT(key, authHeader)
}
