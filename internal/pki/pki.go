package pki

import (
	"crypto/rand"
	"crypto/rsa"
)

func GenerateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 1024)
}
