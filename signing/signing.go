package signing

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// The signing format is as follows
//
// base64(signature(data)) + "," + base64(data)
//
// Don't store private data like passwords.

var base = base64.RawURLEncoding

type Signer struct {
	PrivateKey *rsa.PrivateKey
}

func NewSigner(privateKey *rsa.PrivateKey) *Signer {
	return &Signer{
		PrivateKey: privateKey,
	}
}

func (e *Signer) Sign(data []byte) (code string, err error) {
	encodedData := base.EncodeToString(data)
	digest := sha256.Sum256([]byte(encodedData))
	signature, err := rsa.SignPSS(rand.Reader, e.PrivateKey, crypto.SHA256, digest[:], nil)
	if err != nil {
		return "", err
	}

	encodedSignature := base.EncodeToString(signature)
	return encodedSignature + "," + encodedData, nil
}

type Verifier struct {
	PublicKey *rsa.PublicKey
}

func NewVerifier(publicKey *rsa.PublicKey) *Verifier {
	return &Verifier{
		PublicKey: publicKey,
	}
}

func (d *Verifier) Verify(code string) ([]byte, error) {
	cs := strings.SplitN(code, ",", 3)
	if len(cs) != 2 {
		return nil, fmt.Errorf("invalid token code: %s", code)
	}
	encodedSignature := cs[0]
	encodedData := cs[1]
	signature, err := base.DecodeString(encodedSignature)
	if err != nil {
		return nil, err
	}

	digest := sha256.Sum256([]byte(encodedData))
	err = rsa.VerifyPSS(d.PublicKey, crypto.SHA256, digest[:], signature, nil)
	if err != nil {
		return nil, err
	}

	data, err := base.DecodeString(encodedData)
	if err != nil {
		return nil, err
	}
	return data, nil
}
