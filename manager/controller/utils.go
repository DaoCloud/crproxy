package controller

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"io"
)

var (
	defaultPasswordEncoder = &passwordEncoder{
		NewHash:        sha256.New,
		RandReader:     rand.Reader,
		HashSize:       sha256.Size,
		RandSize:       8,
		EncodeToString: base64.RawURLEncoding.EncodeToString,
		DecodeString:   base64.RawURLEncoding.DecodeString,
	}
)

// password Lossy encryption used to store and verify passwords
type passwordEncoder struct {
	NewHash        func() hash.Hash
	RandReader     io.Reader
	HashSize       int
	RandSize       int
	EncodeToString func([]byte) string
	DecodeString   func(string) ([]byte, error)
}

// Encrypt encryption adds random variables to make each encryption different
func (p *passwordEncoder) Encrypt(word string) (code string) {
	salt := make([]byte, p.RandSize)
	io.ReadFull(p.RandReader, salt)
	return p.encrypt(word, salt)
}

func (p *passwordEncoder) encrypt(word string, salt []byte) (code string) {
	hashSum := p.NewHash()
	hashSum.Write([]byte(word))
	hashSum.Write(salt)
	return p.EncodeToString(append(salt, hashSum.Sum(nil)...))
}

// Verify password
func (p *passwordEncoder) Verify(word, code string) bool {
	raw, err := p.DecodeString(code)
	if err != nil {
		return false
	}
	if len(raw) != p.HashSize+p.RandSize {
		return false
	}
	salt := raw[:p.RandSize]
	return code == p.encrypt(word, salt)
}
