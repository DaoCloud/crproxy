package signing

import (
	"reflect"
	"testing"

	"github.com/daocloud/crproxy/internal/pki"
)

func TestSigning(t *testing.T) {
	privateKey, err := pki.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate private key: %s", err)
	}

	raw := []byte("Hello world")
	encoder := NewSigner(privateKey)
	code, err := encoder.Sign(raw)
	if err != nil {
		t.Fatalf("failed to sign token: %s", err)
	}

	t.Logf("encoded token: %s", code)
	t.Logf("encoded size: %d", len(code))

	decoder := NewVerifier(&privateKey.PublicKey)
	decoded, err := decoder.Verify(code)
	if err != nil {
		t.Fatalf("failed to verify token: %s", err)
	}
	if !reflect.DeepEqual(decoded, raw) {
		t.Fatalf("decoded token does not match original")
	}
}

func BenchmarkSign(b *testing.B) {
	privateKey, err := pki.GenerateKey()
	if err != nil {
		b.Fatalf("failed to generate private key: %s", err)
	}
	encoder := NewSigner(privateKey)
	raw := []byte("Hello world")

	b.StartTimer()
	defer b.StopTimer()
	for i := 0; i < b.N; i++ {
		_, err := encoder.Sign(raw)
		if err != nil {
			b.Fatalf("failed to sign token: %s", err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	privateKey, err := pki.GenerateKey()
	if err != nil {
		b.Fatalf("failed to generate private key: %s", err)
	}

	raw := []byte("Hello world")
	encoder := NewSigner(privateKey)
	code, err := encoder.Sign(raw)
	if err != nil {
		b.Fatalf("failed to sign token: %s", err)
	}

	decoder := NewVerifier(&privateKey.PublicKey)

	b.StartTimer()
	defer b.StopTimer()
	for i := 0; i < b.N; i++ {
		_, err := decoder.Verify(code)
		if err != nil {
			b.Fatalf("failed to verify token: %s", err)
		}
	}
}
