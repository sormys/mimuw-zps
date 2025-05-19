package encryption

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

const ENCRYPTION_KEY_LENGTH = 64

type Key = [ENCRYPTION_KEY_LENGTH]byte

var privateKey *ecdsa.PrivateKey
var publicKey *ecdsa.PublicKey

func init() {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("Failed to generate private key")
	}
	publicKey = privateKey.Public().(*ecdsa.PublicKey)
}

func ParsePublicKey(data Key) *ecdsa.PublicKey {
	var x, y big.Int
	x.SetBytes(data[:32])
	y.SetBytes(data[32:])
	publicKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     &x,
		Y:     &y,
	}
	return &publicKey
}

func SignatureMessage(data []byte) []byte {
	hashed := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
	if err != nil {
		panic("Failed to sign message")
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature
}

func VerifySignature(data, signature []byte, publicKey *ecdsa.PublicKey) bool {
	var r, s big.Int
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])
	hashed := sha256.Sum256(data)
	return ecdsa.Verify(publicKey, hashed[:], &r, &s)
}
