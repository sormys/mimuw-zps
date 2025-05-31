package encryption

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"log/slog"
	"math/big"
)

// uniform name to Key_length
const ENCRYPTION_KEY_LENGTH = 64
const PUBLIC_KEY_LENGTH = 64
const BYTE_LENGTH_32 = 32

type Message []byte
type TypeMessage []byte
type Signature []byte

var EMPTY_SIGNATURE = Signature([]byte{0x00})

type Key = [ENCRYPTION_KEY_LENGTH]byte

var privateKey *ecdsa.PrivateKey
var publicKey *ecdsa.PublicKey

func init() {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		slog.Error("Failed to generate private key", "err", err)
		return
	}
	privateKey = privKey
	publicKey = privateKey.Public().(*ecdsa.PublicKey)
}

func GetMyPublicKey() ecdsa.PublicKey {
	return *publicKey
}

// The code below comes from the project description
func ParsePublicKey(data Key) *ecdsa.PublicKey {
	var x, y big.Int
	x.SetBytes(data[:BYTE_LENGTH_32])
	y.SetBytes(data[BYTE_LENGTH_32:])
	publicKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     &x,
		Y:     &y,
	}
	return &publicKey
}

func GetSignature(data Message) Signature {
	hashed := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
	if err != nil {
		slog.Error("Failed to sign message", "err", err)
		return EMPTY_SIGNATURE
	}
	signature := make([]byte, PUBLIC_KEY_LENGTH)
	r.FillBytes(signature[:BYTE_LENGTH_32])
	s.FillBytes(signature[BYTE_LENGTH_32:])
	return signature
}

func VerifySignature(data, signature []byte, publicKey *ecdsa.PublicKey) bool {
	var r, s big.Int
	if len(signature) != 64 {
		return false
	}
	r.SetBytes(signature[:BYTE_LENGTH_32])
	s.SetBytes(signature[BYTE_LENGTH_32:])
	hashed := sha256.Sum256(data)
	return ecdsa.Verify(publicKey, hashed[:], &r, &s)
}
