package encryption

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
)

const KEY_LENGTH = 64
const BYTE_LENGTH_32 = 32
const privateKeyFile = "private_key.pem"

type Message []byte
type TypeMessage []byte
type Signature = [KEY_LENGTH]byte

var EMPTY_SIGNATURE = Signature{}

type Key = [KEY_LENGTH]byte

var privateKey *ecdsa.PrivateKey
var publicKey *ecdsa.PublicKey

func getKeyPath(privateKeyFile string) (string, error) {
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	return filepath.Join(dir, privateKeyFile), nil
}

func savePrivateKeyToFile(key *ecdsa.PrivateKey) error {
	data, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: data,
	}
	path, err := getKeyPath(privateKeyFile)
	if err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, pemBlock)
}

func loadPrivateKeyFromFile() (*ecdsa.PrivateKey, error) {
	path, err := getKeyPath(privateKeyFile)
	if err != nil {
		return nil, err
	}
	data, _ := os.ReadFile(path)
	block, _ := pem.Decode(data)
	return x509.ParseECPrivateKey(block.Bytes)
}

func PrivateKeyFileExists() bool {
	path, err := getKeyPath(privateKeyFile)
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

func init() {
	var err error
	if !PrivateKeyFileExists() {
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			slog.Error("Failed to generate private key", "err", err)
			return
		}
		err = savePrivateKeyToFile(privateKey)
		if err != nil {
			slog.Error("Failed to save private key", "err", err)
			return
		}
	} else {
		privateKey, _ = loadPrivateKeyFromFile()
	}
	publicKey = privateKey.Public().(*ecdsa.PublicKey)
}

func GetMyPublicKey() ecdsa.PublicKey {
	return *publicKey
}

func GetMyPublicKeyBytes() (Key, error) {
	x := publicKey.X.Bytes()
	y := publicKey.Y.Bytes()

	if len(x) != BYTE_LENGTH_32 || len(y) != BYTE_LENGTH_32 {
		return Key{}, errors.New("incorrect publicKey")
	}

	var key Key
	copy(key[:BYTE_LENGTH_32], x)
	copy(key[BYTE_LENGTH_32:], y)

	return key, nil
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
	signature := make([]byte, KEY_LENGTH)
	r.FillBytes(signature[:BYTE_LENGTH_32])
	s.FillBytes(signature[BYTE_LENGTH_32:])

	var a Signature
	copy(a[:], signature)
	return a
}

func VerifySignature(data []byte, signature Signature, publicKey *ecdsa.PublicKey) bool {
	var r, s big.Int
	r.SetBytes(signature[:BYTE_LENGTH_32])
	s.SetBytes(signature[BYTE_LENGTH_32:])
	hashed := sha256.Sum256(data)
	return ecdsa.Verify(publicKey, hashed[:], &r, &s)
}
