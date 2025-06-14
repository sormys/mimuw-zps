package merkle_tree

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
)

type NodeType string

const (
	NO_TYPE   NodeType = "no type"
	CHUNK     NodeType = "chunk"
	DIRECTORY NodeType = "directory"
	BIG       NodeType = "big"
)

func hashData(childrenHash [][]byte) string {
	h := sha256.New()
	for _, hash := range childrenHash {
		h.Write(hash)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func ConvertHashToString(hash hash.Hash) string {
	return hex.EncodeToString(hash.Sum(nil))
}

func ConvertHashBytesToString(hash []byte) string {
	return hex.EncodeToString(hash)
}

func ConvertStringHashToBytes(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

type DirectoryRecordRaw struct {
	Name string
	Hash []byte
}
