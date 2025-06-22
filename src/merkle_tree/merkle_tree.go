package merkle_tree

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"mimuw_zps/src/handler"
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
func hashDatum(data *Datum) handler.Hash {
	var nodeTypeByte byte
	switch data.NodeType {
	case CHUNK:
		nodeTypeByte = 0
	case DIRECTORY:
		nodeTypeByte = 1
	case BIG:
		nodeTypeByte = 2
	}
	data.Data = append([]byte{nodeTypeByte}, data.Data...)
	h := sha256.Sum256(data.Data)
	data.Hash = h
	return h
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

type DirectoryRecords struct {
	Records []DirectoryRecord
	Raw     []byte
}

type DirectoryRecord struct {
	Name string
	Hash []byte
}
