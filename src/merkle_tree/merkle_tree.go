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

func convertHashToString(hash hash.Hash) string {
	return hex.EncodeToString(hash.Sum(nil))
}

func convertHashBytesToString(hash []byte) string {
	return hex.EncodeToString(hash)
}

type MerkleTree interface {
	Root() Node
	GetNode(string) Node
}

type Node interface {
	Type() NodeType
	Name() string
	Hash() string
	Parent() Node
	Children() []Node
	Data() []byte
	SetName(string)
	Verify() bool
}

type DirectoryRecordRaw struct {
	name string
	hash []byte
}
