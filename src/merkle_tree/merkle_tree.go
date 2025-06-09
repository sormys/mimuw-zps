package merkle_tree

import (
	h "hash"
)

type MerkleTree interface {
	GetRoot() Node
	GetNode(h.Hash) Node
}

type Node interface {
	GetName() string
	GetHash() h.Hash
	GetParent() Node
	Verify() bool
}

type ChunkNode interface {
	Node
	GetData() []byte
}

type DirectoryNode interface {
	Node
	GetChildren() []Node
}

type BigNode interface {
	Node
	GetChildren() []Node
}
