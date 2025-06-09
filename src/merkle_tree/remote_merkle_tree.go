package merkle_tree

import (
	"crypto/sha256"
	"errors"
	h "hash"
)

// This tree is most likely not complete, and is constructed by adding nodes
// from received data. This means that we verify the integrity of the tree as
// we built it.
type remoteMerkleTree struct {
	nodeMap  map[h.Hash]Node
	rootNode Node
}

type remoteNode struct {
	name     string
	hash     h.Hash
	parent   Node
	children []Node
}

type remoteChunkNode struct {
	remoteNode
	data []byte
}

type remoteDirectoryNode struct {
	remoteNode
}

type remoteBigNode struct {
	remoteNode
	hasChunkChild     bool
	hasDirectoryChild bool
}

// ========================== remoteNode ==========================

func (r remoteNode) GetName() string {
	return r.name
}

func (r remoteNode) GetHash() h.Hash {
	return r.hash
}

func (r remoteNode) GetParent() Node {
	return r.parent
}

func (r remoteNode) Verify() bool {
	if len(r.children) == 0 {
		return true
	}

	newHash := sha256.New()
	for _, child := range r.children {
		newHash.Write(child.GetHash().Sum(nil))
	}
	computedHash := newHash.Sum(nil)

	return string(computedHash) == string(r.hash.Sum(nil))
}

func (rd remoteNode) GetChildren() []Node {
	return rd.children
}

func (rd *remoteNode) AddChild(child Node) error {
	rd.children = append(rd.children, child)
	return nil
}

// ======================== remoteChunkNode =======================

func (rc remoteChunkNode) Verify() bool {
	return len(rc.children) == 0
}

func (rc remoteChunkNode) GetData() []byte {
	return rc.data
}

func (rd *remoteChunkNode) AddChild(child Node) error {
	return errors.New("chunk node cannot have child nodes")
}

// ====================== remoteDirectoryNode =====================

func (rd *remoteDirectoryNode) AddChild(child Node) error {
	rd.children = append(rd.children, child)
	return nil
}

// ======================== remoteBigNode =========================

func (rd *remoteBigNode) AddChild(child Node) error {
	hasDir := false
	hasCh := false
	switch c := child.(type) {
	case *remoteChunkNode:
		hasCh = true
	case *remoteDirectoryNode:
		hasDir = true
	case *remoteBigNode:
		hasDir = c.hasDirectoryChild
		hasCh = c.hasChunkChild
	default:
		return errors.New("unknown child node type")
	}
	err := rd.updateNodeData(hasDir, hasCh)
	if err != nil {
		return nil
	}
	rd.children = append(rd.children, child)
	return nil
}

func (rd *remoteBigNode) updateNodeData(hasDirectory bool, hasChunk bool) error {
	err := errors.New("big node ahs multiple types of values")
	if rd.hasDirectoryChild && hasChunk {
		return err
	} else if rd.hasChunkChild && hasDirectory {
		return err
	}
	newDirVal := rd.hasDirectoryChild || hasDirectory
	newChVal := rd.hasChunkChild || hasChunk
	if rd.parent != nil {
		parent, ok := rd.parent.(*remoteBigNode)
		if ok {
			err = parent.updateNodeData(newDirVal, newChVal)
			if err != nil {
				return err
			}
		}
	}
	rd.hasChunkChild = newChVal
	rd.hasDirectoryChild = newDirVal
	return nil
}

func newRemoteMerkleTree(hash h.Hash) remoteMerkleTree {
	rootNode := &remoteNode{
		name:     "",
		hash:     hash,
		children: []Node{},
	}
	return remoteMerkleTree{
		rootNode: rootNode,
		nodeMap:  map[h.Hash]Node{hash: rootNode},
	}
}

func (rmt *remoteMerkleTree) GetRoot() Node {
	return rmt.rootNode
}

func (rmt *remoteMerkleTree) GetNode(hash h.Hash) Node {
	return rmt.nodeMap[hash]
}

func (rmt *remoteMerkleTree) AddChild(parentHash h.Hash, child Node) error {
	if child == nil {
		return errors.New("child is nil")
	}

	parentNode := rmt.nodeMap[parentHash]
	switch p := parentNode.(type) {
	case *remoteChunkNode:
		return p.AddChild(child)
	case *remoteDirectoryNode:
		return p.AddChild(child)
	case *remoteBigNode:
		return p.AddChild(child)
	}
	return errors.New("unknown child node type")
}
