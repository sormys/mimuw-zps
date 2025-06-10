package merkle_tree

import (
	"crypto/sha256"
	"errors"
)

// This tree is most likely not complete, and is constructed by adding nodes
// from received data. This means that we verify the integrity of the tree as
// we build it.
type remoteMerkleTree struct {
	nodeMap  map[string]*remoteNode
	rootNode *remoteNode
}

type remoteNode struct {
	nodeType          NodeType
	name              string
	hash              string
	parent            *remoteNode
	children          []*remoteNode
	data              []byte
	hasChunkChild     bool
	hasDirectoryChild bool
}

// ========================== remoteNode ==========================

func (r remoteNode) Type() NodeType {
	return r.nodeType
}

func (r remoteNode) Name() string {
	return r.name
}

func (r *remoteNode) SetName(s string) {
	r.name = s
}

func (r remoteNode) Hash() string {
	return r.hash
}

func (r remoteNode) Parent() *remoteNode {
	return r.parent
}

func (rd remoteNode) Children() []*remoteNode {
	return rd.children
}

func (rc remoteNode) Data() []byte {
	return rc.data
}

func (rd *remoteNode) registerChildrenType(nodeType NodeType) error {
	if rd.Type() != BIG {
		return nil
	}
	switch nodeType {
	case NO_TYPE, BIG:
		// Nothing to do
	case CHUNK:
		if rd.hasDirectoryChild {
			return errors.New("big node has multiple types of values")
		}
		if !rd.hasChunkChild && rd.parent != nil {
			// State has changed
			if err := rd.parent.registerChildrenType(CHUNK); err != nil {
				return err
			}
		}
		rd.hasChunkChild = true
	case DIRECTORY:
		if rd.hasChunkChild {
			return errors.New("big node has multiple types of values")
		}
		if !rd.hasDirectoryChild && rd.parent != nil {
			// State has changed
			if err := rd.parent.registerChildrenType(DIRECTORY); err != nil {
				return err
			}
		}
		rd.hasDirectoryChild = true
	default:
		return errors.New("unknown node type")
	}
	return nil
}

// ======================= remoteMerkleTree =======================

func NewRemoteMerkleTree(hash string) remoteMerkleTree {
	rootNode := &remoteNode{
		name:     "",
		hash:     hash,
		nodeType: NO_TYPE,
		children: []*remoteNode{},
	}
	return remoteMerkleTree{
		rootNode: rootNode,
		nodeMap:  map[string]*remoteNode{hash: rootNode},
	}
}

func (rmt *remoteMerkleTree) Root() *remoteNode {
	return rmt.rootNode
}

func (rmt *remoteMerkleTree) GetNode(hash string) *remoteNode {
	return rmt.nodeMap[hash]
}

func (rmt *remoteMerkleTree) DiscoverAsChunk(nodeHash string, data []byte) error {
	node, exist := rmt.nodeMap[nodeHash]
	if !exist {
		return errors.New("no node with given hash found")
	}
	if node.Type() != NO_TYPE {
		return errors.New("cannot change type of initialized node")
	}

	if data == nil {
		return errors.New("chunk cannot have nil data")
	}
	expectedHash := hashData([][]byte{data})
	if expectedHash != nodeHash {
		return errors.New("invalid data (hashes do not match)")
	}
	if node.parent != nil {
		if err := node.parent.registerChildrenType(CHUNK); err != nil {
			return err
		}
	}
	node.nodeType = CHUNK
	node.data = data
	return nil
}

func (rmt *remoteMerkleTree) DiscoverAsDirectory(
	nodeHash string,
	children []DirectoryRecordRaw) error {
	node, exist := rmt.nodeMap[nodeHash]
	if !exist {
		return errors.New("no node with given hash found")
	}
	if node.Type() != NO_TYPE {
		return errors.New("cannot change type of initialized node")
	}
	if len(node.Children()) != 0 {
		return errors.New("this node already has children, cannot convert to directory node")
	}

	hash := sha256.New()
	for _, ch := range children {
		hash.Write(ch.hash)
	}
	hashStr := convertHashToString(hash)
	if hashStr != node.hash {
		return errors.New("invalid children (hashes do not match)")
	}
	if node.parent != nil {
		if err := node.parent.registerChildrenType(DIRECTORY); err != nil {
			return err
		}
	}
	newChildren := make([]*remoteNode, len(children))
	for i, ch := range children {
		hashStr := convertHashBytesToString(ch.hash)
		newChildren[i] = &remoteNode{name: ch.name, parent: node,
			hash: convertHashBytesToString(ch.hash), nodeType: NO_TYPE}
		rmt.nodeMap[hashStr] = newChildren[i]
	}
	node.children = newChildren
	node.nodeType = DIRECTORY
	return nil
}

func (rmt *remoteMerkleTree) DiscoverAsBig(
	nodeHash string,
	childrenHashes [][]byte) error {
	node, exist := rmt.nodeMap[nodeHash]
	if !exist {
		return errors.New("no node with given hash found")
	}
	if node.Type() != NO_TYPE {
		return errors.New("cannot change type of initialized node")
	}
	if len(node.Children()) != 0 {
		return errors.New("this node already has children, cannot convert to big node")
	}

	hash := sha256.New()
	for _, chHash := range childrenHashes {
		hash.Write(chHash)
	}
	hashStr := convertHashToString(hash)
	if hashStr != node.hash {
		return errors.New("invalid children (hashes do not match)")
	}
	newChildren := make([]*remoteNode, len(childrenHashes))
	for i, chHash := range childrenHashes {
		strHash := convertHashBytesToString(chHash)
		newChildren[i] = &remoteNode{hash: strHash,
			parent: node, nodeType: NO_TYPE}
		rmt.nodeMap[strHash] = newChildren[i]
	}
	node.children = newChildren
	node.nodeType = BIG
	return nil
}
