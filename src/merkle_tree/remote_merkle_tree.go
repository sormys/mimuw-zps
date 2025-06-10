package merkle_tree

import (
	"crypto/sha256"
	"errors"
)

// This tree is most likely not complete, and is constructed by adding nodes
// from received data. This means that we verify the integrity of the tree as
// we built it.
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

func (rd *remoteNode) AddChild(child *remoteNode) error {
	hasDir := false
	hasCh := false
	switch child.Type() {
	case CHUNK:
		hasCh = true
	case DIRECTORY:
		hasDir = true
	case BIG:
		hasDir = child.hasDirectoryChild
		hasCh = child.hasChunkChild
	default:
		return errors.New("unknown child node type")
	}
	err := rd.UpdateNodeData(hasDir, hasCh)
	if err != nil {
		return nil
	}
	// propagate name
	child.SetName(rd.name)
	rd.children = append(rd.children, child)
	return nil
}

func (rd *remoteNode) UpdateNodeData(hasDirectory bool, hasChunk bool) error {
	if rd.Type() != BIG {
		return nil
	}
	err := errors.New("big node has multiple types of values")
	if rd.hasDirectoryChild && hasChunk {
		return err
	} else if rd.hasChunkChild && hasDirectory {
		return err
	}
	newDirVal := rd.hasDirectoryChild || hasDirectory
	newChVal := rd.hasChunkChild || hasChunk
	if rd.parent != nil && rd.parent.Type() == BIG {
		err = rd.parent.UpdateNodeData(newDirVal, newChVal)
		if err != nil {
			return err
		}
	}
	rd.hasChunkChild = newChVal
	rd.hasDirectoryChild = newDirVal
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
	// TODO(sormys) propagate up the tree the info about the type of the node
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
	// TODO(sormys) propagate up the tree the info about the type of the node
	newChildren := make([]*remoteNode, len(children))
	for i, ch := range children {
		hashStr := convertHashBytesToString(ch.hash)
		newChildren[i] = &remoteNode{name: ch.name,
			hash: convertHashBytesToString(ch.hash), nodeType: NO_TYPE}
		rmt.nodeMap[hashStr] = newChildren[i]
	}
	node.children = newChildren
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
		newChildren[i] = &remoteNode{hash: strHash, nodeType: NO_TYPE}
		rmt.nodeMap[strHash] = newChildren[i]
	}
	node.children = newChildren
	return nil
}
