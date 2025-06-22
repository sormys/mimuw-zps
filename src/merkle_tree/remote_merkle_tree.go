package merkle_tree

import (
	"crypto/sha256"
	"errors"
	"log/slog"
	"sync"
)

// This tree is most likely not complete, and is constructed by adding nodes
// from received data. This means that we verify the integrity of the tree as
// we build it.
// Creating new merkle tree requires root hash. Each created node has no type
// at the beginning. To set the type and verify the data use one of the Discover
// methods. New nodes should be added only by using DiscoverAsDirectory
// or DiscoverAsBig.
type RemoteMerkleTree struct {
	nodeMap  map[string]*RemoteNode
	rootNode *RemoteNode
	mutex    *sync.RWMutex
}

type RemoteNode struct {
	nodeType          NodeType
	name              string
	hash              string
	parent            *RemoteNode
	children          []*RemoteNode
	data              []byte
	hasChunkChild     bool
	hasDirectoryChild bool
}

// ========================== remoteNode ==========================

func (r RemoteNode) Type() NodeType {
	return r.nodeType
}

// Represents type represented in file system - Big node can represent part of dir of file
func (r RemoteNode) IsDir() bool {
	return r.Type() == DIRECTORY || r.hasDirectoryChild
}

func (r RemoteNode) IsFile() bool {
	return r.Type() == CHUNK || r.hasChunkChild
}

func (r RemoteNode) Name() string {
	return r.name
}

func (r *RemoteNode) SetName(s string) {
	r.name = s
}

func (r RemoteNode) Hash() string {
	return r.hash
}

func (r RemoteNode) Parent() *RemoteNode {
	return r.parent
}

func (rd RemoteNode) Children() []*RemoteNode {
	return rd.children
}

func (rc RemoteNode) Data() []byte {
	return rc.data
}

func (rd *RemoteNode) registerChildrenType(nodeType NodeType) error {
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

func NewRemoteMerkleTree(hash string) RemoteMerkleTree {
	rootNode := &RemoteNode{
		name:     "",
		hash:     hash,
		nodeType: NO_TYPE,
		children: []*RemoteNode{},
	}
	return RemoteMerkleTree{
		rootNode: rootNode,
		nodeMap:  map[string]*RemoteNode{hash: rootNode},
		mutex:    &sync.RWMutex{},
	}
}

func (rmt *RemoteMerkleTree) Root() *RemoteNode {
	return rmt.rootNode
}

func (rmt *RemoteMerkleTree) GetNode(hash string) *RemoteNode {
	rmt.mutex.RLock()
	defer rmt.mutex.RUnlock()
	return rmt.nodeMap[hash]
}

// Set the type of node with nodeHash as chunk and validate
// if provided data is correct in merkle tree. If error occurs,
// merkle tree is not modified.
func (rmt *RemoteMerkleTree) DiscoverAsChunk(nodeHash string, data []byte) error {
	node := rmt.GetNode(nodeHash)
	if node == nil {
		return errors.New("no node with given hash found")
	}
	if node.Type() != NO_TYPE {
		return errors.New("cannot change type of initialized node")
	}

	if data == nil {
		return errors.New("chunk cannot have nil data")
	}
	expectedHash := hashData([][]byte{{0x00}, data})
	if expectedHash != node.hash {
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

// Set the type of node with nodeHash as directory and validate
// if provided data is correct in merkle tree. If error occurs,
// merkle tree is not modified.
func (rmt *RemoteMerkleTree) DiscoverAsDirectory(
	nodeHash string,
	children DirectoryRecords) error {
	node := rmt.GetNode(nodeHash)
	if node == nil {
		return errors.New("no node with given hash found")
	}
	if node.Type() != NO_TYPE {
		return errors.New("cannot change type of initialized node")
	}
	if len(node.Children()) != 0 {
		return errors.New("this node already has children, cannot convert to directory node")
	}

	hash := sha256.Sum256(children.Raw)
	hashStr := ConvertHashBytesToString(hash[:])
	if hashStr != node.hash {
		slog.Error("failed to verify hashes:", "requested", nodeHash, "children", children, "got", hashStr)
		return errors.New("invalid children (hashes do not match)")
	}
	if node.parent != nil {
		if err := node.parent.registerChildrenType(DIRECTORY); err != nil {
			return err
		}
	}
	newChildren := make([]*RemoteNode, len(children.Records))
	rmt.mutex.Lock()
	defer rmt.mutex.Unlock()
	for i, ch := range children.Records {
		hashStr := ConvertHashBytesToString(ch.Hash)
		newChildren[i] = &RemoteNode{name: ch.Name, parent: node,
			hash: ConvertHashBytesToString(ch.Hash), nodeType: NO_TYPE}
		rmt.nodeMap[hashStr] = newChildren[i]
	}
	node.children = newChildren
	node.nodeType = DIRECTORY
	return nil
}

// Set the type of node with nodeHash as big node and validate
// if provided data is correct in merkle tree. If error occurs,
// merkle tree is not modified.
func (rmt *RemoteMerkleTree) DiscoverAsBig(
	nodeHash string,
	children DirectoryRecords) error {
	node := rmt.GetNode(nodeHash)
	if node == nil {
		return errors.New("no node with given hash found")
	}
	if node.Type() != NO_TYPE {
		return errors.New("cannot change type of initialized node")
	}
	if len(node.Children()) != 0 {
		return errors.New("this node already has children, cannot convert to big node")
	}

	hash := sha256.Sum256(children.Raw)
	hashStr := ConvertHashBytesToString(hash[:])
	if hashStr != node.hash {
		return errors.New("invalid children (hashes do not match)")
	}
	newChildren := make([]*RemoteNode, len(children.Records))
	rmt.mutex.Lock()
	defer rmt.mutex.Unlock()
	for i, ch := range children.Records {
		strHash := ConvertHashBytesToString(ch.Hash)
		newChildren[i] = &RemoteNode{hash: strHash,
			parent: node, nodeType: NO_TYPE}
		rmt.nodeMap[strHash] = newChildren[i]
	}
	node.children = newChildren
	node.nodeType = BIG
	return nil
}
