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
	nodeType NodeType
	name     string
	hash     string
	children []*RemoteNode
	data     []byte
	// Represents type represented in file system - Big node can represent part of dir of file
	IsDir  bool
	IsFile bool
}

// ========================== remoteNode ==========================

func (r RemoteNode) Type() NodeType {
	return r.nodeType
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

func (rd RemoteNode) Children() []*RemoteNode {
	return rd.children
}

func (rc RemoteNode) Data() []byte {
	return rc.data
}

// ======================= remoteMerkleTree =======================

func NewRemoteMerkleTree(hash string) RemoteMerkleTree {
	rootNode := &RemoteNode{
		name:     "",
		hash:     hash,
		nodeType: NO_TYPE,
		IsFile:   false,
		IsDir:    false,
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
	if node.IsDir {
		return errors.New("invalid node type, cannot be dir and file at the same time")
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
	node.IsFile = true
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
	if node.IsFile {
		return errors.New("invalid node type, cannot be dir and file at the same time")
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
	node.IsDir = true
	newChildren := make([]*RemoteNode, len(children.Records))
	for i, ch := range children.Records {
		hashStr := ConvertHashBytesToString(ch.Hash)
		childNode := rmt.GetNode(hashStr)
		if childNode == nil {
			rmt.mutex.Lock()
			childNode = &RemoteNode{name: ch.Name, IsDir: false, IsFile: false,
				hash: hashStr, nodeType: NO_TYPE}
			rmt.nodeMap[hashStr] = childNode
			rmt.mutex.Unlock()
		}
		newChildren[i] = childNode
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
	for i, ch := range children.Records {
		strHash := ConvertHashBytesToString(ch.Hash)
		childNode := rmt.GetNode(strHash)
		if childNode == nil {
			rmt.mutex.Lock()
			childNode = &RemoteNode{hash: strHash,
				nodeType: NO_TYPE, IsDir: node.IsDir, IsFile: node.IsFile}
			rmt.nodeMap[strHash] = childNode
			rmt.mutex.Unlock()
		}
		newChildren[i] = childNode
	}
	node.children = newChildren
	node.nodeType = BIG
	return nil
}
