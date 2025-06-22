package merkle_tree

import (
	"io"
	"log/slog"
	"mimuw_zps/src/handler"
	"os"
)

const MAX_CHUNK = 1024
const MAX_CHILDREN_SIZE = 32
const MAX_DIRECTORY = 16
const DIR_HALF_ENTRY = 32

type Datum struct {
	Hash     handler.Hash
	NodeType NodeType
	Data     []byte
	Children []string
}

var hashMap = make(map[string]Datum)
var rootHash handler.Hash

func getNameBytes(name string) []byte {
	if len(name) >= DIR_HALF_ENTRY {
		return []byte(name[:DIR_HALF_ENTRY])
	}
	nameBytes := make([]byte, DIR_HALF_ENTRY)
	copy(nameBytes[:len(name)], []byte(name))
	return nameBytes
}

func chunkFile(path string) ([]handler.Hash, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var chunks []handler.Hash
	buf := make([]byte, MAX_CHUNK)
	for {
		n, err := file.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if n > 0 {
			chunkData := make([]byte, n)
			copy(chunkData, buf[:n])
			node := Datum{NodeType: CHUNK, Data: chunkData}
			hash := hashDatum(&node)
			hashString := ConvertHashBytesToString(hash[:])
			hashMap[hashString] = node
			chunks = append(chunks, handler.Hash(hash))
		}
	}

	return chunks, nil
}

func buildBigNode(hashes []handler.Hash) (handler.Hash, error) {
	if len(hashes) == 1 {
		return hashes[0], nil
	}
	var parentHashes []handler.Hash
	for i := 0; i < len(hashes); i += MAX_CHILDREN_SIZE {
		end := min(i+MAX_CHILDREN_SIZE, len(hashes))
		var children []string
		var storedData []byte
		for j := i; j < end; j++ {
			storedData = append(storedData, hashes[j][:]...)
			children = append(children, ConvertHashBytesToString(hashes[j][:]))
		}
		node := Datum{NodeType: BIG, Data: storedData, Children: children}
		hash := hashDatum(&node)
		hashString := ConvertHashBytesToString(hash[:])
		hashMap[hashString] = node
		parentHashes = append(parentHashes, handler.Hash(hash))
	}
	return buildBigNode(parentHashes)
}

func buildFileNode(path string) (handler.Hash, error) {
	chunks, err := chunkFile(path)
	if len(chunks) == 0 {
		node := Datum{NodeType: CHUNK, Data: []byte{}}
		hash := hashDatum(&node)
		hashString := ConvertHashBytesToString(hash[:])
		hashMap[hashString] = node
		return handler.Hash(hash), nil
	}
	if err != nil {
		return handler.Hash{}, err
	}
	root, err := buildBigNode(chunks)
	return handler.Hash(root), err
}

func buildDirectory(path string) (handler.Hash, error) {
	items, err := os.ReadDir(path)
	if err != nil {
		return handler.Hash{}, err
	}
	if len(items) == 0 {
		node := Datum{NodeType: DIRECTORY, Data: []byte{}, Children: []string{}}
		hash := hashDatum(&node)
		hashString := ConvertHashBytesToString(hash[:])
		hashMap[hashString] = node
		return handler.Hash(hash), nil
	}
	var dirHashes []handler.Hash
	for i := 0; i < len(items); i += MAX_DIRECTORY {
		end := min(i+MAX_DIRECTORY, len(items))
		fragment := items[i:end]

		var hashes []byte
		var children []string
		for _, item := range fragment {
			newPath := path + "/" + item.Name()
			var childHash handler.Hash
			if item.IsDir() {
				childHash, err = buildDirectory(newPath)
			} else {
				childHash, err = buildFileNode(newPath)
			}
			if err != nil {
				return handler.Hash{}, err
			}
			hashes = append(hashes, getNameBytes(item.Name())...)
			hashes = append(hashes, childHash[:]...)
			children = append(children, ConvertHashBytesToString(childHash[:]))
		}
		node := Datum{NodeType: DIRECTORY, Data: hashes, Children: children}
		hash := hashDatum(&node)
		hashString := ConvertHashBytesToString(hash[:])
		hashMap[hashString] = node
		dirHashes = append(dirHashes, node.Hash)
	}
	slog.Debug("number of directory hashes", "count", len(dirHashes))
	if len(dirHashes) == 1 {
		return dirHashes[0], nil
	}
	return buildBigNode(dirHashes)
}

func InitMerkleTree(path string) error {
	hash, err := buildDirectory(path)
	rootHash = hash
	return err
}

func GetRoot() handler.Hash {
	return rootHash
}

func GetHashContent(hash string) (Datum, bool) {
	datum, ok := hashMap[hash]
	return datum, ok
}
