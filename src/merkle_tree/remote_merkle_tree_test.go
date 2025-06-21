package merkle_tree

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestVerifyCorrect(t *testing.T) {
	chunk1Data := []byte{0x10, 0x20, 0x01, 0x30}
	chunk2Data := []byte{0x11, 0x32, 0x81, 0x32}
	chunk1Sha := sha256.New()
	chunk1Sha.Write(chunk1Data)
	chunk1Str := hex.EncodeToString(chunk1Sha.Sum(nil))
	chunk2Sha := sha256.New()
	chunk2Sha.Write(chunk2Data)
	chunk2Str := hex.EncodeToString(chunk2Sha.Sum(nil))
	bigSha := sha256.New()
	bigSha.Write(chunk1Sha.Sum(nil))
	bigSha.Write(chunk2Sha.Sum(nil))
	bigStr := hex.EncodeToString(bigSha.Sum(nil))

	tree := NewRemoteMerkleTree(bigStr)
	if err := tree.DiscoverAsBig(bigStr, [][]byte{chunk1Sha.Sum(nil),
		chunk2Sha.Sum(nil)}); err != nil {
		t.Errorf("Error while converting node to big %s", err)
	}
	if err := tree.DiscoverAsChunk(chunk1Str, chunk1Data); err != nil {
		t.Errorf("Error while converting node to chunk %s", err)
	}
	if err := tree.DiscoverAsChunk(chunk2Str, chunk2Data); err != nil {
		t.Errorf("Error while converting node to chunk %s", err)
	}
}

func TestVerifyIncorrect(t *testing.T) {
	chunk1Data := []byte{0x10, 0x20, 0x01, 0x30}
	chunk2Data := []byte{0x11, 0x32, 0x81, 0x32}
	chunk1Sha := sha256.New()
	chunk1Sha.Write(chunk1Data)
	chunk1Str := hex.EncodeToString(chunk1Sha.Sum(nil))
	chunk2Sha := sha256.New()
	chunk2Sha.Write(chunk2Data)
	chunk2Str := hex.EncodeToString(chunk2Sha.Sum(nil))
	bigSha := sha256.New()
	bigSha.Write(chunk1Sha.Sum(nil))
	bigSha.Write(chunk2Sha.Sum(nil))
	bigStr := hex.EncodeToString(bigSha.Sum(nil))

	tree := NewRemoteMerkleTree(bigStr)
	if err := tree.DiscoverAsBig(bigStr, [][]byte{chunk1Sha.Sum(nil),
		chunk2Sha.Sum(nil)}); err != nil {
		t.Errorf("Error while converting node to big %s", err)
	}
	if err := tree.DiscoverAsChunk(chunk1Str, chunk1Data); err != nil {
		t.Errorf("Error while converting node to chunk %s", err)
	}
	// Now use wrong data in chunk2
	if err := tree.DiscoverAsChunk(chunk2Str, chunk1Data); err == nil {
		t.Errorf("Provided wrong data but no error returned")
	}
}

// func TestEmptyDirectory(t *testing.T) {
// 	// creating some correct hashes, data is not important
// 	name1 := "one"
// 	hash1Data := []byte{0x10, 0x20, 0x01, 0x30}
// 	hash1Sha := sha256.New()
// 	hash1Sha.Write(hash1Data)
// 	hash1Str := hex.EncodeToString(hash1Sha.Sum(nil))
// 	directorySha := sha256.New()
// 	directorySha.Write(hash1Sha.Sum(nil))
// 	directoryStr := hex.EncodeToString(directorySha.Sum(nil))

// 	tree := NewRemoteMerkleTree(directoryStr)
// 	if err := tree.DiscoverAsDirectory(directoryStr, []DirectoryRecord{
// 		{Name: name1,
// 			Hash: hash1Sha.Sum(nil)}}); err != nil {
// 		t.Errorf("Error while converting node to big %s", err)
// 	}
// 	if err := tree.DiscoverAsDirectory(hash1Str, []DirectoryRecord{}); err == nil {
// 		t.Errorf("No error occured on empty directory")
// 	}
// }

// func TestConflictingNodeTypesInBig(t *testing.T) {
// 	dirChunkName := "one"
// 	dirChunkData := []byte{0x10, 0x20, 0x01, 0x30}
// 	chunkData := []byte{0x11, 0x32, 0x81, 0x32}
// 	DirChunkSha := sha256.New()
// 	DirChunkSha.Write(dirChunkData)
// 	DirSha := sha256.New()
// 	DirSha.Write(DirChunkSha.Sum(nil))
// 	DirStr := hex.EncodeToString(DirSha.Sum(nil))
// 	ChunkSha := sha256.New()
// 	ChunkSha.Write(chunkData)
// 	ChunkStr := hex.EncodeToString(ChunkSha.Sum(nil))
// 	bigSha := sha256.New()
// 	bigSha.Write(DirSha.Sum(nil))
// 	bigSha.Write(ChunkSha.Sum(nil))
// 	bigStr := hex.EncodeToString(bigSha.Sum(nil))

// 	tree := NewRemoteMerkleTree(bigStr)
// 	if err := tree.DiscoverAsBig(bigStr, [][]byte{DirSha.Sum(nil),
// 		ChunkSha.Sum(nil)}); err != nil {
// 		t.Errorf("Error while converting node to big %s", err)
// 	}
// 	if err := tree.DiscoverAsChunk(ChunkStr, chunkData); err != nil {
// 		t.Errorf("Error while converting node to chunk %s", err)
// 	}
// 	if err := tree.DiscoverAsDirectory(DirStr, []DirectoryRecord{{
// 		Name: dirChunkName, Hash: DirChunkSha.Sum(nil)}}); err == nil {
// 		t.Errorf("No error when there are conflicting type in big node")
// 	}
// }
