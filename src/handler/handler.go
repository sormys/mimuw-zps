package handler

const HASH_LENGTH = 32

type Hash = [HASH_LENGTH]byte

type File struct {
	Hash Hash
	Name string
	Path string
}
