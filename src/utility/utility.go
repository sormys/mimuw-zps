package utility

import (
	"crypto/rand"
	"log/slog"
)

type ID = [4]byte

func GetMessageID(data []byte) ID {
	var id ID
	copy(id[:], data[:4])
	return id
}

func GetMessageType(data []byte) uint16 {
	return GetNumberFromBytes(data[4:5])
}

func GetNumberFromBytes(data []byte) uint16 {
	if len(data) == 0 {
		return 0
	}

	if len(data) < 2 {
		return uint16(data[0])
	}
	return uint16(data[0])<<8 | uint16(data[1])
}

func GenerateEmptyBuffor() []byte {
	return make([]byte, 0)
}

func GenerateID() ID {
	var id ID
	_, err := rand.Read(id[:])
	if err != nil {
		slog.Error("Failed to generate ID", "err", err)
		return ID{}
	}
	return id
}

func GetBytesFromNumber(n int) []byte {
	return []byte{
		byte(n >> 8),
		byte(n & 0xFF),
	}
}
