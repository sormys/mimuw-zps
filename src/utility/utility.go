package utility

import (
	"bytes"
	"crypto/rand"
	"log/slog"
)

type ID = [4]byte

const MAX_ID = uint32(0xFFFFFFFF)

// return ID from messsage
func GetMessageID(data []byte) ID {
	var id ID
	copy(id[:], data[:4])
	return id
}

func ConvertIDToUint(id ID) uint32 {
	return uint32(id[0])<<24 | uint32(id[1])<<16 | uint32(id[2])<<8 | uint32(id[3])
}

// return Type message from messsage
func GetMessageType(data []byte) uint8 {
	return uint8(data[4])
}

// Converts a byte slice (up to 2 bytes) to a uint
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

// Converts uint16 to 2 bytes
func GetBytesFromNumber(n int) []byte {
	return []byte{
		byte(n >> 8),
		byte(n & 0xFF),
	}
}

// Checks whether given ID consists of zero bytes
func IsIDEmpty(id ID) bool {
	IDEmpty := ID{}
	return bytes.Equal(id[:], IDEmpty[:])
}

// Check if value stored in int is equal to value stored in uint16.
// Helpful when using len() and comparing to uint16 length value from message
func EqualIntUint16(valInt int, valUint16 uint16) bool {
	if valInt < 0 {
		return false
	}
	if valInt > 0xFFFF {
		return false
	}
	convertedValue := uint16(valInt)
	return convertedValue == valUint16
}
