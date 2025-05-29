package utility

import (
	"mimuw_zps/src/encryption"
	"testing"
)

func createMessage(id ID) encryption.Message {
	extensions := []byte{0x00, 0x00, 0x00, 0x00}
	messageType := []byte{0x01}
	name := []byte("Skoda Fabia")
	//length = 11
	length := []byte{0x00, 0x0B}

	message := GenerateEmptyBuffor()
	message = append(message, id[:]...)
	message = append(message, messageType...)
	message = append(message, length...)
	message = append(message, extensions...)
	message = append(message, name...)

	return message
}

func equalID(id1 ID, id2 ID) bool {
	if len(id1) != len(id2) {
		return false
	}
	for i := range id1 {
		if id1[i] != id2[i] {
			return false
		}
	}
	return true
}

func TestCorrectData(t *testing.T) {
	ID := GenerateID()
	messageType := uint16(0x01)
	example := createMessage(ID)

	if messageType != GetMessageType(example) {
		t.Errorf("Expected Message Type %d, got: %d",
			messageType, GetMessageType(example))
	}

	if !equalID(ID, GetMessageID(example)) {
		t.Errorf("Expected ID %s, got: %s",
			ID, GetMessageID(example))
	}

	n := 2137
	bytes := GetBytesFromNumber(n)
	if GetNumberFromBytes(bytes) != 2137 {
		t.Errorf("Expected Number %d, got: %d",
			n, GetNumberFromBytes(bytes))
	}
}

func TestIncorrectData(t *testing.T) {
	ID := GenerateID()
	ID2 := GenerateID()
	messageType := uint16(0x0001)
	messageType2 := uint16(0x0002)
	example := createMessage(ID)

	if messageType2 == GetMessageType(example) {
		t.Errorf("Expected Message Type %d, got: %d",
			messageType, GetMessageType(example))
	}

	if equalID(ID2, GetMessageID(example)) {
		t.Errorf("Expected ID %s, got: %s",
			ID, GetMessageID(example))
	}
}
