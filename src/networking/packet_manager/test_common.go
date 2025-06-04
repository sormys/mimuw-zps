package packet_manager

import (
	"bytes"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/utility"
	"net"
	"testing"
	"time"
)

type RetryPolicyMock struct {
	retryFn func() (time.Duration, error)
}

func (rp RetryPolicyMock) NextRetry() (time.Duration, error) {
	return rp.retryFn()
}

func createMessage(typeMessage networking.MessageType, data []byte, length int, id utility.ID) []byte {
	typeID := uint8(0x00)
	lengthBytes := utility.GetBytesFromNumber(length)
	for v, k := range networking.TypeMap {
		if k == typeMessage {
			typeID = v
			break
		}
	}

	message := make([]byte, 0)
	message = append(message, id[:]...)
	message = append(message, byte(typeID))
	message = append(message, lengthBytes...)
	message = append(message, data...)

	return message
}

func assertCorrectMessage(t *testing.T, message networking.ReceivedMessageData,
	typeMessage networking.MessageType, data []byte, length int, id utility.ID, addr net.Addr) {
	if message.ID != id {
		t.Errorf("Received message id does not match\nexpected: '%s'\ngot: '%s'", id, message.ID)
	}
	if message.Addr.String() != addr.String() {
		t.Errorf("Received message sender does not match \nexpected: '%s'\ngot: '%s'", addr, message.Addr)
	}
	if message.Err != nil {
		t.Errorf("Received error when message arrived properly\nexpected: nil\ngot: '%s'", message.Err)
	}
	if message.MessType != typeMessage {
		t.Errorf("Received wrong message type\nexpected: '%s'\ngot: '%s'", typeMessage, message.MessType)
	}
	if !utility.EqualIntUint16(len(data), message.Length) {
		t.Errorf("Received wrong message length\nexpected: %d\ngot:%d", len(data), message.Length)
	}
	if !bytes.Equal(message.Data, data) {
		t.Errorf("Received wrong message conent\nexpected: '%s'\ngot: '%s'", data, message.Data)
	}
	if message.Length != uint16(length) {
		t.Errorf("Received message length does not match expected length\nexpected: %d\ngot: %d", length, message.Length)
	}
}
