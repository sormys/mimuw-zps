package packet_manager

import (
	"bytes"
	"errors"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/utility"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
)

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

type mockRecvUDPConn struct {
	mock.Mock
}

func (m *mockRecvUDPConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	args := m.Called(buf)
	copy(buf, []byte(args.String(0)))
	return args.Int(1), args.Get(2).(net.Addr), args.Error(3)
}

func (m *mockRecvUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) { return 0, nil }
func (m *mockRecvUDPConn) Close() error                                 { return nil }
func (m *mockRecvUDPConn) LocalAddr() net.Addr                          { return &net.UDPAddr{} }
func (m *mockRecvUDPConn) SetDeadline(t time.Time) error                { return nil }
func (m *mockRecvUDPConn) SetReadDeadline(t time.Time) error            { return nil }
func (m *mockRecvUDPConn) SetWriteDeadline(t time.Time) error           { return nil }

// ========================= Receiver.Receiver =========================

func TestReceiverCorrectMessages(t *testing.T) {
	// mesage data
	senderAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 2137}
	messType := networking.HELLO_REPLY
	data := []byte{0x00, 0x00, 0x00, 0x00}                 // extensions
	data = append(data, []byte("TestName")...)             // name
	data = append(data, []byte{0x00, 0x00, 0x00, 0x00}...) // signature
	id := utility.GenerateID()
	msg := createMessage(messType, data, len(data), id)

	// Mock objects
	fakeChannel := make(chan *networking.ReceivedMessageData)
	mockUDPConn := new(mockRecvUDPConn)
	mockUDPConn.On("ReadFrom", mock.Anything).Return(string(msg), len([]byte(msg)), senderAddr, nil)

	go Receiver(mockUDPConn, fakeChannel)

	for range 10 {
		select {
		case message := <-fakeChannel:
			if message.ID != id {
				t.Errorf("Received message id does not match\nexpected: '%s'\ngot: '%s'", id, message.ID)
			}
			if message.Addr.String() != senderAddr.String() {
				t.Errorf("Received message sender does not match \nexpected: '%s'\ngot: '%s'", senderAddr, message.Addr)
			}
			if message.Err != nil {
				t.Errorf("Received error when message arrived properly\nexpected: nil\ngot: '%s'", message.Err)
			}
			if message.MessType != messType {
				t.Errorf("Received wrong message type\nexpected: '%s'\ngot: '%s'", messType, message.MessType)
			}
			if !utility.EqualIntUint16(len(data), message.Length) {
				t.Errorf("Received wrong message length\nexpected: %d\ngot:%d", len(data), message.Length)
			}
			if !bytes.Equal(message.Data, data) {
				t.Errorf("Received wrong message conent\nexpected: '%s'\ngot: '%s'", data, message.Data)
			}
		case <-time.After(time.Second):
			t.Error("No message received.")
		}
	}
	mockUDPConn.AssertExpectations(t)
}

func TestReceiverIncorrectLenMessages(t *testing.T) {
	// mesage data
	senderAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 2137}
	messType := networking.HELLO_REPLY
	data := []byte{0x00, 0x00, 0x00, 0x00}                 // extensions
	data = append(data, []byte("TestName")...)             // name
	data = append(data, []byte{0x00, 0x00, 0x00, 0x00}...) // signature
	id := utility.GenerateID()
	msg := createMessage(messType, data, len(data)-2, id) // message with incrrect len

	// Mock objects
	fakeChannel := make(chan *networking.ReceivedMessageData)
	mockUDPConn := new(mockRecvUDPConn)
	mockUDPConn.On("ReadFrom", mock.Anything).Return(string(msg), len([]byte(msg)), senderAddr, nil)

	go Receiver(mockUDPConn, fakeChannel)

	for range 10 {
		select {
		case message := <-fakeChannel:
			if message.Err == nil {
				t.Errorf("No error received on message of incorrect length")
			}
		case <-time.After(time.Second):
			t.Error("No message received.")
		}
	}
	mockUDPConn.AssertExpectations(t)
}

func TestReceiverIngoresReadErrMessages(t *testing.T) {
	// mesage data
	senderAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 2137}
	messType := networking.HELLO_REPLY
	data := []byte{0x00, 0x00, 0x00, 0x00}                 // extensions
	data = append(data, []byte("TestName")...)             // name
	data = append(data, []byte{0x00, 0x00, 0x00, 0x00}...) // signature
	id := utility.GenerateID()
	msg := createMessage(messType, data, len(data), id)

	// Mock objects
	fakeChannel := make(chan *networking.ReceivedMessageData)
	mockUDPConn := new(mockRecvUDPConn)
	mockUDPConn.On("ReadFrom", mock.Anything).Return("", 0, senderAddr, errors.New("FakeError")).Once()
	mockUDPConn.On("ReadFrom", mock.Anything).Return(string(msg), len([]byte(msg)), senderAddr, nil)

	go Receiver(mockUDPConn, fakeChannel)

	select {
	case message := <-fakeChannel:
		if message.Err != nil {
			t.Errorf("Received error on correct message")
		}
	case <-time.After(time.Second):
		t.Error("No message received.")
	}
	mockUDPConn.AssertExpectations(t)
}

func TestReceiverAwaitsMessages(t *testing.T) {
	// mesage data
	senderAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 2137}
	messType := networking.HELLO_REPLY
	data := []byte{0x00, 0x00, 0x00, 0x00}                 // extensions
	data = append(data, []byte("TestName")...)             // name
	data = append(data, []byte{0x00, 0x00, 0x00, 0x00}...) // signature
	id := utility.GenerateID()
	msg := createMessage(messType, data, len(data), id)
	timeout := time.Millisecond * 10

	// Mock objects
	fakeChannel := make(chan *networking.ReceivedMessageData)
	mockUDPConn := new(mockRecvUDPConn)
	mockUDPConn.On(
		"ReadFrom", mock.Anything).Return(
		string(msg), len([]byte(msg)), senderAddr, nil).WaitUntil(
		time.After(2 * timeout))

	go Receiver(mockUDPConn, fakeChannel)

	select {
	case <-fakeChannel:
		t.Errorf("Message data received when no message appeared")
	case <-time.After(timeout):
		break
	}

	select {
	case message := <-fakeChannel:
		if message.ID != id {
			t.Errorf("Received message id does not match\nexpected: '%s'\ngot: '%s'", id, message.ID)
		}
		if message.Addr.String() != senderAddr.String() {
			t.Errorf("Received message sender does not match \nexpected: '%s'\ngot: '%s'", senderAddr, message.Addr)
		}
		if message.Err != nil {
			t.Errorf("Received error when message arrived properly\nexpected: nil\ngot: '%s'", message.Err)
		}
		if message.MessType != messType {
			t.Errorf("Received wrong message type\nexpected: '%s'\ngot: '%s'", messType, message.MessType)
		}
		if !utility.EqualIntUint16(len(data), message.Length) {
			t.Errorf("Received wrong message length\nexpected: %d\ngot:%d", len(data), message.Length)
		}
		if !bytes.Equal(message.Data, data) {
			t.Errorf("Received wrong message conent\nexpected: '%s'\ngot: '%s'", data, message.Data)
		}
	case <-time.After(2 * timeout):
		t.Error("No message received.")
	}
	mockUDPConn.AssertExpectations(t)
}
