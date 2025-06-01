package packet_manager

import (
	"bytes"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/utility"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
)

func createMessage(typeMessage networking.MessageType, data []byte, id utility.ID) []byte {
	typeID := uint8(0x00)
	length := utility.GetBytesFromNumber(len(data))
	for v, k := range networking.TypeMap {
		if k == typeMessage {
			typeID = v
			break
		}
	}

	message := make([]byte, 0)
	message = append(message, id[:]...)
	message = append(message, byte(typeID))
	message = append(message, length...)
	message = append(message, data...)

	return message
}

type mockUDPConn struct {
	mock.Mock
}

func (m *mockUDPConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	args := m.Called(buf)
	copy(buf, []byte(args.String(0)))
	return args.Int(1), &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 2138}, args.Error(3)
}

func (m *mockUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) { return 0, nil }
func (m *mockUDPConn) Close() error                                 { return nil }
func (m *mockUDPConn) LocalAddr() net.Addr                          { return &net.UDPAddr{} }
func (m *mockUDPConn) SetDeadline(t time.Time) error                { return nil }
func (m *mockUDPConn) SetReadDeadline(t time.Time) error            { return nil }
func (m *mockUDPConn) SetWriteDeadline(t time.Time) error           { return nil }

// ========================= Receiver.Receiver =========================
func TestCorrectHello(t *testing.T) {
	fakeChannel := make(chan *networking.ReceivedMessageData)
	mockUDPConn := new(mockUDPConn)
	senderAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 2138}
	messType := networking.HELLO_REPLY
	data := []byte{0x00, 0x00, 0x00, 0x00}                 // extensions
	data = append(data, []byte("TestName")...)             // name
	data = append(data, []byte{0x00, 0x00, 0x00, 0x00}...) // signature
	id := utility.GenerateID()
	msg := createMessage(messType, data, id)
	mockUDPConn.On("ReadFrom", mock.Anything).Return(string(msg), len([]byte(msg)), senderAddr, nil)

	go Receiver(mockUDPConn, fakeChannel)

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
	case <-time.After(1 * time.Second):
		t.Error("No message received.")
	}
}

func TestCorrectMultipleMessages(t *testing.T) {
	fakeChannel := make(chan *networking.ReceivedMessageData)
	mockUDPConn := new(mockUDPConn)
	senderAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 2138}
	messType := networking.HELLO_REPLY
	data := []byte{0x00, 0x00, 0x00, 0x00}                 // extensions
	data = append(data, []byte("TestName")...)             // name
	data = append(data, []byte{0x00, 0x00, 0x00, 0x00}...) // signature
	id := utility.GenerateID()
	msg := createMessage(messType, data, id)
	mockUDPConn.On("ReadFrom", mock.Anything).Return(string(msg), len([]byte(msg)), senderAddr, nil)

	go Receiver(mockUDPConn, fakeChannel)

	for range 100 {
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
		case <-time.After(1 * time.Second):
			t.Error("No message received.")
		}

	}
}
