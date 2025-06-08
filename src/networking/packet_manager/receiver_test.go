package packet_manager

import (
	"errors"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/utility"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
)

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
	replyChan := make(chan networking.ReceivedMessageData)
	requestChan := make(chan networking.ReceivedMessageData)
	mockUDPConn := new(mockRecvUDPConn)
	mockUDPConn.On("ReadFrom", mock.Anything).Return(string(msg), len([]byte(msg)), senderAddr, nil)

	go ReceiverWorker(mockUDPConn, replyChan, requestChan)

	for range 10 {
		select {
		case message := <-replyChan:
			assertCorrectMessage(t, message, messType, data, len(data), id, senderAddr)
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
	replyChan := make(chan networking.ReceivedMessageData)
	requestChan := make(chan networking.ReceivedMessageData)
	mockUDPConn := new(mockRecvUDPConn)
	mockUDPConn.On("ReadFrom", mock.Anything).Return(string(msg), len([]byte(msg)), senderAddr, nil)

	go ReceiverWorker(mockUDPConn, replyChan, requestChan)

	for range 10 {
		select {
		case message := <-replyChan:
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
	replyChan := make(chan networking.ReceivedMessageData)
	requestChan := make(chan networking.ReceivedMessageData)
	mockUDPConn := new(mockRecvUDPConn)
	mockUDPConn.On("ReadFrom", mock.Anything).Return("", 0, senderAddr, errors.New("FakeError")).Once()
	mockUDPConn.On("ReadFrom", mock.Anything).Return(string(msg), len([]byte(msg)), senderAddr, nil)

	go ReceiverWorker(mockUDPConn, replyChan, requestChan)

	select {
	case message := <-replyChan:
		assertCorrectMessage(t, message, messType, data, len(data), id, senderAddr)
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
	replyChan := make(chan networking.ReceivedMessageData)
	requestChan := make(chan networking.ReceivedMessageData)
	mockUDPConn := new(mockRecvUDPConn)
	mockUDPConn.On(
		"ReadFrom", mock.Anything).Return(
		string(msg), len([]byte(msg)), senderAddr, nil).WaitUntil(
		time.After(2 * timeout))

	go ReceiverWorker(mockUDPConn, replyChan, requestChan)

	select {
	case <-replyChan:
		t.Errorf("Message data received when no message appeared")
	case <-time.After(timeout):
		break
	}

	select {
	case message := <-replyChan:
		assertCorrectMessage(t, message, messType, data, len(data), id, senderAddr)
	case <-time.After(2 * timeout):
		t.Error("No message received.")
	}
	mockUDPConn.AssertExpectations(t)
}

func TestReceiverForwardsRequestsMessages(t *testing.T) {
	// mesage data
	senderAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 2137}
	messType := networking.HELLO
	data := []byte{0x00, 0x00, 0x00, 0x00}                 // extensions
	data = append(data, []byte("TestName")...)             // name
	data = append(data, []byte{0x00, 0x00, 0x00, 0x00}...) // signature
	id := utility.GenerateID()
	msg := createMessage(messType, data, len(data), id)

	// Mock objects
	replyChan := make(chan networking.ReceivedMessageData)
	requestChan := make(chan networking.ReceivedMessageData)
	mockUDPConn := new(mockRecvUDPConn)
	mockUDPConn.On(
		"ReadFrom", mock.Anything).Return(
		string(msg), len([]byte(msg)), senderAddr, nil)

	go ReceiverWorker(mockUDPConn, replyChan, requestChan)

	select {
	case message := <-requestChan:
		assertCorrectMessage(t, message, messType, data, len(data), id, senderAddr)
	case <-time.After(time.Millisecond * 200):
		t.Error("No message received.")
	}
	mockUDPConn.AssertExpectations(t)
}
