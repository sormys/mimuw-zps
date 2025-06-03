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

type mockSendUDPConn struct {
	mock.Mock
}

func (m *mockSendUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	args := m.Called(b, addr)
	bytes.Equal(b, args.Get(0).([]byte))
	return args.Int(1), args.Error(2)
}

func (m *mockSendUDPConn) ReadFrom(buf []byte) (int, net.Addr, error) { return 0, nil, nil }
func (m *mockSendUDPConn) Close() error                               { return nil }
func (m *mockSendUDPConn) LocalAddr() net.Addr                        { return &net.UDPAddr{} }
func (m *mockSendUDPConn) SetDeadline(t time.Time) error              { return nil }
func (m *mockSendUDPConn) SetReadDeadline(t time.Time) error          { return nil }
func (m *mockSendUDPConn) SetWriteDeadline(t time.Time) error         { return nil }

func TestSenderCorrectMessage(t *testing.T) {
	// mesage data
	recvAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 2137}
	messType := networking.HELLO
	data := []byte{0x00, 0x00, 0x00, 0x00}                 // extensions
	data = append(data, []byte("TestName")...)             // name
	data = append(data, []byte{0x00, 0x00, 0x00, 0x00}...) // signature
	id := utility.GenerateID()
	msg := createMessage(messType, data, len(data), id)
	// send request
	retryPolicyFn := func() (time.Duration, error) { return time.Hour, nil }
	retryPolicy := RetryPolicyMock{retryPolicyFn}
	callbackChan := make(chan networking.ReceivedMessageData)
	sendReq := networking.SendRequest{Addr: recvAddr, Message: msg,
		MessRetryPolicy: retryPolicy, CallbackChan: callbackChan}

	// Mock objects
	reqChannel := make(chan networking.SendRequest)
	waiterChannel := make(chan networking.SendRequest)
	mockUDPConn := new(mockSendUDPConn)
	mockUDPConn.On("WriteTo", mock.Anything, recvAddr).Return(
		[]byte(sendReq.Message), len(sendReq.Message), nil).Once()

	go SenderWorker(mockUDPConn, reqChannel, waiterChannel)
	reqChannel <- sendReq

	select {
	case recvReq := <-waiterChannel:
		if !bytes.Equal(recvReq.Message, sendReq.Message) {
			t.Errorf("Received message retry content does not match\nexpected: '%s'\ngot: '%s'",
				sendReq.Message, recvReq.Message)
		}
		if recvReq.Addr != sendReq.Addr {
			t.Errorf("Received message retry address does not match\nexpected: '%s'\ngot: '%s'",
				sendReq.Addr, recvReq.Addr)
		}
		recvRetry, recvRetryErr := recvReq.MessRetryPolicy.NextRetry()
		sendRetry, sendRetryErr := sendReq.MessRetryPolicy.NextRetry()
		if recvRetry != sendRetry || recvRetryErr != sendRetryErr {
			t.Errorf("Received retry policy does not match\nexpected: '%v', '%v'\ngot: '%v', '%v'",
				sendRetry, sendRetryErr, recvRetry, recvRetryErr)
		}
	case <-time.After(time.Second):
		t.Error("No message retry queued.")
	}
	mockUDPConn.AssertExpectations(t)
}

func TestSenderFailedToSend(t *testing.T) {
	// mesage data
	recvAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 2137}
	messType := networking.HELLO
	data := []byte{0x00, 0x00, 0x00, 0x00}                 // extensions
	data = append(data, []byte("TestName")...)             // name
	data = append(data, []byte{0x00, 0x00, 0x00, 0x00}...) // signature
	id := utility.GenerateID()
	msg := createMessage(messType, data, len(data), id)
	// send request
	retryPolicyFn := func() (time.Duration, error) { return time.Hour, nil }
	retryPolicy := RetryPolicyMock{retryPolicyFn}
	callbackChan := make(chan networking.ReceivedMessageData)
	sendReq := networking.SendRequest{Addr: recvAddr, Message: msg,
		MessRetryPolicy: retryPolicy, CallbackChan: callbackChan}
	err := errors.New("Fake send error")

	// Mock objects
	reqChannel := make(chan networking.SendRequest)
	waiterChannel := make(chan networking.SendRequest)
	mockUDPConn := new(mockSendUDPConn)
	mockUDPConn.On("WriteTo", mock.Anything, recvAddr).Return(
		[]byte(sendReq.Message), 0, err).Once()

	go SenderWorker(mockUDPConn, reqChannel, waiterChannel)
	reqChannel <- sendReq

	select {
	case <-waiterChannel:
		t.Error("Received retry request when request failed")
	case message := <-callbackChan:
		if message.Err != err {
			t.Errorf("Expected error: %v, got: %v", err, message.Err)
		}
	case <-time.After(time.Second):
		t.Error("Error was not propagated to callback channel of the request.")
	}
	mockUDPConn.AssertExpectations(t)
}

func TestSenderAwaitsMessages(t *testing.T) {
	// mesage data
	recvAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 2137}
	messType := networking.HELLO
	data := []byte{0x00, 0x00, 0x00, 0x00}                 // extensions
	data = append(data, []byte("TestName")...)             // name
	data = append(data, []byte{0x00, 0x00, 0x00, 0x00}...) // signature
	id := utility.GenerateID()
	msg := createMessage(messType, data, len(data), id)
	timeout := time.Millisecond * 10

	// send request
	retryPolicyFn := func() (time.Duration, error) { return time.Hour, nil }
	retryPolicy := RetryPolicyMock{retryPolicyFn}
	callbackChan := make(chan networking.ReceivedMessageData)
	sendReq := networking.SendRequest{Addr: recvAddr, Message: msg,
		MessRetryPolicy: retryPolicy, CallbackChan: callbackChan}

	// Mock objects
	reqChannel := make(chan networking.SendRequest)
	waiterChannel := make(chan networking.SendRequest)
	mockUDPConn := new(mockSendUDPConn)
	mockUDPConn.On("WriteTo", mock.Anything, recvAddr).Return(
		[]byte(sendReq.Message), len(sendReq.Message), nil).Once().WaitUntil(
		time.After(2 * timeout))

	go SenderWorker(mockUDPConn, reqChannel, waiterChannel)
	reqChannel <- sendReq

	select {
	case <-waiterChannel:
		t.Errorf("Retry request received before correctly sending packet")
	case <-time.After(timeout):
		break
	}

	select {
	case recvReq := <-waiterChannel:
		if !bytes.Equal(recvReq.Message, sendReq.Message) {
			t.Errorf("Received message retry content does not match\nexpected: '%s'\ngot: '%s'",
				sendReq.Message, recvReq.Message)
		}
		if recvReq.Addr != sendReq.Addr {
			t.Errorf("Received message retry address does not match\nexpected: '%s'\ngot: '%s'",
				sendReq.Addr, recvReq.Addr)
		}
		recvRetry, recvRetryErr := recvReq.MessRetryPolicy.NextRetry()
		sendRetry, sendRetryErr := sendReq.MessRetryPolicy.NextRetry()
		if recvRetry != sendRetry || recvRetryErr != sendRetryErr {
			t.Errorf("Received retry policy does not match\nexpected: '%v', '%v'\ngot: '%v', '%v'",
				sendRetry, sendRetryErr, recvRetry, recvRetryErr)
		}
	case <-time.After(2 * timeout):
		t.Error("No message retry queued.")
	}
	mockUDPConn.AssertExpectations(t)
}
