package packet_manager

import (
	"bytes"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/utility"
	"net"
	"testing"
	"time"
)

func TestWriterCorrectMessage(t *testing.T) {
	// mesage data
	recvAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 2137}
	messType := networking.HELLO
	data := []byte{0x00, 0x00, 0x00, 0x00}                 // extensions
	data = append(data, []byte("TestName")...)             // name
	data = append(data, []byte{0x00, 0x00, 0x00, 0x00}...) // signature
	idShort := utility.GenerateID()
	idLong := utility.GenerateID()
	msgShort := createMessage(messType, data, len(data), idShort)
	msgLong := createMessage(messType, data, len(data), idLong)
	// send request
	timeout := time.Millisecond * 100
	retryPolicyFnLong := func() (time.Duration, error) { return 10 * timeout, nil }
	retryPolicyFnShort := func() (time.Duration, error) { return timeout, nil }
	callbackChanLong := make(chan networking.ReceivedMessageData)
	callbackChanShort := make(chan networking.ReceivedMessageData)
	sendReqLong := networking.SendRequest{Addr: recvAddr, Message: msgLong,
		MessRetryPolicy: RetryPolicyMock{retryPolicyFnLong}, CallbackChan: callbackChanLong}
	sendReqShort := networking.SendRequest{Addr: recvAddr, Message: msgShort,
		MessRetryPolicy: RetryPolicyMock{retryPolicyFnShort}, CallbackChan: callbackChanShort}
	// channels
	senderChan := make(chan networking.SendRequest)
	retryReqChan := make(chan networking.SendRequest)
	receiverChannel := make(chan networking.ReceivedMessageData)

	go Writer(senderChan, retryReqChan, receiverChannel)
	retryReqChan <- sendReqLong
	retryReqChan <- sendReqShort

	receivedShort := false
	for range 2 {
		select {
		case recvReq := <-senderChan:
			if utility.GetMessageID(recvReq.Message) == idShort {
				receivedShort = true
				if !bytes.Equal(recvReq.Message, msgShort) {
					t.Errorf("Received message retry content does not match\nexpected: '%s'\ngot: '%s'",
						msgShort, recvReq.Message)
				}
			} else if utility.GetMessageID(recvReq.Message) == idLong {
				if !receivedShort {
					t.Errorf("Long timeout retry was retried before the short ones")
				}
				if !bytes.Equal(recvReq.Message, msgLong) {
					t.Errorf("Received message retry content does not match\nexpected: '%s'\ngot: '%s'",
						msgLong, recvReq.Message)
				}
			} else {
				t.Error("Recevied message with unknown id")
			}

			if recvReq.Addr != recvAddr {
				t.Errorf("Received message retry address does not match\nexpected: '%s'\ngot: '%s'",
					recvAddr, recvReq.Addr)
			}
		case <-time.After(time.Second):
			t.Errorf("No message was retried.")
		}
	}
}
