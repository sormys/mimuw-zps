package packet_manager

import (
	"bytes"
	"errors"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/utility"
	"net"
	"testing"
	"time"
)

func TestWaiterCorrectMessage(t *testing.T) {
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
	retryPolicyFnLong := func() (time.Duration, error) { return 5 * timeout, nil }
	retryPolicyFnShort := func() (time.Duration, error) { return timeout, nil }
	callbackChanLong := make(chan networking.ReceivedMessageData, 1)
	callbackChanShort := make(chan networking.ReceivedMessageData, 1)
	sendReqLong := networking.SendRequest{Addr: recvAddr, Message: msgLong,
		MessRetryPolicy: RetryPolicyMock{retryPolicyFnLong}, CallbackChan: callbackChanLong}
	sendReqShort := networking.SendRequest{Addr: recvAddr, Message: msgShort,
		MessRetryPolicy: RetryPolicyMock{retryPolicyFnShort}, CallbackChan: callbackChanShort}
	// channels
	bufSize := 10
	senderChan := make(chan networking.SendRequest, bufSize)
	retryReqChan := make(chan networking.SendRequest, bufSize)
	receiverChannel := make(chan networking.ReceivedMessageData, bufSize)

	go WaiterWorker(senderChan, retryReqChan, receiverChannel)
	retryReqChan <- sendReqLong
	retryReqChan <- sendReqShort

	receivedShort := false
	for range 2 {
		select {
		case recvReq := <-senderChan:
			messId := utility.GetMessageID(recvReq.Message)
			if bytes.Equal(messId[:], idShort[:]) {
				receivedShort = true
				if !bytes.Equal(recvReq.Message, msgShort) {
					t.Errorf("Received message retry content does not match\nexpected: '%s'\ngot: '%s'",
						msgShort, recvReq.Message)
				}
			} else if bytes.Equal(messId[:], idLong[:]) {
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

func TestWaiterGetsReplyMessage(t *testing.T) {
	// mesage data
	recvAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 2137}
	messType := networking.HELLO
	data := []byte{0x00, 0x00, 0x00, 0x00}                 // extensions
	data = append(data, []byte("TestName")...)             // name
	data = append(data, []byte{0x00, 0x00, 0x00, 0x00}...) // signature
	id := utility.GenerateID()
	msg := createMessage(messType, data, len(data), id)
	// send request
	timeout := time.Millisecond * 200
	retryPolicyFnLong := func() (time.Duration, error) { return timeout, nil }
	callbackChan := make(chan networking.ReceivedMessageData, 1)
	sendReq := networking.SendRequest{Addr: recvAddr, Message: msg,
		MessRetryPolicy: RetryPolicyMock{retryPolicyFnLong}, CallbackChan: callbackChan}
	// reply data
	reply := networking.ReceivedMessageData{
		Addr:     recvAddr,
		ID:       id,
		MessType: networking.HELLO_REPLY,
		Length:   uint16(len(data)),
		Data:     data,
		Err:      nil,
	}
	// channels
	bufSize := 10
	senderChan := make(chan networking.SendRequest, bufSize)
	retryReqChan := make(chan networking.SendRequest, bufSize)
	receiverChannel := make(chan networking.ReceivedMessageData, bufSize)

	go WaiterWorker(senderChan, retryReqChan, receiverChannel)
	retryReqChan <- sendReq

	// Check if message was retried
	select {
	case recvReq := <-senderChan:
		messId := utility.GetMessageID(recvReq.Message)
		if !bytes.Equal(messId[:], id[:]) {
			t.Error("Recevied message with unknown id")
		}
		if recvReq.Addr != recvAddr {
			t.Errorf("Received message retry address does not match\nexpected: '%s'\ngot: '%s'",
				recvAddr, recvReq.Addr)
		}
		recvRetry, recvRetryErr := recvReq.MessRetryPolicy.NextRetry()
		sendRetry, sendRetryErr := sendReq.MessRetryPolicy.NextRetry()
		if recvRetry != sendRetry || recvRetryErr != sendRetryErr {
			t.Errorf("Received retry policy does not match\nexpected: '%v', '%v'\ngot: '%v', '%v'",
				sendRetry, sendRetryErr, recvRetry, recvRetryErr)
		}
		if !bytes.Equal(recvReq.Message, msg) {
			t.Errorf("Received message retry content does not match\nexpected: '%s'\ngot: '%s'", msg, recvReq.Message)
		}
	case <-time.After(timeout * 2):
		t.Errorf("No message was retried.")
	}

	// Check if message was retrieved
	retryReqChan <- sendReq
	receiverChannel <- reply
	select {
	case cbData := <-callbackChan:
		assertCorrectMessage(t, cbData, networking.HELLO_REPLY, data, len(data), id, recvAddr)
	case <-time.After(time.Second):
		t.Errorf("No reply has been received in callback.")
	}

	// Check if message is no longer retried
	select {
	case <-senderChan:
		t.Errorf("Message was retried after receiving a reply")
	case <-time.After(timeout * 2):
		// Success: no retry after reply
	}
}

func TestWaiterReplyPolicyErr(t *testing.T) {
	// mesage data
	recvAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 2137}
	messType := networking.HELLO
	data := []byte{0x00, 0x00, 0x00, 0x00}                 // extensions
	data = append(data, []byte("TestName")...)             // name
	data = append(data, []byte{0x00, 0x00, 0x00, 0x00}...) // signature
	id := utility.GenerateID()
	msg := createMessage(messType, data, len(data), id)
	// send request
	retryPolicyFnLong := func() (time.Duration, error) { return time.Nanosecond, errors.New("test no retry") }
	callbackChan := make(chan networking.ReceivedMessageData, 1)
	sendReq := networking.SendRequest{Addr: recvAddr, Message: msg,
		MessRetryPolicy: RetryPolicyMock{retryPolicyFnLong}, CallbackChan: callbackChan}
	// channels
	bufSize := 10
	senderChan := make(chan networking.SendRequest, bufSize)
	retryReqChan := make(chan networking.SendRequest, bufSize)
	receiverChannel := make(chan networking.ReceivedMessageData, bufSize)

	go WaiterWorker(senderChan, retryReqChan, receiverChannel)
	retryReqChan <- sendReq

	select {
	case cbData := <-callbackChan:
		if cbData.Err == nil {
			t.Error("Received reply without expected retry error")
		}
	case <-time.After(time.Second):
		t.Errorf("No reply has been received in callback.")
	}
}

func TestWaiterAwaitesAfterErr(t *testing.T) {
	// mesage data
	recvAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 2137}
	messType := networking.HELLO
	data := []byte{0x00, 0x00, 0x00, 0x00}                 // extensions
	data = append(data, []byte("TestName")...)             // name
	data = append(data, []byte{0x00, 0x00, 0x00, 0x00}...) // signature
	id := utility.GenerateID()
	msg := createMessage(messType, data, len(data), id)
	// send request
	retryPolicyFnLong := func() (time.Duration, error) { return time.Second, errors.New("test no retry") }
	callbackChan := make(chan networking.ReceivedMessageData, 1)
	sendReq := networking.SendRequest{Addr: recvAddr, Message: msg,
		MessRetryPolicy: RetryPolicyMock{retryPolicyFnLong}, CallbackChan: callbackChan}
	// reply data
	reply := networking.ReceivedMessageData{
		Addr:     recvAddr,
		ID:       id,
		MessType: networking.HELLO_REPLY,
		Length:   uint16(len(data)),
		Data:     data,
		Err:      nil,
	}
	// channels
	bufSize := 10
	senderChan := make(chan networking.SendRequest, bufSize)
	retryReqChan := make(chan networking.SendRequest, bufSize)
	receiverChannel := make(chan networking.ReceivedMessageData, bufSize)

	go WaiterWorker(senderChan, retryReqChan, receiverChannel)
	retryReqChan <- sendReq
	receiverChannel <- reply

	select {
	case cbData := <-callbackChan:
		assertCorrectMessage(t, cbData, reply.MessType, reply.Data, int(reply.Length), reply.ID, reply.Addr)
	case <-time.After(time.Second):
		t.Errorf("No reply has been received in callback.")
	}
}

func TestWaiterHandleEarlyReply(t *testing.T) {
	// mesage data
	recvAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 2137}
	messType := networking.HELLO
	data := []byte{0x00, 0x00, 0x00, 0x00}                 // extensions
	data = append(data, []byte("TestName")...)             // name
	data = append(data, []byte{0x00, 0x00, 0x00, 0x00}...) // signature
	id := utility.GenerateID()
	msg := createMessage(messType, data, len(data), id)
	// send request
	retryPolicyFnLong := func() (time.Duration, error) { return time.Second, errors.New("test no retry") }
	callbackChan := make(chan networking.ReceivedMessageData, 1)
	sendReq := networking.SendRequest{Addr: recvAddr, Message: msg,
		MessRetryPolicy: RetryPolicyMock{retryPolicyFnLong}, CallbackChan: callbackChan}
	// reply data
	reply := networking.ReceivedMessageData{
		Addr:     recvAddr,
		ID:       id,
		MessType: networking.HELLO_REPLY,
		Length:   uint16(len(data)),
		Data:     data,
		Err:      nil,
	}
	// channels
	bufSize := 10
	senderChan := make(chan networking.SendRequest, bufSize)
	retryReqChan := make(chan networking.SendRequest, bufSize)
	receiverChannel := make(chan networking.ReceivedMessageData, bufSize)

	go WaiterWorker(senderChan, retryReqChan, receiverChannel)
	// Reply comes before the request
	receiverChannel <- reply
	retryReqChan <- sendReq

	select {
	case cbData := <-callbackChan:
		assertCorrectMessage(t, cbData, reply.MessType, reply.Data, int(reply.Length), reply.ID, reply.Addr)
	case <-time.After(time.Second):
		t.Errorf("No reply has been received in callback.")
	}
}

func TestWaiterIgnoresEmptyRetry(t *testing.T) {
	// mesage data
	recvAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 2137}
	messType := networking.HELLO
	data := []byte{0x00, 0x00, 0x00, 0x00}                 // extensions
	data = append(data, []byte("TestName")...)             // name
	data = append(data, []byte{0x00, 0x00, 0x00, 0x00}...) // signature
	id := utility.GenerateID()
	msg := createMessage(messType, data, len(data), id)
	// send request
	sendReq := networking.SendRequest{Addr: recvAddr, Message: msg,
		MessRetryPolicy: nil, CallbackChan: nil}
	// channels
	bufSize := 10
	senderChan := make(chan networking.SendRequest, bufSize)
	retryReqChan := make(chan networking.SendRequest, bufSize)
	receiverChannel := make(chan networking.ReceivedMessageData, bufSize)

	go WaiterWorker(senderChan, retryReqChan, receiverChannel)
	// Reply comes before the request
	retryReqChan <- sendReq

	select {
	case <-senderChan:
		t.Errorf("Nothing should be sent, as there is no retry policy")
	case <-time.After(time.Millisecond * 200):
	}
}
