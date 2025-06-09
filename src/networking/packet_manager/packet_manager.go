package packet_manager

import (
	"errors"
	"log/slog"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/networking"
	"net"
)

type PacketSendRequest struct {
	Addr            net.Addr
	Message         encryption.Message
	MessRetryPolicy networking.RetryPolicy
}

type PacketConn interface {
	SendRequest(request PacketSendRequest) networking.ReceivedMessageData // blocking
	SendReply(request PacketSendRequest) error                            // non-blocking
	RecvRequest() networking.ReceivedMessageData                          // blocking
}

type packetConn struct {
	senderChan  chan<- networking.SendRequest
	requestChan <-chan networking.ReceivedMessageData
}

// Sends message request.Message to request.Addr and awaits a reply. Retrying on
// no reply is done according to request.MessRetryPolicy. If the retry policy
// does not return an error, the retries will continue after the specified time.
// Otherwise method will wait for the specified time for the last time and no
// further replies will occur. The request.MessRetryPolicy cannot be nil.
//
// Return: networking.ReceivedMessageData with received data in reply or error,
// when problem with reply validation occured, retry limit was reached without
// receiving a reply or when system is overloaded.
func (pc packetConn) SendRequest(request PacketSendRequest) networking.ReceivedMessageData {
	if request.MessRetryPolicy == nil {
		return networking.ReceivedMessageData{Err: errors.New("retry policy cannot be nil")}
	}

	callbackChan := make(chan networking.ReceivedMessageData, 1)
	sendRequest := networking.SendRequest{
		Addr:            request.Addr,
		Message:         request.Message,
		MessRetryPolicy: request.MessRetryPolicy,
		CallbackChan:    callbackChan,
	}
	select {
	case pc.senderChan <- sendRequest:
	default:
		return networking.ReceivedMessageData{
			Err: errors.New("system overloaded, could not send request. Try again later")}
	}
	slog.Debug("Sent request, awaiting reply", "addr", request.Addr.String())
	recvData := <-callbackChan
	return recvData
}

// Sends message request.Message to request.Addr but does not await a reply.
// Request.MessRetryPolicy will be ignored.

// Returns: error when system is overloaded and cannot handle any more requests.
func (pc packetConn) SendReply(request PacketSendRequest) error {
	sendRequest := networking.SendRequest{
		Addr:            request.Addr,
		Message:         request.Message,
		MessRetryPolicy: nil,
		CallbackChan:    nil,
	}
	select {
	case pc.senderChan <- sendRequest:
	default:
		return errors.New("system overloaded, could not send reply. Try again later")
	}
	return nil
}

// Function awaits any incoming request.
//
// Returns: networking.ReceivedMessageData with initialy validated data of the request
func (pc packetConn) RecvRequest() networking.ReceivedMessageData {
	request := <-pc.requestChan
	return request
}

// Starts packet manager with provieded number of workers (goroutines) handling
// sending/awaiting/receiving messages.
//
// Returns: PacketConn for sending and receiving messages
// error when system failed to start
func StartPacketManager(addr net.Addr, senderCount uint32, waiterCount uint32, receiverCount uint32) (PacketConn, error) {
	senderChan := make(chan networking.SendRequest, networking.MAIN_CHAN_BUF_SIZE)
	waiterChan := make(chan networking.SendRequest, networking.MAIN_CHAN_BUF_SIZE)
	receiverReplyChan := make(chan networking.ReceivedMessageData, networking.MAIN_CHAN_BUF_SIZE)
	receiverRequestChan := make(chan networking.ReceivedMessageData, networking.MAIN_CHAN_BUF_SIZE)
	conn, err := net.ListenPacket("udp", addr.String())
	if err != nil {
		return packetConn{}, err
	}
	go Sender(conn, senderChan, waiterChan, senderCount)
	go Waiter(senderChan, waiterChan, receiverReplyChan, waiterCount)
	go Receiver(conn, receiverReplyChan, receiverRequestChan, receiverCount)
	return packetConn{senderChan: senderChan, requestChan: receiverRequestChan}, nil
}
