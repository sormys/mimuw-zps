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
	sendRequest(request PacketSendRequest) networking.ReceivedMessageData // blocking
	sendReply(request PacketSendRequest) error                            // non-blocking
	recvRequest() networking.ReceivedMessageData                          // blocking
}

type packetConn struct {
	senderChan  chan<- networking.SendRequest
	requestChan <-chan networking.ReceivedMessageData
}

func (pc packetConn) sendRequest(request PacketSendRequest) networking.ReceivedMessageData {
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

func (pc packetConn) sendReply(request PacketSendRequest) error {
	sendRequest := networking.SendRequest{
		Addr:            request.Addr,
		Message:         request.Message,
		MessRetryPolicy: request.MessRetryPolicy,
		CallbackChan:    nil,
	}
	select {
	case pc.senderChan <- sendRequest:
	default:
		return errors.New("system overloaded, could not send reply. Try again later")
	}
	return nil
}

func (pc packetConn) recvRequest() networking.ReceivedMessageData {
	request := <-pc.requestChan
	return request
}

func StartPacketManager(addr net.Addr, senderCount uint32, waiterCount uint32, receiverCount uint32) (PacketConn, error) {
	senderChan := make(chan networking.SendRequest)
	waiterChan := make(chan networking.SendRequest)
	receiverReplyChan := make(chan networking.ReceivedMessageData)
	receiverRequestChan := make(chan networking.ReceivedMessageData)
	conn, err := net.ListenPacket("udp4", addr.String())
	if err != nil {
		return packetConn{}, err
	}
	go Sender(conn, senderChan, waiterChan, senderCount)
	go Waiter(senderChan, waiterChan, receiverReplyChan, waiterCount)
	go Receiver(conn, receiverReplyChan, receiverRequestChan, receiverCount)
	return packetConn{senderChan: senderChan, requestChan: receiverRequestChan}, nil
}
