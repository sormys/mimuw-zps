package packet_manager

import (
	"log/slog"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/utility"
	"net"
)

const BUF_SIZE = 2048

// Receives a message (sigle UDP packet) and sends received initialy validated
// data to waiter via replyChan or requestChan depending on the message type
// (reply -> replyChan, request -> requestChan).
func ReceiverWorker(conn net.PacketConn,
	replyChan chan<- networking.ReceivedMessageData,
	requestChan chan<- networking.ReceivedMessageData) {
	buf := make([]byte, BUF_SIZE)
	for {
		n, addr, err := conn.ReadFrom(buf)

		if err != nil || n <= networking.MIN_MESSAGE_SIZE {
			slog.Error("Problem with read data", "err", err)
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		receivedMessage := networking.StoreReceivedMessageData(data, addr)
		// Chance that random ID is 0 is almost 0 isn't it? ;)
		if utility.IsIDEmpty(receivedMessage.ID) && receivedMessage.Err != nil {
			slog.Warn("Error decoding message data", "err", receivedMessage.Err)
			continue
		}
		if receivedMessage.Err == nil && networking.IsRequest(receivedMessage.MessType) {
			// A request arrived
			slog.Warn("Forwarding request")
			requestChan <- receivedMessage
			continue
		}
		replyChan <- receivedMessage
	}
}

func Receiver(conn net.PacketConn, replyChan chan<- networking.ReceivedMessageData,
	requestChan chan<- networking.ReceivedMessageData, workerCount uint32) {

	if workerCount < 1 {
		slog.Error("Invalid number of receiver workers provided")
		return
	}
	for range workerCount {
		go ReceiverWorker(conn, replyChan, requestChan)
	}
}
