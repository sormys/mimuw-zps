package packet_manager

import (
	"log/slog"
	"mimuw_zps/src/networking"
	"net"
)

const BUF_SIZE = 2048

// Receives a message (sigle UDP packet) and sends received initialy validated
// data to writer via writerChan.
func Receiver(conn net.UDPConn, writerChan chan *networking.ReceivedMessageData) {
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
		writerChan <- &receivedMessage
	}
}
