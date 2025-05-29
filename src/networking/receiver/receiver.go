package receiver

import (
	"fmt"
	"log/slog"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/networking/peer_conn"
	"mimuw_zps/src/networking/srv_conn"
	"mimuw_zps/src/utility"
	"net"
)

const (
	BUF_SIZE      = 2048
	PING          = "Ping"
	HELLO         = "Hello"
	ROOT_REQUEST  = "RootRequest"
	DATUM_REQUEST = "DatumRequest"
	ERROR         = "Error"
	HELLO_REPLY   = "HelloReply"
	ROOT_REPLY    = "RootReply"
	DATUM         = "Datum"
	NO_DATUM      = "NoDatum"
	MINIMUM_SIZE  = 3
)

var typeMap = map[uint16]string{
	0x0000: PING,
	0x0001: HELLO,
	0x0002: ROOT_REQUEST,
	0x0003: DATUM_REQUEST,
	0x0129: ERROR,
	0x0130: HELLO_REPLY,
	0x0131: ROOT_REPLY,
	0x0132: DATUM,
	0x0133: NO_DATUM,
}

// Temporary works only on one thread. You should provide the address on which receiver will run
func Receiver(address string, name string, key encryption.Key, server srv_conn.Server) error {
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		slog.Warn("Fail during creation udp listening", "err", err)
		return err
	}

	defer conn.Close()

	buf := make([]byte, BUF_SIZE)
	n, addr, err := conn.ReadFrom(buf)
	data := make([]byte, n)
	copy(data, buf[:n])

	if err != nil || n <= MINIMUM_SIZE {
		slog.Warn("Problem with read data", "err", err)
		return err
	}

	typeMessage := utility.GetMessageType(buf)
	switch typeMap[typeMessage] {
	case "Hello":
		go peer_conn.ReceiveHandshake(addr, data, server)
	case "HelloReply":
		go peer_conn.ReceiveReplyHandshake(data)
	default:
		fmt.Print(typeMessage)
		slog.Info("Received typeMessage", "typeMessage", typeMessage)
	}
	return nil
}
