package receiver

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/networking/peer_conn"
	"net"
)

var typeMap = map[uint16]string{
	0x0000: "Ping",
	0x0001: "Hello",
	0x0002: "RootRequest",
	0x0003: "DatumRequest",
	0x0129: "Error",
	0x0130: "HelloReply",
	0x0131: "RootReply",
	0x0132: "Datum",
	0x0133: "NoDatum",
}

// Temporary works only on one thread. You should provide the address on which receiver will run
func Receiver(address string, name string, key encryption.Key) error {
	p := peer_conn.NewPeer(name, []string{address}, key, nil)
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		slog.Warn("Fail during creation udp listening", "err", err)
		return err
	}

	defer conn.Close()

	//It should be replace to StringBuilder
	buf := make([]byte, 2048)
	n, addr, err := conn.ReadFrom(buf)
	data := make([]byte, n)
	copy(data, buf[:n])

	if err != nil || n <= 3 {
		slog.Warn("Problem with read data", "err", err)
		return err
	}

	typeMessage := binary.BigEndian.Uint16(buf[3:5])
	switch typeMap[typeMessage] {
	case "Hello":
		go p.ReceiveHandshake(addr, data)
	case "HelloReply":
		go peer_conn.ReceiveReplyHandshake(data)
	default:
		fmt.Print(typeMessage)
	}
	return nil
}
