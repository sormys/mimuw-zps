package peer_conn

import (
	"fmt"
	"log/slog"
	"mimuw_zps/src/encryption"
	"net"
)

type Peer struct {
	name      string
	addresses []string
	key       encryption.Key
}

// Which address to use? I had to set it to nil, otherwise it would not work
// If you set nil, Go chooses the first non-loopback address
var addr = net.UDPAddr{
	Port: 2139,
	IP:   nil,
}

type Message []byte

type HandshakeType struct {
	ID         []byte
	Type       []byte
	Length     []byte
	Extensions []byte
	Name       []byte
}

var (
	HELLO        = Message([]byte{0x00})
	EMPTY_LENGTH = Message([]byte{0x00, 0x00})
	HELLO_REPLY  = Message([]byte{0x82})
)

func NewPeer(name string, addresses []string, key encryption.Key) Peer {
	return Peer{name: name, addresses: addresses, key: key}
}

func getExtensions() []byte {
	return []byte{0x00, 0x00, 0x00, 0x00}
}

func (p Peer) decodeHandshake(data []byte) HandshakeType {
	id := data[:4]
	typeMessage := data[4:5]
	length := data[5:7]
	extensions := data[7:11]
	name := data[11 : 11+length[0]]
	return HandshakeType{id, typeMessage, length, extensions, name}
}

func (p Peer) encodeHandshake() []byte {
	id := make([]byte, 4)
	extensions := getExtensions()
	typeMessage := HELLO
	name := []byte(p.name)
	length := EMPTY_LENGTH

	message := make([]byte, 0)
	message = append(message, id...)
	message = append(message, typeMessage...)
	message = append(message, length...)
	message = append(message, extensions...)
	message = append(message, name...)

	return message
}

func (p Peer) SendHandshake(peer Peer) bool {

	message := p.encodeHandshake()
	data := encryption.SignatureMessage(message)

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		slog.Error("Failed to listen on UDP", "error", err)
		return false
	}
	defer conn.Close()

	//which address to use?
	raddr, err := net.ResolveUDPAddr("udp", peer.addresses[0])
	if err != nil {
		slog.Error("Failed to resolve UDP address", "error", err)
		return false
	}
	_, err = conn.WriteTo(data, raddr)
	fmt.Println("Sent data to", raddr)

	if err != nil {
		slog.Error("Failed to send handshake", "error", err)
	}

	//how big should the buffer be?
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		slog.Error("Failed to read handshake response", "error", err)
	}

	fmt.Println("Received response:", buf[:n])
	handshake := p.decodeHandshake(buf[:n])

	if handshake.Type[0] != HELLO_REPLY[0] {
		slog.Error("Failed to receive handshake response", "error", err)
		return false
	}

	return true
}
