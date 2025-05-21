package peer_conn

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/networking/srv_conn"
	"net"
)

// / This will be shared memory. It's important to track the current communication stage:
// no knowledge yet, in the middle of the handshake, or post-handshake.

var userMap = map[string]Peer{}

type Peer struct {
	addresses []string
	name      string
	key       encryption.Key
	last_id   []byte
	//temporary commented
	//stage     string
}

type Message []byte

type HandshakeType struct {
	ID         []byte
	typeM      []byte
	length     []byte
	extensions []byte
	name       []byte
	signature  []byte
}

var (
	HELLO        = Message([]byte{0x00})
	EMPTY_LENGTH = Message([]byte{0x00, 0x00})
	HELLO_REPLY  = Message([]byte{0x82})
	ERROR        = Message([]byte{0x81})
)

func NewPeer(name string, addresses []string, key encryption.Key, last_id []byte) Peer {
	return Peer{name: name, addresses: addresses, key: key, last_id: last_id}
}

func getExtensions() []byte {
	return []byte{0x00, 0x00, 0x00, 0x00}
}

func decodeHandshake(data []byte) HandshakeType {
	id := data[:4]
	typeMessage := data[4:5]
	length := data[5:7]
	extensions := data[7:11]
	name := data[11 : 11+length[0]]
	signature := data[11+length[0]:]
	return HandshakeType{id, typeMessage, length, extensions, name, signature}
}

func encodeError(id []byte, errorMessage string) []byte {
	message := make([]byte, 0)
	message = append(message, id...)
	message = append(message, ERROR...)

	messageByte := []byte(errorMessage)
	buffor := new(bytes.Buffer)
	err := binary.Write(buffor, binary.LittleEndian, uint16(len(messageByte)))
	if err != nil {
		slog.Error("Problem with construct message length", "error", err)
		return nil
	}
	message = append(message, buffor.Bytes()...)
	message = append(message, messageByte...)
	return message
}

func (p Peer) encodeHandshake(typeMessage Message, id []byte) []byte {
	extensions := getExtensions()
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

// Currently this function sends a message directly, but I think in future we will create thread for it
func SendMessage(addr net.Addr, data []byte) error {
	my_address := "0.0.0.0:2137"
	conn, err := net.ListenPacket("udp4", my_address)
	if err != nil {
		slog.Error("Problem when creating a connection", "error", err)
		return err
	}
	defer conn.Close()

	_, err = conn.WriteTo(data, addr)
	fmt.Println("Sent data to", addr)

	if err != nil {
		slog.Error("Inccorect send message", "error", err)
		return err
	}
	return nil
}

// We invoke this function when we want start communication with new server/peer.
// Function return ID of request.
func (p Peer) SendHandshake(addr net.Addr) []byte {

	id := make([]byte, 4)
	message := p.encodeHandshake(HELLO, id)

	data := encryption.SignatureMessage(message)

	err := SendMessage(addr, data)

	if err != nil {
		slog.Error("Incorrect sending message", "error", err)
		return nil
	}
	return id
}

// This function is called when we receive ReplyHandshake.
// It verfies that the response ID matches the one we sent.
// Return true if reply is valid
func ReceiveReplyHandshake(buf []byte) bool {

	handshake := decodeHandshake(buf)
	id := userMap[string(handshake.name)].last_id

	if bytes.Equal(handshake.ID, id) {
		slog.Error("Hello ID doesnt match to HelloReply ID", "error", "ID mismatch")
		return false
	}

	return true
}

// This function is called when the main receiver recognize, that request was "Hello".
// It queries the server for peer's key, verifies it and responds to the sender with "HelloReply"
func (p Peer) ReceiveHandshake(addr net.Addr, data []byte) bool {

	// How should we obtain the Server Instance here? Creating a new object is a temporary solution
	// Alternatively, should we send a message via a channel to the sending thread
	url := "https://galene.org:8448/"
	server := srv_conn.NewServer(url)

	request := decodeHandshake(data)
	key, error := server.GetPeerKey(string(request.name))

	if error != nil {
		slog.Error("Failed to get peer key", "error", error)
		return false
	}

	if !encryption.VerifySignature(data, request.signature, encryption.ParsePublicKey(key)) {
		SendMessage(addr, encodeError(data[:4], "Signature verification failed"))
		return false
	}

	data = p.encodeHandshake(HELLO_REPLY, data[:4])
	conn := SendMessage(addr, data)

	if conn == nil {
		slog.Error("Fail to response to handshake", "error", error)
		return false
	}
	fmt.Println("Sent handshake response:", data)
	return true
}
