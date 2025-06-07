package peer_conn

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/utility"
	"net"
)

const USER_NAME = "NICPON"

var userMap = map[string]Peer{}

// Stage can me ENUM, for example: in the middle of the handshake, or post-handshake
type Peer struct {
	Addresses []net.Addr
	Name      string
	Key       encryption.Key
}

type HandshakeType struct {
	ID         utility.ID
	typeM      encryption.TypeMessage
	length     uint16
	extensions []byte
	name       string
	signature  encryption.Signature
}

var (
	HELLO        = encryption.TypeMessage([]byte{0x00})
	EMPTY_LENGTH = encryption.TypeMessage([]byte{0x00, 0x00})
	HELLO_REPLY  = encryption.TypeMessage([]byte{0x82})
	ERROR        = encryption.TypeMessage([]byte{0x81})
	my_address   = "0.0.0.0:2137"
)

func NewPeer(name string, addresses []net.Addr, key encryption.Key) Peer {
	return Peer{Name: name, Addresses: addresses, Key: key}
}

func getExtensions() []byte {
	return []byte{0x00, 0x00, 0x00, 0x00}
}

// Finds a Peer by his address, then return thei last_id
//	to verify if the sent ID matches the reveiced ID

func getLastIDPeer(addr net.Addr) utility.ID {
	return utility.ID{}
}

// Convert raw data to struct
func decodeHandshake(data encryption.Message) HandshakeType {
	id := data[:4]
	typeMessage := data[4:5]
	length := data[5:7]
	extensions := data[7:11]
	name := data[11 : 11+utility.GetNumberFromBytes(length)]
	signature := data[11+utility.GetNumberFromBytes(length):]
	return HandshakeType{utility.ID(id),
		encryption.TypeMessage(typeMessage),
		utility.GetNumberFromBytes(length),
		extensions,
		string(name),
		encryption.Signature(signature)}
}

// Creates an message error that includes from the given ID and description of the error.
func encodeError(id utility.ID, errorMessage string) encryption.Message {
	message := utility.GenerateEmptyBuffor()
	message = append(message, id[:]...)
	message = append(message, ERROR...)

	messageByte := []byte(errorMessage)
	buffor := new(bytes.Buffer)
	err := binary.Write(buffor, binary.LittleEndian, utility.GetBytesFromNumber(len(messageByte)))
	if err != nil {
		slog.Error("Problem with construct message length", "error", err)
		return nil
	}
	message = append(message, buffor.Bytes()...)
	message = append(message, messageByte...)
	return message
}

// Creates an Handshake that includes from the given ID and messageType HELLO or HELLO_REPLY.
func encodeHandshake(typeMessage encryption.TypeMessage, id utility.ID) encryption.Message {
	extensions := getExtensions()
	name := []byte(USER_NAME)
	length := utility.GetBytesFromNumber(len(name))

	message := utility.GenerateEmptyBuffor()
	message = append(message, id[:]...)
	message = append(message, typeMessage...)
	message = append(message, length...)
	message = append(message, extensions...)
	message = append(message, name...)

	return message
}

// Currently this function sends a message directly, but I think in future we will create thread for it
func SendMessage(addr net.Addr, data encryption.Message) error {
	conn, err := net.ListenPacket("udp4", my_address)
	if err != nil {
		slog.Error("Problem when creating a connection", "error", err)
		return err
	}
	defer conn.Close()

	_, err = conn.WriteTo(data, addr)

	if err != nil {
		slog.Error("Inccorect send message", "error", err)
		return err
	}

	slog.Info("Sent data to", "address", addr)

	return nil
}

// We invoke this function when we want start communication with new server/peer.
// Function return ID of request.
func SendHandshake(MessageType []byte, addr net.Addr) utility.ID {

	if !(bytes.Equal(MessageType, HELLO) || bytes.Equal(MessageType, HELLO_REPLY)) {
		slog.Error("Incorrect MessageType during sending Handshake", "MessageType", string(MessageType))
		return utility.ID{}
	}

	id := utility.GenerateID()
	if !utility.IsIDEmpty(getLastIDPeer(addr)) {
		id = getLastIDPeer(addr)
	}

	message := encodeHandshake(MessageType, id)
	signature := encryption.GetSignature(message)
	data := append(message, signature[:]...)
	err := SendMessage(addr, data)

	if err != nil {
		slog.Error("Incorrect sending message", "error", err)
		return utility.ID{}
	}
	return id
}
