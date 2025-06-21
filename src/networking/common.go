package networking

import (
	"errors"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/utility"
	"net"
)

const WORKER_CHAN_BUF_SIZE = 1024
const MAIN_CHAN_BUF_SIZE = 2048

type stage = string

const (
	NOT_CONNECTED stage = "not connected"
	CONNECT       stage = "connect"
	PENDING       stage = "pending"
)

type Peer struct {
	Addresses []net.Addr
	Name      string
	Key       encryption.Key
	Stage     stage
}

func NewPeer(name string, addresses []net.Addr, key encryption.Key) Peer {
	return Peer{Name: name, Addresses: addresses, Key: key}
}

type MessageType = string

const (
	PING          MessageType = "Ping"
	HELLO         MessageType = "Hello"
	ROOT_REQUEST  MessageType = "RootRequest"
	DATUM_REQUEST MessageType = "DatumRequest"
	PONG          MessageType = "Pong"
	ERROR         MessageType = "Error"
	HELLO_REPLY   MessageType = "HelloReply"
	ROOT_REPLY    MessageType = "RootReply"
	DATUM         MessageType = "Datum"
	NO_DATUM      MessageType = "NoDatum"
)

func IsRequest(messageType MessageType) bool {
	// FIXME(sormys) temporary solution, should probably just check if code is
	// >127
	isRequest := false
	switch messageType {
	case HELLO, ROOT_REQUEST, DATUM_REQUEST, PING:
		isRequest = true
	}
	return isRequest
}

func swapMap[K comparable, V comparable](original map[K]V) map[V]K {
	swapped := make(map[V]K, len(original))
	for key, value := range original {
		swapped[value] = key
	}
	return swapped
}

var TypeMap = map[uint8]MessageType{
	0x00: PING,
	0x01: HELLO,
	0x02: ROOT_REQUEST,
	0x03: DATUM_REQUEST,
	0x80: PONG,
	0x81: ERROR,
	0x82: HELLO_REPLY,
	0x83: ROOT_REPLY,
	0x84: DATUM,
	0x85: NO_DATUM,
}

var ByteTypeMap = swapMap(TypeMap)

type ReceivedMessageData struct {
	Addr     net.Addr
	ID       utility.ID
	MessType MessageType
	Length   uint16
	Data     []byte
	Raw      []byte
	Err      error
}

type SendRequest struct {
	Addr            net.Addr
	Message         encryption.Message
	MessRetryPolicy RetryPolicy
	CallbackChan    chan<- ReceivedMessageData
}

const MIN_MESSAGE_SIZE = 7

func StoreReceivedMessageData(message encryption.Message, addr net.Addr) ReceivedMessageData {
	if len(message) < MIN_MESSAGE_SIZE {
		return ReceivedMessageData{Err: errors.New(
			"received message of incorrect size from peer")}
	}
	id := utility.GetMessageID(message)
	messageType := TypeMap[utility.GetMessageType(message)]
	if len(message) < MIN_MESSAGE_SIZE {
		return ReceivedMessageData{ID: id, Err: errors.New(
			"received message of incorrect size from peer")}
	}
	lengthBytes := message[5:7]
	length := utility.GetNumberFromBytes(lengthBytes)
	if int(length) > len(message)-MIN_MESSAGE_SIZE {
		// With or without signature
		return ReceivedMessageData{ID: id, Err: errors.New(
			"received message with incorrect data (declared length do not match)")}
	}
	return ReceivedMessageData{Addr: addr, ID: id, MessType: messageType, Length: length, Data: message[7:], Raw: message, Err: nil}
}
