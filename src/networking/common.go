package networking

import (
	"errors"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/utility"
	"net"
	"time"
)

type MessageType = string

const (
	PING          MessageType = "Ping"
	HELLO         MessageType = "Hello"
	ROOT_REQUEST  MessageType = "RootRequest"
	DATUM_REQUEST MessageType = "DatumRequest"
	ERROR         MessageType = "Error"
	HELLO_REPLY   MessageType = "HelloReply"
	ROOT_REPLY    MessageType = "RootReply"
	DATUM         MessageType = "Datum"
	NO_DATUM      MessageType = "NoDatum"
)

var TypeMap = map[uint16]MessageType{
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

type ReceivedMessageData struct {
	Addr     net.Addr
	ID       utility.ID
	MessType MessageType
	Length   uint16
	Data     []byte
	Err      error
}

type RetryPolicy interface {
	NextRetry() (time.Duration, error)
}

type SendRequest struct {
	Addr            net.Addr
	Message         encryption.Message
	MessRetryPolicy RetryPolicy
	CallbackChan    chan<- *ReceivedMessageData
}

const MIN_MESSAGE_SIZE = 7
const MIN_HELLO_SIZE = 16
const MIN_HELLO_REPLY_SIZE = 16

func getMinimalSize(messageType MessageType) int {
	switch messageType {
	case HELLO:
		return MIN_HELLO_SIZE
	case HELLO_REPLY:
		return MIN_HELLO_REPLY_SIZE
	default:
		return -1
	}
}

func StoreReceivedMessageData(message encryption.Message, addr net.Addr) ReceivedMessageData {
	if len(message) < 7 {
		return ReceivedMessageData{Err: errors.New(
			"received message of incorrect size from peer")}
	}
	id := utility.GetMessageID(message)
	messageType := TypeMap[utility.GetMessageType(message)]
	if len(message) < getMinimalSize(messageType) {
		return ReceivedMessageData{ID: id, Err: errors.New(
			"received message of incorrect size from peer")}
	}
	lengthBytes := message[5:7]
	length := utility.GetNumberFromBytes(lengthBytes)
	if utility.EqualIntUint16(len(message), 11+length) {
		return ReceivedMessageData{ID: id, Err: errors.New(
			"received message with incorrect data (declared length do not match)")}
	}
	return ReceivedMessageData{Addr: addr, ID: id, MessType: messageType, Length: length, Data: message[7:], Err: nil}
}
