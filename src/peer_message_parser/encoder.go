package peer_message_parser

import (
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/handler"
	"mimuw_zps/src/merkle_tree"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/utility"
)

func NewEmptyBaseMassage(id utility.ID) BaseMessage {
	return BaseMessage{
		id: id,
	}
}

func NewEmtpyUnsignedMessage(id utility.ID) UnsignedMessage {
	return UnsignedMessage{NewEmptyBaseMassage(id)}
}

func NewEmptySignedMessage(id utility.ID) SignedMessage {
	return SignedMessage{BaseMessage: NewEmptyBaseMassage(id), Signature: encryption.Key{}}
}

// EncodeMessage converts a peerMessage to raw bytes for transmission
// PeerMessage length parameter can be of any value as it will be calculated
// during encoding.
func EncodeMessage(msg PeerMessage) []byte {
	switch m := msg.(type) {
	case PingMsg:
		return encodePingMsg(m)
	case PongMsg:
		return encodePongMsg(m)
	case ErrorMsg:
		return encodeErrorMsg(m)
	case HelloMsg:
		return encodeHelloMsg(m)
	case HelloReplyMsg:
		return encodeHelloReplyMsg(m)
	case RootRequestMsg:
		return encodeRootRequestMsg(m)
	case RootReplyMsg:
		return encodeRootReplyMsg(m)
	case DatumRequestMsg:
		return encodeDatumRequestMsg(m)
	case DatumMsg:
		return encodeDatumMsg(m)
	case NoDatumMsg:
		return encodeNoDatumMsg(m)
	default:
		return nil
	}
}

// ============================BaseMsg==============================

// Helper function to create base message structure
func createBaseMessage(id utility.ID, msgType networking.MessageType, length uint16) []byte {
	msg := make([]byte, networking.MIN_MESSAGE_SIZE)
	copy(msg[0:4], id[:])
	msg[4] = networking.ByteTypeMap[msgType]
	msg[5] = byte(length >> 8)
	msg[6] = byte(length & 0xFF)
	return msg
}

// ============================PingMsg==============================

func encodePingMsg(msg PingMsg) []byte {
	return createBaseMessage(msg.ID(), networking.PING, 0)
}

// ============================PongMsg==============================

func encodePongMsg(msg PongMsg) []byte {
	return createBaseMessage(msg.ID(), networking.PONG, 0)
}

// ===========================ErrorMsg==============================

func encodeErrorMsg(msg ErrorMsg) []byte {
	messageBytes := []byte(msg.Message)
	length := uint16(len(messageBytes))

	result := createBaseMessage(msg.ID(), networking.ERROR, length)
	result = append(result, messageBytes...)
	return result
}

// ===========================HelloMsg==============================

func encodeHandshake(id utility.ID, msgType networking.MessageType, extensions Extensions, name string) []byte {
	nameBytes := []byte(name)
	length := uint16(EXTENSIONS_LEN + len(nameBytes))

	result := createBaseMessage(id, msgType, length)
	result = append(result, extensions[:]...)
	result = append(result, nameBytes...)
	signature := encryption.GetSignature(result)
	result = append(result, signature[:]...)
	return result
}

func encodeHelloMsg(msg HelloMsg) []byte {
	return encodeHandshake(msg.ID(), networking.HELLO, msg.Extensions, msg.Name)
}

// ========================HelloReplyMsg============================

func encodeHelloReplyMsg(msg HelloReplyMsg) []byte {
	return encodeHandshake(msg.ID(), networking.HELLO_REPLY, msg.Extensions, msg.Name)
}

// ========================RootRequestMsg===========================

func encodeRootRequestMsg(msg RootRequestMsg) []byte {
	result := createBaseMessage(msg.ID(), networking.ROOT_REQUEST, 0)
	signature := encryption.GetSignature(result)
	result = append(result, signature[:]...)
	return result
}

// =========================RootReplyMsg============================

func encodeRootReplyMsg(msg RootReplyMsg) []byte {
	length := uint16(handler.HASH_LENGTH)

	result := createBaseMessage(msg.ID(), networking.ROOT_REPLY, length)
	result = append(result, msg.Hash[:]...)
	signature := encryption.GetSignature(result)
	result = append(result, signature[:]...)
	return result
}

// =========================DatumRequestMsg=========================

func encodeDatumRequestMsg(msg DatumRequestMsg) []byte {
	length := uint16(handler.HASH_LENGTH)

	result := createBaseMessage(msg.ID(), networking.DATUM_REQUEST, length)
	result = append(result, msg.Hash[:]...)
	return result
}

// =============================DatumMsg============================

func encodeDatumMsg(msg DatumMsg) []byte {
	var dataBytes []byte

	switch msg.NodeType {
	case merkle_tree.CHUNK:
		dataBytes = append([]byte{0x0}, msg.Data...)

	case merkle_tree.DIRECTORY:
		dataBytes = []byte{0x01}
		for _, child := range msg.Children {
			nameBytes := make([]byte, DIR_HALF_ENTRY)
			copy(nameBytes, []byte(child.Name))
			dataBytes = append(dataBytes, nameBytes...)
			dataBytes = append(dataBytes, child.Hash...)
		}

	case merkle_tree.BIG:
		dataBytes = []byte{0x03}
		for _, child := range msg.Children {
			dataBytes = append(dataBytes, child.Hash...)
		}

	default:
		return nil
	}

	length := uint16(handler.HASH_LENGTH + len(dataBytes))

	result := createBaseMessage(msg.ID(), networking.DATUM, length)

	result = append(result, msg.Hash[:]...)
	result = append(result, dataBytes...)

	return result
}

// =============================NoDatumMsg============================

func encodeNoDatumMsg(msg NoDatumMsg) []byte {
	length := uint16(handler.HASH_LENGTH)

	result := createBaseMessage(msg.ID(), networking.NO_DATUM, length)
	result = append(result, msg.Hash[:]...)
	signature := encryption.GetSignature(result)
	result = append(result, signature[:]...)
	return result
}
