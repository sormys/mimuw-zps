package peer_message_parser

import (
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/utility"
)

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

func SignMessage(msg BaseMessage) SignedMessage {
	signature := encryption.GetSignature(msg.Raw())

	return SignedMessage{
		BaseMessage: msg,
		Signature:   signature,
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

func encodeHandshake(id utility.ID, msgType networking.MessageType, extensions Extensions, name string, signature encryption.Key) []byte {
	nameBytes := []byte(name)
	length := uint16(EXTENSIONS_LEN + len(nameBytes))

	result := createBaseMessage(id, msgType, length)
	result = append(result, extensions[:]...)
	result = append(result, nameBytes...)
	result = append(result, signature[:]...)
	return result
}

func encodeHelloMsg(msg HelloMsg) []byte {
	return encodeHandshake(msg.ID(), networking.HELLO, msg.Extensions, msg.Name, msg.Signature)
}

// ========================HelloReplyMsg============================

func encodeHelloReplyMsg(msg HelloReplyMsg) []byte {
	return encodeHandshake(msg.ID(), networking.HELLO_REPLY, msg.Extensions, msg.Name, msg.Signature)
}

// ========================RootRequestMsg===========================

func encodeRootRequestMsg(msg RootRequestMsg) []byte {
	result := createBaseMessage(msg.ID(), networking.ROOT_REQUEST, 0)
	result = append(result, msg.Signature[:]...)
	return result
}

// =========================RootReplyMsg============================

func encodeRootReplyMsg(msg RootReplyMsg) []byte {
	length := uint16(message_manager.HASH_LENGTH)

	result := createBaseMessage(msg.ID(), networking.ROOT_REPLY, length)
	result = append(result, msg.Hash[:]...)
	result = append(result, msg.Signature[:]...)
	return result
}

// =========================DatumRequestMsg=========================

func encodeDatumRequestMsg(msg DatumRequestMsg) []byte {
	length := uint16(message_manager.HASH_LENGTH)

	result := createBaseMessage(msg.ID(), networking.DATUM_REQUEST, length)
	result = append(result, msg.Hash[:]...)
	return result
}

// =============================DatumMsg============================

func encodeDatumMsg(msg DatumMsg) []byte {
	length := uint16(message_manager.HASH_LENGTH)

	result := createBaseMessage(msg.ID(), networking.DATUM, length)
	result = append(result, msg.Hash[:]...)
	return result
}

// =============================NoDatumMsg============================

func encodeNoDatumMsg(msg NoDatumMsg) []byte {
	length := uint16(message_manager.HASH_LENGTH)

	result := createBaseMessage(msg.ID(), networking.NO_DATUM, length)
	result = append(result, msg.Hash[:]...)
	result = append(result, msg.Signature[:]...)
	return result
}
