package peer_message_parser

import (
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/handler"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/utility"
	"net"
)

func NewEmptyBaseMassage(id utility.ID) BaseMessage {
	return BaseMessage{
		id: id,
	}
}

func NewEmptyUnsignedMessage(id utility.ID) UnsignedMessage {
	return UnsignedMessage{NewEmptyBaseMassage(id)}
}

func NewEmptySignedMessage(id utility.ID) SignedMessage {
	return SignedMessage{BaseMessage: NewEmptyBaseMassage(id), Signature: encryption.Key{}}
}

// EncodeMessage converts a peerMessage to raw bytes for transmission
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
	case NATTraversal:
		return encodeNATTraversal(m)
	case NATTraversal2:
		return encodeNATTraversal2(m)
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
	result := createBaseMessage(msg.ID(), networking.ROOT_REQUEST, 32)
	result = append(result)
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
	dataBytes := msg.Data

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

// ===========================NATTraversal==========================

func encodeNATTraversal(msg NATTraversal) []byte {
	var addrBytes []byte
	var length uint16

	// Convert address to bytes based on IP version
	if udpAddr, ok := msg.Addr.(*net.UDPAddr); ok {
		if ipv4 := udpAddr.IP.To4(); ipv4 != nil {
			// IPv4 address: 4 bytes IP + 2 bytes port
			addrBytes = make([]byte, IPV4_LEN)
			copy(addrBytes[:4], ipv4)
			addrBytes[4] = byte(udpAddr.Port >> 8)
			addrBytes[5] = byte(udpAddr.Port & 0xFF)
			length = IPV4_LEN
		} else {
			// IPv6 address: 16 bytes IP + 2 bytes port
			addrBytes = make([]byte, IPV6_LEN)
			copy(addrBytes[:16], udpAddr.IP.To16())
			addrBytes[16] = byte(udpAddr.Port >> 8)
			addrBytes[17] = byte(udpAddr.Port & 0xFF)
			length = IPV6_LEN
		}
	} else {
		// Fallback for unknown address types
		return nil
	}

	result := createBaseMessage(msg.ID(), networking.NAT_TRAVERSAL, length)
	result = append(result, addrBytes...)
	signature := encryption.GetSignature(result)
	result = append(result, signature[:]...)
	return result
}

// ===========================NATTraversal2=========================

func encodeNATTraversal2(msg NATTraversal2) []byte {
	var addrBytes []byte
	var length uint16

	// Convert address to bytes based on IP version
	if udpAddr, ok := msg.Addr.(*net.UDPAddr); ok {
		if ipv4 := udpAddr.IP.To4(); ipv4 != nil {
			// IPv4 address: 4 bytes IP + 2 bytes port
			addrBytes = make([]byte, IPV4_LEN)
			copy(addrBytes[:4], ipv4)
			addrBytes[4] = byte(udpAddr.Port >> 8)
			addrBytes[5] = byte(udpAddr.Port & 0xFF)
			length = IPV4_LEN
		} else {
			// IPv6 address: 16 bytes IP + 2 bytes port
			addrBytes = make([]byte, IPV6_LEN)
			copy(addrBytes[:16], udpAddr.IP.To16())
			addrBytes[16] = byte(udpAddr.Port >> 8)
			addrBytes[17] = byte(udpAddr.Port & 0xFF)
			length = IPV6_LEN
		}
	} else {
		// Fallback for unknown address types
		return nil
	}

	result := createBaseMessage(msg.ID(), networking.NAT_TRAVERSAL2, length)
	result = append(result, addrBytes...)
	signature := encryption.GetSignature(result)
	result = append(result, signature[:]...)
	return result
}
