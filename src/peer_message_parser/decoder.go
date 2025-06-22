package peer_message_parser

import (
	"errors"
	"log/slog"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/handler"
	"mimuw_zps/src/merkle_tree"
	"mimuw_zps/src/networking"
	"net"
	"unicode/utf8"
)

func decoderError(message string) error {
	return errors.New("decoder error: " + message)
}

func basicValidation(msg networking.ReceivedMessageData) error {
	if msg.Err != nil {
		return msg.Err
	}
	if uint16(len(msg.Data)) < msg.Length {
		return decoderError("message too short")
	}
	return nil
}

func DecodeMessage(msg networking.ReceivedMessageData) (PeerMessage, error) {
	if msg.Err != nil {
		return nil, msg.Err
	}
	switch msg.MessType {
	case networking.PING:
		return decodePingMsg(msg)
	case networking.HELLO:
		return decodeHelloMsg(msg)
	case networking.ROOT_REQUEST:
		return decodeRootRequestMsg(msg)
	case networking.DATUM_REQUEST:
		return decodeDatumRequestMsg(msg)
	case networking.PONG:
		return decodePongMsg(msg)
	case networking.ERROR:
		return decodeErrorMsg(msg)
	case networking.HELLO_REPLY:
		return decodeHelloReplyMsg(msg)
	case networking.ROOT_REPLY:
		return decodeRootReplyMsg(msg)
	case networking.DATUM:
		return decodeDatumMsg(msg)
	case networking.NO_DATUM:
		return decodeNoDatumMsg(msg)
	case networking.NAT_TRAVERSAL:
		return decodeNATTraversal(msg)
	case networking.NAT_TRAVERSAL2:
		return decodeNATTraversal2(msg)
	}
	return nil, decoderError("unknown message type: " + msg.MessType)
}

// ===========================BaseMessage===========================

func newBaseMassage(msg networking.ReceivedMessageData) BaseMessage {
	return BaseMessage{
		addr:   msg.Addr,
		id:     msg.ID,
		length: msg.Length,
		raw:    msg.Raw,
	}
}

func getSignature(msg networking.ReceivedMessageData) (encryption.Key, error) {
	if len(msg.Data) < int(msg.Length)+encryption.KEY_LENGTH {
		return encryption.Key{}, decoderError("message not signed")
	}
	return encryption.Key(msg.Data[msg.Length : msg.Length+encryption.KEY_LENGTH]), nil
}

// ==========================UnsignedMessage========================

func newUnsignedMessage(msg networking.ReceivedMessageData) UnsignedMessage {
	return UnsignedMessage{
		BaseMessage: newBaseMassage(msg),
	}
}

// ===========================SignedMessage==========================

func newSignedMessage(msg networking.ReceivedMessageData, signature encryption.Key) SignedMessage {
	return SignedMessage{
		BaseMessage: newBaseMassage(msg),
		Signature:   signature,
	}
}

// ============================PingMsg==============================

func decodePingMsg(msg networking.ReceivedMessageData) (PingMsg, error) {
	if err := basicValidation(msg); err != nil {
		return PingMsg{}, err
	}

	return PingMsg{
		UnsignedMessage: newUnsignedMessage(msg),
	}, nil
}

// ============================PongMsg==============================

func decodePongMsg(msg networking.ReceivedMessageData) (PongMsg, error) {
	if err := basicValidation(msg); err != nil {
		return PongMsg{}, err
	}

	return PongMsg{
		UnsignedMessage: newUnsignedMessage(msg),
	}, nil
}

// ===========================ErrorMsg==============================

func decodeErrorMsg(msg networking.ReceivedMessageData) (ErrorMsg, error) {
	if err := basicValidation(msg); err != nil {
		return ErrorMsg{}, err
	}

	if !utf8.Valid(msg.Data) {
		return ErrorMsg{}, decoderError("invalid error message")
	}
	message := string(msg.Data)
	return ErrorMsg{
		UnsignedMessage: newUnsignedMessage(msg),
		Message:         message,
	}, nil
}

// ===========================HelloMsg==============================

func decodeHandshake(msg networking.ReceivedMessageData) (Extensions, string, encryption.Key, error) {
	if err := basicValidation(msg); err != nil {
		return Extensions{}, "", encryption.Key{}, err
	}
	if msg.Length <= EXTENSIONS_LEN {
		return Extensions{}, "", encryption.Key{}, decoderError("message too short")
	}
	extensions := Extensions(msg.Data[:EXTENSIONS_LEN])
	nameBytes := msg.Data[EXTENSIONS_LEN:msg.Length]
	if !utf8.Valid(nameBytes) {
		return Extensions{}, "", encryption.Key{}, decoderError("name is not a valid utf-8 string")
	}
	signature, err := getSignature(msg)
	if err != nil {
		return Extensions{}, "", encryption.Key{}, err
	}
	return extensions, string(nameBytes), signature, nil
}

func decodeHelloMsg(msg networking.ReceivedMessageData) (HelloMsg, error) {
	extensions, name, signature, err := decodeHandshake(msg)
	if err != nil {
		return HelloMsg{}, err
	}
	return HelloMsg{
		SignedMessage: newSignedMessage(msg, signature),
		Extensions:    extensions,
		Name:          name,
	}, nil
}

// ========================HelloReplyMsg============================

func decodeHelloReplyMsg(msg networking.ReceivedMessageData) (HelloReplyMsg, error) {
	extensions, name, signature, err := decodeHandshake(msg)
	if err != nil {
		return HelloReplyMsg{}, err
	}
	return HelloReplyMsg{
		SignedMessage: newSignedMessage(msg, signature),
		Extensions:    extensions,
		Name:          name,
	}, nil
}

// ========================RootRequestMsg===========================

func decodeRootRequestMsg(msg networking.ReceivedMessageData) (RootRequestMsg, error) {
	if err := basicValidation(msg); err != nil {
		return RootRequestMsg{}, err
	}
	if msg.Length != 32 {
		return RootRequestMsg{}, decoderError("root request of invalid length")
	}
	return RootRequestMsg{
		UnsignedMessage: newUnsignedMessage(msg),
	}, nil
}

// =========================RootReplyMsg============================

func decodeRootReplyMsg(msg networking.ReceivedMessageData) (RootReplyMsg, error) {
	if err := basicValidation(msg); err != nil {
		return RootReplyMsg{}, err
	}
	if msg.Length < handler.HASH_LENGTH {
		return RootReplyMsg{}, decoderError("invalid root hash")
	}
	signature, err := getSignature(msg)
	if err != nil {
		return RootReplyMsg{}, err
	}
	slog.Debug("Root hash bytes", "hash", []byte(msg.Data[:handler.HASH_LENGTH]))
	return RootReplyMsg{
		SignedMessage: newSignedMessage(msg, signature),
		Hash:          handler.Hash(msg.Data[:handler.HASH_LENGTH]),
	}, nil
}

// =========================DatumRequestMsg=========================

func decodeDatumRequestMsg(msg networking.ReceivedMessageData) (DatumRequestMsg, error) {
	if err := basicValidation(msg); err != nil {
		return DatumRequestMsg{}, err
	}
	if msg.Length < handler.HASH_LENGTH {
		return DatumRequestMsg{}, decoderError("invalid root hash")
	}

	return DatumRequestMsg{
		UnsignedMessage: newUnsignedMessage(msg),
		Hash:            handler.Hash(msg.Data[:handler.HASH_LENGTH]),
	}, nil
}

// =============================DatumMsg============================

func getNameFromBytes(nameBytes [32]byte) (string, error) {
	var i int
	for i = 31; i >= 0; i-- {
		if nameBytes[i] != 0x0 {
			break
		}
	}
	if i == 0 {
		return "", nil
	}
	importantBytes := nameBytes[:min(i, 30)+1]
	if !utf8.Valid(importantBytes) {
		return "", errors.New("invalid name of file/directory")
	}
	return string(importantBytes), nil
}

func decodeDatumMsg(msg networking.ReceivedMessageData) (DatumMsg, error) {
	if err := basicValidation(msg); err != nil {
		return DatumMsg{}, err
	}
	if msg.Length < handler.HASH_LENGTH+1 {
		// +1 for type
		return DatumMsg{}, decoderError("message too short")
	}
	hash := handler.Hash(msg.Data[:handler.HASH_LENGTH])
	var nodeType merkle_tree.NodeType
	var data []byte
	var children []merkle_tree.DirectoryRecord
	switch msg.Data[handler.HASH_LENGTH] {
	case 0x0:
		// CHUNK
		if msg.Length-handler.HASH_LENGTH > MAX_CHUNK_SIZE+1 {
			return DatumMsg{}, decoderError("chunk data too big")
		}
		nodeType = merkle_tree.CHUNK
		data = msg.Data[1+handler.HASH_LENGTH:]
	case 0x01:
		dirEntriesLen := msg.Length - 1 - handler.HASH_LENGTH
		// DIRECTORY
		if dirEntriesLen%DIR_ENTRY_SIZE != 0 || dirEntriesLen/DIR_ENTRY_SIZE > DIR_MAX_ENTRIES {
			return DatumMsg{}, decoderError("directory entires are of incorrect length")
		}
		records := make([]merkle_tree.DirectoryRecord, dirEntriesLen/DIR_ENTRY_SIZE)
		recordStart := handler.HASH_LENGTH + 1
		for i := range len(records) {
			n, err := getNameFromBytes([DIR_HALF_ENTRY]byte(msg.Data[recordStart : recordStart+DIR_HALF_ENTRY]))
			if err != nil {
				return DatumMsg{}, decoderError(err.Error())
			}
			h := msg.Data[recordStart+DIR_HALF_ENTRY : recordStart+DIR_ENTRY_SIZE]
			records[i] = merkle_tree.DirectoryRecord{Name: n, Hash: h}
			recordStart += DIR_ENTRY_SIZE
		}
		nodeType = merkle_tree.DIRECTORY
		children = records
	case 0x03, 0x02:
		// BIG
		recordsRawLen := (msg.Length - 1 - handler.HASH_LENGTH)
		recordsCount := recordsRawLen / BIG_ENTRY_SIZE
		if recordsRawLen%BIG_ENTRY_SIZE != 0 || recordsCount > BIG_ENTRY_SIZE || recordsCount < BIG_MIN_ENTRY_SIZE {
			return DatumMsg{}, decoderError("big node children are of incorrect length")
		}
		records := make([]merkle_tree.DirectoryRecord, recordsCount)
		recordStart := 1 + handler.HASH_LENGTH
		for i := 0; i < int(recordsCount); i++ {
			records[i] = merkle_tree.DirectoryRecord{Hash: msg.Data[recordStart : recordStart+BIG_ENTRY_SIZE]}
			recordStart += BIG_ENTRY_SIZE
		}
		nodeType = merkle_tree.BIG
		children = records
	default:
		slog.Warn("Invalid node type in response", "type", msg.Data[handler.HASH_LENGTH], "msg", msg)
		return DatumMsg{}, errors.New("invalid node type in response")
	}

	return DatumMsg{
		UnsignedMessage: newUnsignedMessage(msg),
		Hash:            hash,
		NodeType:        nodeType,
		Data:            data,
		Children:        merkle_tree.DirectoryRecords{Records: children, Raw: msg.Data[handler.HASH_LENGTH:]},
	}, nil
}

// =============================NoDatumMsg============================

func decodeNoDatumMsg(msg networking.ReceivedMessageData) (NoDatumMsg, error) {
	if err := basicValidation(msg); err != nil {
		return NoDatumMsg{}, err
	}
	if msg.Length < handler.HASH_LENGTH {
		return NoDatumMsg{}, decoderError("invalid root hash")
	}
	signature, err := getSignature(msg)
	if err != nil {
		return NoDatumMsg{}, err
	}

	return NoDatumMsg{
		SignedMessage: newSignedMessage(msg, signature),
		Hash:          handler.Hash(msg.Data[:handler.HASH_LENGTH]),
	}, nil
}

// =============================NATTRaversalMsg============================

func decodeNATTraversal(msg networking.ReceivedMessageData) (NATTraversal, error) {
	if err := basicValidation(msg); err != nil {
		return NATTraversal{}, err
	}
	var addr net.Addr
	if msg.Length == IPV4_LEN {
		ip := net.IPv4(msg.Data[0], msg.Data[1], msg.Data[2], msg.Data[3])

		port := int(msg.Data[4])<<8 | int(msg.Data[5])

		addr = &net.UDPAddr{
			IP:   ip,
			Port: port,
		}
	} else if msg.Length == IPV6_LEN {
		ip := net.IP(msg.Data[0 : IPV6_LEN-2])

		port := int(msg.Data[IPV6_LEN-2])<<8 | int(msg.Data[IPV6_LEN-1])

		addr = &net.UDPAddr{
			IP:   ip,
			Port: port,
		}
	}
	signature, err := getSignature(msg)
	if err != nil {
		return NATTraversal{}, err
	}

	return NATTraversal{
		SignedMessage: newSignedMessage(msg, signature),
		Addr:          addr,
	}, nil
}

// =============================NATTRaversal2Msg============================

func decodeNATTraversal2(msg networking.ReceivedMessageData) (NATTraversal2, error) {
	if err := basicValidation(msg); err != nil {
		return NATTraversal2{}, err
	}
	var addr net.Addr
	if msg.Length == IPV4_LEN {
		ip := net.IPv4(msg.Data[0], msg.Data[1], msg.Data[2], msg.Data[3])

		port := int(msg.Data[4])<<8 | int(msg.Data[5])

		addr = &net.UDPAddr{
			IP:   ip,
			Port: port,
		}
	} else if msg.Length == IPV6_LEN {
		ip := net.IP(msg.Data[0 : IPV6_LEN-2])

		port := int(msg.Data[IPV6_LEN-2])<<8 | int(msg.Data[IPV6_LEN-1])

		addr = &net.UDPAddr{
			IP:   ip,
			Port: port,
		}
	}
	signature, err := getSignature(msg)
	if err != nil {
		return NATTraversal2{}, err
	}

	return NATTraversal2{
		SignedMessage: newSignedMessage(msg, signature),
		Addr:          addr,
	}, nil
}

// TODO(sormys) add NatTraversal messages
