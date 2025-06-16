package peer_message_parser

import (
	"errors"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking"
	"unicode/utf8"
)

func decoderError(message string) error {
	return errors.New("decoder error: " + message)
}

func basicValidation(msg networking.ReceivedMessageData) error {
	if msg.Err != nil {
		return msg.Err
	}
	if msg.Length < networking.MIN_MESSAGE_SIZE {
		return decoderError("message too short")
	}
	return nil
}

func DecodeMessage(msg networking.ReceivedMessageData) (PeerMessage, error) {
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
	}
	return nil, decoderError("unknown message type")
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
	if len(msg.Data) <= int(msg.Length)+encryption.KEY_LENGTH {
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
	if msg.Length > 0 {
		return RootRequestMsg{}, decoderError("root request should have empty body")
	}
	signature, err := getSignature(msg)
	if err != nil {
		return RootRequestMsg{}, err
	}
	return RootRequestMsg{
		SignedMessage: newSignedMessage(msg, signature),
	}, nil
}

// =========================RootReplyMsg============================

func decodeRootReplyMsg(msg networking.ReceivedMessageData) (RootReplyMsg, error) {
	if err := basicValidation(msg); err != nil {
		return RootReplyMsg{}, err
	}
	if msg.Length < message_manager.HASH_LENGTH {
		return RootReplyMsg{}, decoderError("invalid root hash")
	}
	signature, err := getSignature(msg)
	if err != nil {
		return RootReplyMsg{}, err
	}
	return RootReplyMsg{
		SignedMessage: newSignedMessage(msg, signature),
		Hash:          message_manager.Hash(msg.Data[:message_manager.HASH_LENGTH]),
	}, nil
}

// =========================DatumRequestMsg=========================

func decodeDatumRequestMsg(msg networking.ReceivedMessageData) (DatumRequestMsg, error) {
	if err := basicValidation(msg); err != nil {
		return DatumRequestMsg{}, err
	}
	if msg.Length < message_manager.HASH_LENGTH {
		return DatumRequestMsg{}, decoderError("invalid root hash")
	}

	return DatumRequestMsg{
		UnsignedMessage: newUnsignedMessage(msg),
		Hash:            message_manager.Hash(msg.Data[:message_manager.HASH_LENGTH]),
	}, nil
}

// =============================DatumMsg============================

func decodeDatumMsg(msg networking.ReceivedMessageData) (DatumMsg, error) {
	if err := basicValidation(msg); err != nil {
		return DatumMsg{}, err
	}
	if msg.Length < message_manager.HASH_LENGTH {
		return DatumMsg{}, decoderError("invalid root hash")
	}

	return DatumMsg{
		UnsignedMessage: newUnsignedMessage(msg),
		Hash:            message_manager.Hash(msg.Data[:message_manager.HASH_LENGTH]),
	}, nil
}

// =============================NoDatumMsg============================

func decodeNoDatumMsg(msg networking.ReceivedMessageData) (NoDatumMsg, error) {
	if err := basicValidation(msg); err != nil {
		return NoDatumMsg{}, err
	}
	if msg.Length < message_manager.HASH_LENGTH {
		return NoDatumMsg{}, decoderError("invalid root hash")
	}
	signature, err := getSignature(msg)
	if err != nil {
		return NoDatumMsg{}, err
	}

	return NoDatumMsg{
		SignedMessage: newSignedMessage(msg, signature),
		Hash:          message_manager.Hash(msg.Data[:message_manager.HASH_LENGTH]),
	}, nil
}

// TODO(sormys) add NatTraversal messages
