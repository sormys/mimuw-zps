package peer_message_parser

import (
	"crypto/ecdsa"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/utility"
	"net"
)

const EXTENSIONS_LEN = 32

type Extensions [EXTENSIONS_LEN]byte

type PeerMessage interface {
	Raw() encryption.Message
	Type() networking.MessageType
	Sender() net.Addr
	ID() utility.ID
	VerifySignature(*ecdsa.PublicKey) bool
}

// ===========================BaseMessage===========================

type BaseMessage struct {
	addr   net.Addr
	id     utility.ID
	length uint16
	raw    []byte
}

func (bm BaseMessage) Raw() encryption.Message {
	return bm.raw
}

func (bm BaseMessage) Sender() net.Addr {
	return bm.addr
}

func (bm BaseMessage) ID() utility.ID {
	return bm.id
}

// ==========================UnsignedMessage========================

type UnsignedMessage struct {
	BaseMessage
}

func (um UnsignedMessage) VerifySignature(publicKey *ecdsa.PublicKey) bool {
	return true
}

// ==========================SignedMessage==========================

type SignedMessage struct {
	BaseMessage
	Signature encryption.Key
}

func (sm SignedMessage) VerifySignature(publicKey *ecdsa.PublicKey) bool {
	return encryption.VerifySignature(sm.raw[:networking.MIN_HELLO_SIZE+sm.length], sm.Signature, publicKey)
}

// ============================PingMsg==============================

type PingMsg struct {
	UnsignedMessage
}

func (p PingMsg) Type() networking.MessageType {
	return networking.PING
}

// ============================PongMsg==============================

type PongMsg struct {
	UnsignedMessage
}

func (p PongMsg) Type() networking.MessageType {
	return networking.PONG
}

// ===========================ErrorMsg==============================

type ErrorMsg struct {
	UnsignedMessage
	Message string
}

func (em ErrorMsg) Type() networking.MessageType {
	return networking.ERROR
}

// ===========================HelloMsg==============================

type HelloMsg struct {
	SignedMessage
	Extensions Extensions
	Name       string
}

func (hm HelloMsg) Type() networking.MessageType {
	return networking.HELLO
}

func (hm HelloMsg) VerifySignature(publicKey *ecdsa.PublicKey) bool {
	return encryption.VerifySignature(hm.raw[:networking.MIN_HELLO_SIZE+hm.length], hm.Signature, publicKey)
}

// ========================HelloReplyMsg============================

type HelloReplyMsg struct {
	SignedMessage
	Extensions Extensions
	Name       string
}

func (hrm HelloReplyMsg) Type() networking.MessageType {
	return networking.HELLO_REPLY
}

func (hrm HelloReplyMsg) VerifySignature(publicKey *ecdsa.PublicKey) bool {
	return encryption.VerifySignature(hrm.raw[:networking.MIN_HELLO_SIZE+hrm.length], hrm.Signature, publicKey)
}

// ========================RootRequestMsg===========================

type RootRequestMsg struct {
	SignedMessage
}

func (rr RootRequestMsg) Type() networking.MessageType {
	return networking.ROOT_REQUEST
}

// =========================RootReplyMsg============================

type RootReplyMsg struct {
	SignedMessage
	Hash message_manager.Hash
}

func (rr RootReplyMsg) Type() networking.MessageType {
	return networking.ROOT_REPLY
}

// =========================DatumRequestMsg=========================

type DatumRequestMsg struct {
	UnsignedMessage
	Hash message_manager.Hash
}

func (dr DatumRequestMsg) Type() networking.MessageType {
	return networking.DATUM_REQUEST
}

// =============================DatumMsg============================

type DatumMsg struct {
	UnsignedMessage
	Hash message_manager.Hash
}

func (dr DatumMsg) Type() networking.MessageType {
	return networking.DATUM
}

// =============================NoDatumMsg============================

type NoDatumMsg struct {
	SignedMessage
	Hash message_manager.Hash
}

func (dr NoDatumMsg) Type() networking.MessageType {
	return networking.NO_DATUM
}

// TODO(sormys) add NatTraversal messages
