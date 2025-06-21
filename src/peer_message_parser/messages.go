package peer_message_parser

import (
	"crypto/ecdsa"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/handler"
	"mimuw_zps/src/merkle_tree"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/utility"
	"net"
)

const EXTENSIONS_LEN = 4

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
	return encryption.VerifySignature(sm.raw[:networking.MIN_MESSAGE_SIZE+sm.length], sm.Signature, publicKey)
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

// ========================HelloReplyMsg============================

type HelloReplyMsg struct {
	SignedMessage
	Extensions Extensions
	Name       string
}

func (hrm HelloReplyMsg) Type() networking.MessageType {
	return networking.HELLO_REPLY
}

// ========================RootRequestMsg===========================

type RootRequestMsg struct {
	UnsignedMessage
}

func (rr RootRequestMsg) Type() networking.MessageType {
	return networking.ROOT_REQUEST
}

// =========================RootReplyMsg============================

type RootReplyMsg struct {
	SignedMessage
	Hash handler.Hash
}

func (rr RootReplyMsg) Type() networking.MessageType {
	return networking.ROOT_REPLY
}

// =========================DatumRequestMsg=========================

type DatumRequestMsg struct {
	UnsignedMessage
	Hash handler.Hash
}

func (dr DatumRequestMsg) Type() networking.MessageType {
	return networking.DATUM_REQUEST
}

// =============================DatumMsg============================

const MAX_CHUNK_SIZE = 1024
const DIR_MAX_ENTRIES = 16
const DIR_ENTRY_SIZE = 64
const DIR_HALF_ENTRY = 32
const BIG_MAX_ENTRIES = 16
const BIG_ENTRY_SIZE = 32
const BIG_MIN_ENTRY_SIZE = 2

// Data is only available if node type is chunk, children available otherwise
type DatumMsg struct {
	UnsignedMessage
	Hash     handler.Hash
	NodeType merkle_tree.NodeType
	Data     []byte
	Children merkle_tree.DirectoryRecords
}

func (dr DatumMsg) Type() networking.MessageType {
	return networking.DATUM
}

// =============================NoDatumMsg============================

type NoDatumMsg struct {
	SignedMessage
	Hash handler.Hash
}

func (dr NoDatumMsg) Type() networking.MessageType {
	return networking.NO_DATUM
}

func GetExtensions() Extensions {
	return Extensions{0x00, 0x00, 0x00, 0x00}
}

// TODO(sormys) add NatTraversal messages
