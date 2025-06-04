package message_manager

import (
	"mimuw_zps/src/networking"
	"mimuw_zps/src/networking/peer_conn"
)

const HASH_LENGTH = 32

type RequestTuiType = string

type Download struct {
	Peer peer_conn.Peer
	Hash Hash
}

var (
	INFO     = RequestTuiType("connect")
	RELOAD   = RequestTuiType("reload")
	DOWNLOAD = RequestTuiType("sent")
	PEERS    = RequestTuiType("peers")
	CONNECT  = RequestTuiType("connect")
)

type Hash = [HASH_LENGTH]byte

type TuiMessage interface {
	//User    peer_conn.Peer
	Payload() any
	// Hash        encryption.Message
	RequestType() RequestTuiType
}

type TuiMessageEx struct {
}

func (s *TuiMessageEx) Payload() string { return "test" }

func (s *TuiMessageEx) RequestType() RequestTuiType { return "test2" }

func ConvertErrorToTuiMessage(err error) TuiMessage
func CreateListPeers(peers []peer_conn.Peer) TuiMessage
func ConvertReceivedMessageDataToTuiMessage(data networking.ReceivedMessageData) TuiMessage
