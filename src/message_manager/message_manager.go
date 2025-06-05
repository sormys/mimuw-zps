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
	INFO           = RequestTuiType("connect")
	RELOAD_CONTENT = RequestTuiType("reload_content")
	RELOAD_PEERS   = RequestTuiType("reload_peers")
	DOWNLOAD       = RequestTuiType("sent")
	PEERS          = RequestTuiType("peers")
	CONNECT        = RequestTuiType("connect")
)

type Hash = [HASH_LENGTH]byte

type TuiMessage interface {
	//User    peer_conn.Peer
	Payload() any
	// Hash        encryption.Message123
	RequestType() RequestTuiType
}

type TuiMessageInfo struct {
}

type TuiMessageBasicInfo struct {
}

type TuiMessageContent struct {
}

type BasicFileInfo struct {
	Hash Hash
	Peer peer_conn.Peer
}

func (s *TuiMessageInfo) Payload() string             { return "test" }
func (s *TuiMessageInfo) RequestType() RequestTuiType { return "test2" }

func (s *TuiMessageBasicInfo) Payload() BasicFileInfo      { return BasicFileInfo{} }
func (s *TuiMessageBasicInfo) RequestType() RequestTuiType { return "test2" }

func ConvertErrorToTuiMessage(err error) TuiMessage
func ConvertErrorsToTuiMessage(err []error) TuiMessage
func CreateTuiMessageTypeBasicInfo(hash Hash, peer peer_conn.Peer) TuiMessage
func CreateListPeers(peers []peer_conn.Peer) TuiMessage
func ConvertReceivedMessageDataToTuiMessage(data networking.ReceivedMessageData) TuiMessage
func CreateTuiMessageInfo(info string, description string) TuiMessage
