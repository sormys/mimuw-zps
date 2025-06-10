package message_manager

import (
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

const (
	INFO_TUI  = RequestTuiType("INFO_TUI")
	ERROR_TUI = RequestTuiType("ERROR_TUI")
	PEERS_TUI = RequestTuiType("PEERS_TUI")
)

type TuiMessage interface {
	Payload() any
	RequestType() RequestTuiType
}

// Displays all errors and info messages in the TUI
type TuiMessageInfo struct {
	Notification RequestTuiType
	Description  []string
}

// Contains a Peer and a Hash. Behavior depends on the RequestTuiType:
// It may be used to connect, downlaod data, or retrieve peer information
type TuiMessageBasicInfo struct {
	Notification RequestTuiType
	FileInfo     BasicFileInfo
}

type TuiMessagePeers struct {
	Notification RequestTuiType
	Peers        []peer_conn.Peer
}

type BasicFileInfo struct {
	Hash Hash
	Peer peer_conn.Peer
}

func newBasicFileInfo(hash Hash, peer peer_conn.Peer) BasicFileInfo {
	return BasicFileInfo{Hash: hash, Peer: peer}
}

func (s *TuiMessageInfo) Payload() any                { return s.Description }
func (s *TuiMessageInfo) RequestType() RequestTuiType { return s.Notification }

func (s *TuiMessageBasicInfo) Payload() any                { return s.FileInfo }
func (s *TuiMessageBasicInfo) RequestType() RequestTuiType { return s.Notification }

func (s *TuiMessagePeers) Payload() any                { return s.Peers }
func (s *TuiMessagePeers) RequestType() RequestTuiType { return s.Notification }

func ConvertErrorToTuiMessage(err error) TuiMessage {
	return &TuiMessageInfo{
		Notification: ERROR_TUI,
		Description:  []string{err.Error()},
	}
}

func ConvertErrorsToTuiMessage(err []error) TuiMessage {
	description := make([]string, len(err))
	for i := range err {
		description[i] = err[i].Error()
	}

	return &TuiMessageInfo{
		Notification: ERROR_TUI,
		Description:  description,
	}
}

func CreateTuiMessageTypeBasicInfo(hash Hash, peer peer_conn.Peer) TuiMessage {
	return &TuiMessageBasicInfo{
		Notification: ERROR_TUI,
		FileInfo:     newBasicFileInfo(hash, peer),
	}
}

func CreateListPeers(peers []peer_conn.Peer) TuiMessage {
	return &TuiMessagePeers{
		Notification: PEERS_TUI,
		Peers:        peers,
	}
}

func CreateTuiMessageInfo(requestType RequestTuiType, description string) TuiMessage {
	return &TuiMessageInfo{
		Notification: requestType,
		Description:  []string{description},
	}
}

func IsEmpty(data TuiMessage) bool {
	if data == nil {
		return true
	}

	return data.RequestType() == ""
}

func CreateEmptyMessageInfo() TuiMessage {
	return &TuiMessageInfo{
		Notification: "",
		Description:  []string{},
	}
}
