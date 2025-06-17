package message_manager

import (
	"mimuw_zps/src/handler"
	"mimuw_zps/src/networking/peer_conn"
)

type RequestTuiType = string

const (
	INFO_TUI       RequestTuiType = "INFO_TUI"
	ERROR_TUI      RequestTuiType = "ERROR_TUI"
	PEERS_TUI      RequestTuiType = "PEERS_TUI"
	FOLDER_TUI     RequestTuiType = "FOLDER_TUI"
	FILE_TUI       RequestTuiType = "FILE_TUI"
	EXPAND_FOLDER  RequestTuiType = "EXPAND_FOLDER"
	CONNECT        RequestTuiType = "CONNECT"
	SHOW_DATA      RequestTuiType = "SHOW_DATA"
	DOWNLOAD       RequestTuiType = "DOWNLOAD"
	RELOAD_CONTENT RequestTuiType = "RELOAD_CONTENT"
)

type TUIFolder struct {
	Hash       handler.Hash
	Name       string
	Path       string
	Files      []handler.File
	Subfolders []TUIFolder
	Loaded     bool
	Expanded   bool
}

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

type TuiMessageFolder struct {
	Notification RequestTuiType
	Folder       TUIFolder
}

type TuiMessageFile struct {
	Notification RequestTuiType
	File         handler.File
}

type TuiMessagePeers struct {
	Notification RequestTuiType
	Peers        []peer_conn.Peer
}

type BasicFileInfo struct {
	Hash handler.Hash
	Peer peer_conn.Peer
}

type BasicFolder struct {
	Path string
	Name string
	Hash handler.Hash
	Peer peer_conn.Peer
}

type ExpandFolderInfo struct {
	Notification RequestTuiType
	Info         BasicFolder
}

func (s *TuiMessageInfo) Payload() any                { return s.Description }
func (s *TuiMessageInfo) RequestType() RequestTuiType { return s.Notification }

func (s *TuiMessageBasicInfo) Payload() any                { return s.FileInfo }
func (s *TuiMessageBasicInfo) RequestType() RequestTuiType { return s.Notification }

func (s *TuiMessagePeers) Payload() any                { return s.Peers }
func (s *TuiMessagePeers) RequestType() RequestTuiType { return s.Notification }

func (s *TuiMessageFolder) Payload() any                { return s.Folder }
func (s *TuiMessageFolder) RequestType() RequestTuiType { return s.Notification }

func (s *TuiMessageFile) Payload() any                { return s.File }
func (s *TuiMessageFile) RequestType() RequestTuiType { return s.Notification }

func (s *ExpandFolderInfo) Payload() any                { return s.Info }
func (s *ExpandFolderInfo) RequestType() RequestTuiType { return s.Notification }

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

func CreateTuiMessageTypeBasicInfo(hash handler.Hash, peer peer_conn.Peer) TuiMessage {
	return &TuiMessageBasicInfo{
		Notification: ERROR_TUI,
		FileInfo:     BasicFileInfo{Hash: hash, Peer: peer},
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

func InitConnectionMessage(peer peer_conn.Peer) TuiMessage {
	return &TuiMessagePeers{
		Notification: CONNECT,
		Peers:        []peer_conn.Peer{peer},
	}
}

func InitGetDataMessage(peer peer_conn.Peer) TuiMessage {
	return &TuiMessagePeers{
		Notification: SHOW_DATA,
		Peers:        []peer_conn.Peer{peer},
	}
}

func CreateTuiFolders(folder TUIFolder) TuiMessage {
	return &TuiMessageFolder{
		Notification: FOLDER_TUI,
		Folder:       folder,
	}
}
func ExpandFolder(path string, peer peer_conn.Peer, name string, hash handler.Hash) TuiMessage {
	return &ExpandFolderInfo{
		Notification: EXPAND_FOLDER,
		Info:         BasicFolder{Path: path, Peer: peer, Name: name, Hash: hash},
	}
}
func DownloadFile(hash handler.Hash, peer peer_conn.Peer) TuiMessage {
	return &TuiMessageBasicInfo{
		Notification: DOWNLOAD,
		FileInfo:     BasicFileInfo{Hash: hash, Peer: peer},
	}
}
func ReloadContent() TuiMessage {
	return &TuiMessageInfo{
		Notification: RELOAD_CONTENT,
		Description:  []string{},
	}
}
func SetDownloadInfo(file handler.File) TuiMessage {
	return &TuiMessageFile{
		Notification: FILE_TUI,
		File:         file,
	}
}

func TuiError(content string) TuiMessage {
	return CreateTuiMessageInfo(ERROR_TUI, content)
}

func TuiInfo(content string) TuiMessage {
	return CreateTuiMessageInfo(INFO_TUI, content)
}
