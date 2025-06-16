package main

import (
	"errors"
	"log"
	"log/slog"
	"mimuw_zps/src/handler"
	"mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/networking/connection_manager"
	"mimuw_zps/src/networking/packet_manager"
	"mimuw_zps/src/networking/peer_conn"
	"mimuw_zps/src/networking/srv_conn"
	"mimuw_zps/src/tui"
	"net"
	"os"

	"github.com/lmittmann/tint"
)

var nickname string

func connect(peer peer_conn.Peer) message_manager.TuiMessage {
	return message_manager.InitConnectionMessage(peer)
}

// example expected output
func buildSampleTree() message_manager.TUIFolder {
	file := func(name string) handler.File {
		return handler.File{Name: name}
	}

	files1 := []handler.File{file("first.txt"), file("second.txt")}
	files2 := []handler.File{file("third.txt"), file("fourth.txt")}
	files3 := []handler.File{file("fifth.txt"), file("sixth.txt")}

	subfolderOfFolder2 := message_manager.TUIFolder{
		Name:     "trzeci",
		Path:     "root/drugi/trzeci",
		Files:    files3,
		Loaded:   true,
		Expanded: false,
	}

	folder2 := message_manager.TUIFolder{
		Name:       "drugi",
		Path:       "root/drugi",
		Files:      files2,
		Subfolders: []message_manager.TUIFolder{subfolderOfFolder2},
		Loaded:     false,
		Expanded:   false,
	}

	folder4 := message_manager.TUIFolder{
		Name:       "czwarty",
		Path:       "root/czwarty",
		Files:      nil,
		Subfolders: nil,
		Loaded:     false,
		Expanded:   false,
	}

	folder1 := message_manager.TUIFolder{
		Name:       "pierwszy",
		Path:       "root",
		Files:      files1,
		Subfolders: []message_manager.TUIFolder{folder2, folder4},
		Loaded:     false,
		Expanded:   true,
	}

	return folder1
}

func showFiles() message_manager.TuiMessage {
	folder := buildSampleTree()
	return message_manager.CreateTuiFolders(folder)
}

// Example how to expand Folder
func expandFolder(info message_manager.BasicFolder) message_manager.TuiMessage {
	path := info.Path
	files := []handler.File{
		{Name: "kotki.jpg"},
		{Name: "dowody zbrodni wojennych"},
	}

	subfolders := []message_manager.TUIFolder{
		{Name: "piffko", Path: path + "/piffko"},
		{Name: "tyskie", Path: path + "/tyskie"},
	}

	folder := message_manager.TUIFolder{
		Name:       info.Name,
		Path:       path,
		Files:      files,
		Subfolders: subfolders,
		Loaded:     true,
		Expanded:   true,
	}
	return message_manager.CreateTuiFolders(folder)

}

func handleUserCommand(conn packet_manager.PacketConn,
	tuiReceiver <-chan message_manager.TuiMessage,
	tuiSender chan<- message_manager.TuiMessage,
	server srv_conn.Server) {
	var data message_manager.TuiMessage
	var err error
	for message := range tuiReceiver {
		go func(message message_manager.TuiMessage) {
			switch message.RequestType() {
			case message_manager.CONNECT:
				{
					// Expected output is peer when after successful handshake. You can use
					// message_manager.InitConnectionMessage(peer)

					data = connect(message.Payload().([]peer_conn.Peer)[0])
					//data = connection_manager.StartConnection(conn, message.Payload().([]peer_conn.Peer)[0], nickname)
				}

			case message_manager.RELOAD_CONTENT:
				{
					data = connection_manager.ReloadAvailablePeers(server)

					// in this state handler should reset all his states!
				}

			case message_manager.DOWNLOAD:
				{
					// message.Payload().(BasicFileInfo) -> {Peer: peer, Hash: hash}
					// In this case we want download file from peer with hash. Expected output should be TUIMessage
					// with INFO_TUI when download finished successful or ERROR_TUI with list of error

					data = message_manager.CreateTuiMessageInfo(message_manager.INFO_TUI, "pobrano bardzo ciekawe zdjęcie")
					// data = connection_manager.DownloadFileFromPeer(conn, message.Payload().(message_manager.TuiMessageBasicInfo))
				}
			case message_manager.EXPAND_FOLDER:
				{
					// In this case the folder's contens are not yet loaded in the TUI.
					// Check if the contents are available in the cache. If not,
					// send a request to fetch data. Expected output is TuiMessage -> see expandFolder

					// message.Payload().(BasicFolder) -> {Path: path, Peer: peer, Name: name, Hash: hash}
					data = expandFolder(message.Payload().(message_manager.BasicFolder))
				}
			case message_manager.SHOW_DATA:
				{
					// In this case we want discover user's file. So you have to sent RootRequest
					// user = message.Payload().([]peer_conn.Peer)[0]
					// Expected output is TuiMessage -> see expand Folder
					data = showFiles()
				}
			}
			if err != nil {
				tuiSender <- message_manager.ConvertErrorToTuiMessage(err)

			}
			if data != nil && !message_manager.IsEmpty(data) {
				// slog.Debug("Trying to send", "message", data)
				tuiSender <- data
			}
		}(message)

	}
}

func handlerReceiver(conn packet_manager.PacketConn, tuiSender chan<- message_manager.TuiMessage, server srv_conn.Server) {
	var err error
	for {
		// I am not sure if this solution is safe, when we get a lots of requests
		data := conn.RecvRequest()
		go func(data networking.ReceivedMessageData) {
			switch data.MessType {

			case networking.DATUM_REQUEST:
				// we have to manage with which users we can talk, because there are after handshake. We can send data to someone with whom we are not conencted
				err = connection_manager.SendData(conn, data)

			case networking.ROOT_REQUEST:
				err = connection_manager.SendRootReply(conn, data)

			case networking.HELLO:
				err = connection_manager.SendHelloReply(conn, data, server, nickname)

			default:
				err = errors.New("Unknown Message Type " + data.MessType + " from address " + data.Addr.String())
			}

			if err != nil {
				tuiSender <- message_manager.ConvertErrorToTuiMessage(err)
			}
		}(data)
	}
}

func setupLogger() {
	w := os.Stderr
	slog.SetDefault(slog.New(
		tint.NewHandler(w, &tint.Options{
			Level: slog.LevelDebug,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Value.Kind() == slog.KindAny {
					if _, ok := a.Value.Any().(error); ok {
						return tint.Attr(9, a)
					}
				}
				return a
			},
		})))
}

func main() {

	waiterCount := uint32(2)
	senderCount := uint32(2)
	channel_size := 10
	receiverCount := uint32(2)
	myAddress := ":0"
	server_url := "https://galene.org:8448"
	myReceiverCount := 1
	n := "parowkozerca"

	setupLogger()

	server := srv_conn.NewServer(server_url)

	nickname = n
	addr, err := net.ResolveUDPAddr("udp4", myAddress)

	if err != nil {
		log.Fatal("Failed to Resolve address", err)
	}

	slog.Debug("Resolved local address", "addr", addr.String())
	conn, err := packet_manager.StartPacketManager(addr, senderCount, waiterCount, receiverCount)

	if err != nil {
		log.Fatal("Failed to set up the program", err)
	}
	slog.Debug("Successfully started Packet Manager")

	channelToSend := make(chan message_manager.TuiMessage, channel_size)
	receiveFromTui := make(chan message_manager.TuiMessage, channel_size)

	go handleUserCommand(conn, receiveFromTui, channelToSend, server)

	for range myReceiverCount {
		go handlerReceiver(conn, channelToSend, server)
	}

	slog.Debug("Trying to connect to server...", "nickname", nickname)
	err = server.ConnectWithServer(nickname, conn)
	if err != nil {
		log.Fatal("Failed to connect to the server " + err.Error())
	}
	slog.Debug("Successfully connected with server")
	peers, errArray := server.GetInfoPeers()

	channelToSend <- message_manager.ConvertErrorsToTuiMessage(errArray)
	channelToSend <- message_manager.CreateListPeers(peers)

	tui.TuiManager(channelToSend, receiveFromTui, peers)
}
