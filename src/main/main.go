package main

import (
	"errors"
	"log"
	"log/slog"
	"mimuw_zps/src/handler"
	"mimuw_zps/src/merkle_tree"
	"mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking"
	cm "mimuw_zps/src/networking/handlers"
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
		Expanded:   false,
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

func handlerReceiver(conn packet_manager.PacketConn, tuiSender chan<- message_manager.TuiMessage, server srv_conn.Server) {
	var err error
	for {
		// I am not sure if this solution is safe, when we get a lots of requests
		data := conn.RecvRequest()
		go func(data networking.ReceivedMessageData) {
			switch data.MessType {

			case networking.DATUM_REQUEST:
				// we have to manage with which users we can talk, because there are after handshake. We can send data to someone with whom we are not conencted
				err = cm.SendData(conn, data)

			case networking.ROOT_REQUEST:
				err = cm.SendRootReply(conn, data)

			case networking.HELLO:
				err = cm.SendHelloReply(conn, data, server, nickname)

			case networking.PING:
				//Do sth with ping
			default:
				err = errors.New("Unknown Message Type " + data.MessType + " from address " + data.Addr.String())
			}

			if err != nil {
				cm.SendErrorReply(conn, data.Addr, err)
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
	path := "../../root"
	myReceiverCount := 1
	n := "schabowy"

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

	go cm.RunUserRequestHandler(conn, receiveFromTui, channelToSend, server, nickname)

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

	err = merkle_tree.InitMerkleTree(path)
	slog.Debug("Merkle tree root", "root", merkle_tree.GetRoot())
	if err != nil {
		log.Fatal("Failed to create Merkle Tree", err)
	}
	tui.TuiManager(channelToSend, receiveFromTui, peers)
}
