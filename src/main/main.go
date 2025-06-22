package main

import (
	"log"
	"log/slog"
	"mimuw_zps/src/merkle_tree"
	"mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking/handlers"
	"mimuw_zps/src/networking/packet_manager"
	"mimuw_zps/src/networking/srv_conn"
	"mimuw_zps/src/tui"
	"net"
	"os"

	"github.com/lmittmann/tint"
)

var nickname string

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
	n := "Urwipołeć śmierdzący groszem"

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

	go handlers.RunUserRequestHandler(conn, receiveFromTui, channelToSend, server, nickname)
	go handlers.RunPeerRequestHandler(conn, channelToSend, server, nickname)
	go handlers.RunAutoRefreshConnections(conn)

	slog.Debug("Trying to connect to server...", "nickname", nickname)
	err = server.ConnectWithServer(nickname, conn)
	if err != nil {
		log.Fatal("Failed to connect to the server " + err.Error())
	}
	slog.Debug("Successfully connected with server")
	peers, errArray := server.GetInfoPeers()

	channelToSend <- message_manager.ConvertErrorsToTuiMessage(errArray)
	channelToSend <- message_manager.CreateListPeers(peers)

	path, ok := merkle_tree.GetMerkleeDirectory()
	if !ok {
		log.Fatal("Problem with init Merkle tree")
	}
	err = merkle_tree.InitMerkleTree(path)
	if err != nil {
		log.Fatal("Failed to create Merkle Tree", err)
	}
	tui.TuiManager(channelToSend, receiveFromTui, peers)
}
