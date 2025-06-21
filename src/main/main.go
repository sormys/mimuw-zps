package main

import (
	"log"
	"log/slog"
	"mimuw_zps/src/merkle_tree"
	"mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking"
	cm "mimuw_zps/src/networking/handlers"
	"mimuw_zps/src/networking/packet_manager"
	"mimuw_zps/src/networking/srv_conn"
	pmp "mimuw_zps/src/peer_message_parser"
	"mimuw_zps/src/tui"
	"net"
	"os"

	"github.com/lmittmann/tint"
)

var nickname string

func handlerReceiver(conn packet_manager.PacketConn, tuiSender chan<- message_manager.TuiMessage, server srv_conn.Server) {
	for {
		// I am not sure if this solution is safe, when we get a lots of requests
		data := conn.RecvRequest()
		decoded, err := pmp.DecodeMessage(data)
		go func(data networking.ReceivedMessageData) {
			switch msg := decoded.(type) {
			case pmp.HelloMsg:
				err = cm.HandleHello(conn, data.Addr, msg, server, nickname)
			case pmp.RootRequestMsg:
				err = cm.HandleRootRequest(conn, data.Addr, msg)
			case pmp.DatumRequestMsg:
				err = cm.HandleDatumRequest(conn, data.Addr, msg)
			case pmp.PingMsg:
				err = cm.HandlePing(conn, data.Addr, msg)
			default:
				slog.Warn("Currently no handler for request of type", "type", msg.Type())
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
