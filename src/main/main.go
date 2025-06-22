package main

import (
	"flag"
	"io"
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
	"strings"

	"github.com/lmittmann/tint"
)

var nickname string

func parseLogLevel(levelStr string) slog.Level {
	levelStr = strings.ToUpper(levelStr)
	switch levelStr {
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		slog.Warn("Unknown log level, using INFO", "level", levelStr)
		return slog.LevelInfo
	}
}

func setupLogger(logLevel slog.Level, writer io.Writer) {
	slog.SetDefault(slog.New(
		tint.NewHandler(writer, &tint.Options{
			Level: logLevel,
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
	var (
		logLevelFlag  = flag.String("log-level", "DEBUG", "Log level (DEBUG, INFO, WARN, ERROR)")
		nicknameFlag  = flag.String("nickname", "Belmondo", "Your nickname for the peer network")
		logToFileFlag = flag.Bool("log-to-file", false, "Log to file app.log instead of stderr")
	)
	flag.Parse()

	logLevel := parseLogLevel(*logLevelFlag)
	var logWriter io.Writer
	if *logToFileFlag {
		var err error
		logWriter, err = os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatal("Failed to open log file:", err)
		}
	} else {
		logWriter = os.Stderr
	}
	setupLogger(logLevel, logWriter)

	waiterCount := uint32(2)
	senderCount := uint32(2)
	channel_size := 10
	receiverCount := uint32(2)
	myAddress := ":0"
	server_url := "https://galene.org:8448"

	server := srv_conn.NewServer(server_url)

	nickname = *nicknameFlag
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
