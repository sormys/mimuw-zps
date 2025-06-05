package main

import (
	"errors"
	"log"
	"mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/networking/connection_manager"
	"mimuw_zps/src/networking/packet_manager"
	"mimuw_zps/src/networking/peer_conn"
	"mimuw_zps/src/networking/srv_conn"
	"net"
)

func tuiManager(received <-chan message_manager.TuiMessage,
	sender <-chan message_manager.TuiMessage) {

}
func ifEmptyReceivedData(data message_manager.TuiMessage) bool

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
					data = connection_manager.StartConnection(conn, message.Payload().(peer_conn.Peer).Addresses)
				}

			case message_manager.RELOAD_PEERS:
				{
					data = connection_manager.ReloadAvailablePeers(server)
				}
			case message_manager.RELOAD_CONTENT:
				{
					data = connection_manager.ReloadPeerContent(conn, message.Payload().(message_manager.TuiMessageBasicInfo))
				}

			case message_manager.DOWNLOAD:
				{
					data = connection_manager.DownloadFileFromPeer(conn, message.Payload().(message_manager.TuiMessageBasicInfo))
				}
			}
			if err != nil {
				tuiSender <- message_manager.ConvertErrorToTuiMessage(err)

			}
			if ifEmptyReceivedData(data) {
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
				err = connection_manager.SendHelloReply(conn, data, server)

			default:
				err = errors.New("Unknown Message Type " + data.MessType + " from address " + data.Addr.String())
			}

			if err != nil {
				tuiSender <- message_manager.ConvertErrorToTuiMessage(err)
			}
		}(data)
	}
}
func main() {

	waiterCount := uint32(1)
	senderCount := uint32(1)
	channel_size := 10
	receiverCount := uint32(1)
	myAddress := ":0"
	server_url := "https://galene.org:8448"
	myReceiverCount := 1
	nickname := "parowkozerca"

	server := srv_conn.NewServer(server_url)

	addr, err := net.ResolveUDPAddr("udp4", myAddress)

	if err != nil {
		log.Fatal("Failed to Resolve address", err)
	}

	conn, err := packet_manager.StartPacketManager(addr, senderCount, waiterCount, receiverCount)

	if err != nil {
		log.Fatal("Failed to set up the program", err)
	}

	channelToSend := make(chan message_manager.TuiMessage, channel_size)
	receiveFromTui := make(chan message_manager.TuiMessage, channel_size)

	go tuiManager(channelToSend, receiveFromTui)
	go handleUserCommand(conn, channelToSend, receiveFromTui, server)

	for range myReceiverCount {
		go handlerReceiver(conn, channelToSend, server)
	}

	err = server.ConnectWithServer(nickname, addr)
	if err != nil {
		log.Fatal("Failed to connect to the server " + err.Error())
	}

	peers, errArray := server.GetInfoPeers()

	channelToSend <- message_manager.ConvertErrorsToTuiMessage(errArray)
	channelToSend <- message_manager.CreateListPeers(peers)

	select {}

}
