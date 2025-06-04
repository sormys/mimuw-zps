package main

import (
	"errors"
	"log"
	"mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking"
	connection_manager "mimuw_zps/src/networking/connection"
	"mimuw_zps/src/networking/packet_manager"
	"mimuw_zps/src/networking/peer_conn"
	"mimuw_zps/src/networking/srv_conn"
	"net"
)

func tuiManager(received <-chan message_manager.TuiMessage,
	sender <-chan message_manager.TuiMessage) {

}

func handleUserCommand(conn packet_manager.PacketConn,
	tuiReceiver <-chan message_manager.TuiMessage,
	tuiSender chan<- message_manager.TuiMessage) {
	var data networking.ReceivedMessageData
	for message := range tuiReceiver {
		go func(message message_manager.TuiMessage) {
			switch message.RequestType() {
			case message_manager.CONNECT:
				{
					data = connection_manager.StartConnection(conn, message.Payload().(peer_conn.Peer).Addresses)
				}

			case message_manager.RELOAD:
				{
					data = connection_manager.ReloadContent(conn, message)
				}

			case message_manager.DOWNLOAD:
				{
					data = connection_manager.SendMessage(conn, message)
				}
			}
			tuiSender <- message_manager.ConvertReceivedMessageDataToTuiMessage(data)
		}(message)

	}
}

func handlerReceiver(conn packet_manager.PacketConn, tuiSender chan<- message_manager.TuiMessage) {
	var err error
	for {
		// I am not sure if this solution is safe, when we get a lots of requests
		data := conn.RecvRequest()
		go func(data networking.ReceivedMessageData) {
			switch data.MessType {
			case networking.DATUM_REQUEST:
				err = connection_manager.SendData(conn, data)

			case networking.ROOT_REQUEST:
				err = connection_manager.SendRoot(conn, data)

			case networking.HELLO:
				err = connection_manager.SendHello(conn, data)

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
	attempts := 4
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
	go handleUserCommand(conn, channelToSend, receiveFromTui)

	for range myReceiverCount {
		go handlerReceiver(conn, channelToSend)
	}

	err = server.ConnectWithServer(attempts, conn, nickname)
	if err != nil {
		log.Fatal("Tried to connect to the server %d times, but all attempts failed", attempts, err)
	}

	peers, err := server.GetInfoPeers()
	channelToSend <- message_manager.CreateListPeers(peers)

	select {}

}
