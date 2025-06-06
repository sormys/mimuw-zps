package connection_manager

import (
	"log/slog"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/networking/packet_manager"
	"mimuw_zps/src/networking/srv_conn"
	"mimuw_zps/src/utility"
	"net"
)

func sendErrorReply(conn packet_manager.PacketConn, addr net.Addr, err error) {
	conn.SendRequest(createErrorReply(addr, err))
}
func sendDatumRequest(conn packet_manager.PacketConn, addr []net.Addr, hash message_manager.Hash) (networking.ReceivedMessageData, message_manager.TuiMessage) {
	id := utility.GenerateID()
	for _, address := range addr {
		outgoingMessage := createDatumRequest(address, hash)
		receivedData := conn.SendRequest(outgoingMessage)

		if receivedData.MessType != networking.NO_DATUM {
			return networking.ReceivedMessageData{},
				message_manager.CreateTuiMessageInfo(message_manager.ERROR_TUI, "User does not have data with this hash")
		}
		if verifyIdAndType(receivedData, id, networking.DATUM_REQUEST) {
			return receivedData, message_manager.CreateEmptyMessageInfo()
		}
	}
	return networking.ReceivedMessageData{},
		message_manager.CreateTuiMessageInfo(message_manager.ERROR_TUI, "User responded with error or did not respond")

}

func sendRootRequest(conn packet_manager.PacketConn, addr []net.Addr) (networking.ReceivedMessageData, message_manager.TuiMessage) {
	id := utility.GenerateID()
	for _, address := range addr {
		outgoingMessage := createRootRequest(address, id)
		receivedData := conn.SendRequest(outgoingMessage)
		if verifyIdAndType(receivedData, id, networking.ROOT_REQUEST) {
			return receivedData, message_manager.CreateEmptyMessageInfo()
		}

	}
	return networking.ReceivedMessageData{}, message_manager.CreateTuiMessageInfo(message_manager.ERROR_TUI, "None of peers responds")
}

// func StartConnection(conn packet_manager.PacketConn, addresses []string) TuiNotification {
func StartConnection(conn packet_manager.PacketConn, addresses []net.Addr, nickname string) message_manager.TuiMessage {
	for _, addr := range addresses {
		id := utility.GenerateID()
		message := CreateHandshake(addr, id, nickname)
		info := conn.SendRequest(message)
		if verifyIdAndType(info, id, networking.HELLO_REPLY) {
			return message_manager.CreateTuiMessageInfo(message_manager.INFO_TUI, "Successfully connected to address "+addr.String())
		}

	}

	return message_manager.CreateTuiMessageInfo(message_manager.ERROR_TUI, "Cannot connect to any of these addresses"+printAddreses(addresses))

}

func SendHelloReply(conn packet_manager.PacketConn, data networking.ReceivedMessageData, server srv_conn.Server, nickname string) error {
	key, err := server.GetPeerKey(getNameFromReceivedHandshake(data.Data))

	if err != nil {
		slog.Error("Failed to get peer key", "error", err)
		return err
	}

	if !encryption.VerifySignature(data.Data, getSignatureFromReceivedHandshake(data.Data), encryption.ParsePublicKey(key)) {
		sendErrorReply(conn, data.Addr, err)
	}
	conn.SendReply(createHandshakeReply(data.Addr, data.ID, nickname))
	return nil
}

func ReloadPeerContent(conn packet_manager.PacketConn, message message_manager.TuiMessageBasicInfo) message_manager.TuiMessage {
	peer := message.FileInfo.Peer
	receivedData, info := sendRootRequest(conn, peer.Addresses)
	if !message_manager.IsEmpty(info) {
		return info
	}

	return message_manager.CreateTuiMessageTypeBasicInfo(getHashFromRootReply(receivedData), peer)

}

func ReloadAvailablePeers(server srv_conn.Server) message_manager.TuiMessage {
	peers, err := server.GetInfoPeers()
	if err != nil {
		return message_manager.ConvertErrorsToTuiMessage(err)
	}
	return message_manager.CreateListPeers(peers)
}

// func DownloadFileFromPeer(conn packet_manager.PacketConn, message message_manager.TuiMessageBasicInfo) TuiNotification {
func DownloadFileFromPeer(conn packet_manager.PacketConn, message message_manager.TuiMessageBasicInfo) message_manager.TuiMessage {
	fileInfo := message.FileInfo
	receivedInfoDatum, err := sendDatumRequest(conn, fileInfo.Peer.Addresses, fileInfo.Hash)
	if !message_manager.IsEmpty(err) {
		return err
	}
	_ = receivedInfoDatum
	//TODO
	//manage received data and do something with them. Temporary dunno what

	return message_manager.CreateTuiMessageInfo(message_manager.INFO_TUI, "Successfully downloaded data from "+fileInfo.Peer.Name+"")
}

// TODO
// Someome ask us to send data
func SendData(conn packet_manager.PacketConn, data networking.ReceivedMessageData) error

// TODO
// Someone ask us about our hash
func SendRootReply(conn packet_manager.PacketConn, data networking.ReceivedMessageData) error
