package connection_manager

import (
	"errors"
	"log/slog"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/handler"
	"mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/networking/packet_manager"
	"mimuw_zps/src/networking/peer_conn"
	"mimuw_zps/src/networking/srv_conn"
	"mimuw_zps/src/utility"
	"net"
)

func sendErrorReply(conn packet_manager.PacketConn, addr net.Addr, err error) {
	conn.SendReply(addr, createErrorReply(err))
}
func sendDatumRequest(conn packet_manager.PacketConn, addr []net.Addr, hash handler.Hash) (networking.ReceivedMessageData, message_manager.TuiMessage) {
	id := utility.GenerateID()
	for _, address := range addr {
		message := createDatumRequestTemplate(id, DATUM_REQUEST, hash)
		receivedData := conn.SendRequest(address, message, networking.NewRetryPolicyRequest())

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

// Sends a message of type RootRequest to all provided addresses. Stop automatically upon receiving a valid response
func sendRootRequest(conn packet_manager.PacketConn, addr []net.Addr) (networking.ReceivedMessageData, message_manager.TuiMessage) {
	id := utility.GenerateID()
	for _, address := range addr {
		message := createDatumRequestTemplate(id, ROOT_REQUEST, handler.Hash{})
		receivedData := conn.SendRequest(address, message, networking.NewRetryPolicyRequest())
		if verifyIdAndType(receivedData, id, networking.ROOT_REQUEST) {
			return receivedData, message_manager.CreateEmptyMessageInfo()
		}

	}
	return networking.ReceivedMessageData{}, message_manager.CreateTuiMessageInfo(message_manager.ERROR_TUI, "None of peers responds")
}

// Initiates communication with the peer whose addresses are provided
func StartConnection(conn packet_manager.PacketConn, peer peer_conn.Peer, nickname string) message_manager.TuiMessage {
	slog.Debug("Starting connection with", "message", peer.Name)
	addresses := peer.Addresses
	for _, addr := range addresses {
		id := utility.GenerateID()
		message := srv_conn.CreateHandshakeBytes(HELLO, nickname, id)
		info := conn.SendRequest(addr, message, networking.NewPolicyHandshake())
		if verifyIdAndType(info, id, networking.HELLO_REPLY) &&
			encryption.VerifySignature(info.Raw[:networking.MIN_HELLO_SIZE+info.Length], getSignatureFromReceivedHandshake(info), encryption.ParsePublicKey(peer.Key)) {
			return message_manager.CreateTuiMessageInfo(message_manager.INFO_TUI, "Successfully connected to address "+addr.String())
		}

	}

	return message_manager.CreateTuiMessageInfo(message_manager.ERROR_TUI, "Cannot connect to any of these addresses"+printAddreses(addresses))

}

func SendHelloReply(conn packet_manager.PacketConn, data networking.ReceivedMessageData, server srv_conn.Server, nickname string) error {
	slog.Debug("Responding to HELLO message", "id", data.ID, "addr", data.Addr)
	key, err := server.GetPeerKey(getNameFromReceivedHandshake(data))

	if err != nil {
		slog.Error("Failed to get peer key", "error", err)
		return err
	}

	if !encryption.VerifySignature(data.Raw[:networking.MIN_MESSAGE_SIZE+data.Length],
		getSignatureFromReceivedHandshake(data), encryption.ParsePublicKey(key)) {
		slog.Debug("Failed to verify signature")
		return errors.New("failed to verify signature in hello reply")
	}

	slog.Debug("Received correct Hello, sending reply")
	message := srv_conn.CreateHandshakeBytes(HELLO_REPLY, nickname, data.ID)
	conn.SendReply(data.Addr, message)
	return nil
}

// reloads all files associated with the provided peer in message
func ReloadPeerContent(conn packet_manager.PacketConn, message message_manager.TuiMessageBasicInfo) message_manager.TuiMessage {
	peer := message.FileInfo.Peer
	receivedData, info := sendRootRequest(conn, peer.Addresses)
	if !message_manager.IsEmpty(info) {
		return info
	}

	return message_manager.CreateTuiMessageTypeBasicInfo(getHashFromRootReply(receivedData), peer)

}

// return a list with available peers
func ReloadAvailablePeers(server srv_conn.Server) message_manager.TuiMessage {
	peers, err := server.GetInfoPeers()
	if err != nil {
		return message_manager.ConvertErrorsToTuiMessage(err)
	}
	return message_manager.CreateListPeers(peers)
}

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
// Respond to request for our data
func SendData(conn packet_manager.PacketConn, data networking.ReceivedMessageData) error {
	return nil
}

// TODO
// Respond to request for our hash
func SendRootReply(conn packet_manager.PacketConn, data networking.ReceivedMessageData) error {
	return nil
}
