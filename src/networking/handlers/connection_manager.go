package connection_manager

import (
	"errors"
	"log/slog"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/handler"
	"mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/networking/packet_manager"
	"mimuw_zps/src/networking/srv_conn"
	"mimuw_zps/src/utility"
	"net"
)

func SendErrorReply(conn packet_manager.PacketConn, addr net.Addr, err error) {
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
