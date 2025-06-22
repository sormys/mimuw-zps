package handlers

import (
	"errors"
	"log/slog"
	"mimuw_zps/src/encryption"
	mt "mimuw_zps/src/merkle_tree"
	"mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/networking/packet_manager"
	"mimuw_zps/src/networking/srv_conn"
	pmp "mimuw_zps/src/peer_message_parser"
	"mimuw_zps/src/utility"
	"net"
)

func RunPeerRequestHandler(conn packet_manager.PacketConn, tuiSender chan<- message_manager.TuiMessage,
	server srv_conn.Server, nickname string) {
	for {
		data := conn.RecvRequest()
		decoded, err := pmp.DecodeMessage(data)
		go func(data networking.ReceivedMessageData) {
			switch msg := decoded.(type) {
			case pmp.HelloMsg:
				err = handleHello(conn, data.Addr, msg, server, nickname)
			case pmp.RootRequestMsg:
				if ContainsUser(data.Addr) {
					err = handleRootRequest(conn, data.Addr, msg)
				}
			case pmp.DatumRequestMsg:
				if ContainsUser(data.Addr) {
					err = handleDatumRequest(conn, data.Addr, msg)
				}
			case pmp.PingMsg:
				err = handlePing(conn, data.Addr, msg)
			case pmp.NATTraversal2:
				handleNATTraversal2(conn, msg)
			default:
				slog.Warn("Currently no handler for request of type", "type", msg.Type())
			}

			if err != nil {
				sendErrorReply(conn, data.Addr, err)
				tuiSender <- message_manager.ConvertErrorToTuiMessage(err)
			}
		}(data)
	}
}

func sendErrorReply(conn packet_manager.PacketConn, addr net.Addr, err error) {
	replyMsg := pmp.ErrorMsg{
		UnsignedMessage: pmp.NewEmptyUnsignedMessage(utility.GenerateID()),
		Message:         err.Error(),
	}
	conn.SendReply(addr, pmp.EncodeMessage(replyMsg))
}

func handleHello(conn packet_manager.PacketConn, addr net.Addr, hello pmp.HelloMsg,
	server srv_conn.Server, nickname string) error {

	peer, err := server.GetInfoPeer(hello.Name)

	if err != nil {
		slog.Error("Failed to get peer key", "error", err)
		return err
	}

	if !hello.VerifySignature(encryption.ParsePublicKey(peer.Key)) {
		slog.Debug("Failed to verify signature")
		return errors.New("failed to verify signature in hello reply")
	}

	slog.Debug("Received correct Hello, sending reply")
	message := pmp.HelloReplyMsg{
		SignedMessage: pmp.NewEmptySignedMessage(hello.ID()),
		Extensions:    pmp.GetExtensions(),
		Name:          nickname,
	}
	conn.SendReply(addr, pmp.EncodeMessage(message))
	outgoing := peer.Name == srv_conn.GALENE // Nasty trick to refresh connection with the server
	ConnectPeer(outgoing, peer, hello.Extensions)
	return nil
}

func handleRootRequest(conn packet_manager.PacketConn, addr net.Addr, rootRequest pmp.RootRequestMsg) error {
	root := mt.GetRoot()
	request := pmp.RootReplyMsg{
		SignedMessage: pmp.NewEmptySignedMessage(rootRequest.ID()),
		Hash:          root,
	}
	conn.SendReply(addr, pmp.EncodeMessage(request))
	return nil
}

func handleDatumRequest(conn packet_manager.PacketConn, addr net.Addr, datumRequest pmp.DatumRequestMsg) error {
	hash := mt.ConvertHashBytesToString(datumRequest.Hash[:])
	datum, exists := mt.GetHashContent(hash)
	var reply pmp.PeerMessage
	if !exists {
		reply = pmp.NoDatumMsg{
			SignedMessage: pmp.NewEmptySignedMessage(datumRequest.ID()),
			Hash:          datumRequest.Hash,
		}
	} else {
		reply = pmp.DatumMsg{
			UnsignedMessage: pmp.NewEmptyUnsignedMessage(datumRequest.ID()),
			Hash:            datumRequest.Hash,
			Data:            datum.Data,
		}
	}
	conn.SendReply(addr, pmp.EncodeMessage(reply))
	return nil
}

func handlePing(conn packet_manager.PacketConn, addr net.Addr, ping pmp.PingMsg) error {
	reply := pmp.PongMsg{
		UnsignedMessage: pmp.NewEmptyUnsignedMessage(ping.ID()),
	}
	conn.SendReply(addr, pmp.EncodeMessage(reply))
	return nil
}

func handleNATTraversal2(conn packet_manager.PacketConn, nattrav2 pmp.NATTraversal2) {
	ping := pmp.PingMsg{
		UnsignedMessage: pmp.NewEmptyUnsignedMessage(utility.GenerateID()),
	}
	conn.SendReply(nattrav2.Addr, pmp.EncodeMessage(ping))
}
