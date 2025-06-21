package handlers

import (
	"errors"
	"log/slog"
	"mimuw_zps/src/encryption"
	mt "mimuw_zps/src/merkle_tree"
	"mimuw_zps/src/networking/packet_manager"
	"mimuw_zps/src/networking/srv_conn"
	pmp "mimuw_zps/src/peer_message_parser"
	"mimuw_zps/src/utility"
	"net"
)

func SendErrorReply(conn packet_manager.PacketConn, addr net.Addr, err error) {
	replyMsg := pmp.ErrorMsg{
		UnsignedMessage: pmp.NewEmptyUnsignedMessage(utility.GenerateID()),
		Message:         err.Error(),
	}
	conn.SendReply(addr, pmp.EncodeMessage(replyMsg))
}

func HandleHello(conn packet_manager.PacketConn, addr net.Addr, hello pmp.HelloMsg,
	server srv_conn.Server, nickname string) error {

	slog.Debug("Responding to HELLO message", "id", hello.ID, "addr", addr)
	key, err := server.GetPeerKey(hello.Name)

	if err != nil {
		slog.Error("Failed to get peer key", "error", err)
		return err
	}

	if !hello.VerifySignature(encryption.ParsePublicKey(key)) {
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
	return nil
}

func HandleRootRequest(conn packet_manager.PacketConn, addr net.Addr, rootRequest pmp.RootRequestMsg) error {
	root := mt.GetRoot()
	request := pmp.RootReplyMsg{
		SignedMessage: pmp.NewEmptySignedMessage(rootRequest.ID()),
		Hash:          root,
	}
	conn.SendReply(addr, pmp.EncodeMessage(request))
	return nil
}

func HandleDatumRequest(conn packet_manager.PacketConn, addr net.Addr, datumRequest pmp.DatumRequestMsg) error {
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

func HandlePing(conn packet_manager.PacketConn, addr net.Addr, ping pmp.PingMsg) error {
	reply := pmp.PongMsg{
		UnsignedMessage: pmp.NewEmptyUnsignedMessage(ping.ID()),
	}
	conn.SendReply(addr, pmp.EncodeMessage(reply))
	return nil
}
