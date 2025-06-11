package connection_manager

import (
	"log/slog"
	"mimuw_zps/src/encryption"
	mt "mimuw_zps/src/merkle_tree"
	mm "mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/networking/packet_manager"
	"mimuw_zps/src/networking/peer_conn"
	"mimuw_zps/src/networking/srv_conn"
	"mimuw_zps/src/utility"
	"sync"
)

// Initiates communication with the peer whose addresses are provided
func StartConnection(conn packet_manager.PacketConn,
	peer peer_conn.Peer, nickname string) mm.TuiMessage {

	addresses := peer.Addresses
	for _, addr := range addresses {
		id := utility.GenerateID()
		message := CreateHandshake(addr, id, nickname)
		info := conn.SendRequest(message)
		if verifyIdAndType(info, id, networking.HELLO_REPLY) &&
			encryption.VerifySignature(info.Raw[:networking.MIN_HELLO_SIZE+info.Length],
				getSignatureFromReceivedHandshake(info), encryption.ParsePublicKey(peer.Key)) {
			return mm.CreateTuiMessageInfo(mm.INFO_TUI,
				"Successfully connected to address "+addr.String())
		}

	}

	return mm.CreateTuiMessageInfo(mm.ERROR_TUI,
		"Cannot connect to any of these addresses"+printAddreses(addresses))

}

// return a list with available peers
func ReloadAvailablePeers(server srv_conn.Server) mm.TuiMessage {
	peers, err := server.GetInfoPeers()
	if err != nil {
		return mm.ConvertErrorsToTuiMessage(err)
	}
	return mm.CreateListPeers(peers)
}

// reloads all files associated with the provided peer in message
func ReloadPeerContent(conn packet_manager.PacketConn,
	message mm.TuiMessageBasicInfo) mm.TuiMessage {

	peer := message.FileInfo.Peer
	receivedData, info := sendRootRequest(conn, peer.Addresses)
	if !mm.IsEmpty(info) {
		return info
	}

	return mm.CreateTuiMessageTypeBasicInfo(getHashFromRootReply(receivedData), peer)

}

func DownloadFileFromPeer(conn packet_manager.PacketConn, message mm.TuiMessageBasicInfo) mm.TuiMessage {
	fileInfo := message.FileInfo
	receivedInfoDatum, err := sendDatumRequest(conn, fileInfo.Peer.Addresses, fileInfo.Hash)
	if !mm.IsEmpty(err) {
		return err
	}
	_ = receivedInfoDatum
	//TODO
	//manage received data and do something with them. Temporary dunno what

	return mm.CreateTuiMessageInfo(mm.INFO_TUI, "Successfully downloaded data from "+fileInfo.Peer.Name+"")
}

func GetContent(conn packet_manager.PacketConn, message mm.TuiMessageBasicInfo,
	peersTrees map[string]mt.RemoteMerkleTree, treeMutex *sync.Mutex) mm.TuiMessage {
	treeMutex.Lock()
	tree := mt
}

func RunUserRequestHandler(conn packet_manager.PacketConn,
	tuiReceiver <-chan mm.TuiMessage,
	tuiSender chan<- mm.TuiMessage,
	server srv_conn.Server, nickname string) {

	var mutex sync.Mutex
	var data mm.TuiMessage
	var err error

	peerTrees := map[string]mt.RemoteMerkleTree{}

	for message := range tuiReceiver {
		go func(message mm.TuiMessage) {
			switch message.RequestType() {
			case mm.CONNECT:
				{
					data = StartConnection(conn, message.Payload().(peer_conn.Peer), nickname)
				}
			case mm.RELOAD_PEERS:
				{
					data = ReloadAvailablePeers(server)
				}
			case mm.RELOAD_CONTENT:
				{
					data = ReloadPeerContent(conn, message.Payload().(mm.TuiMessageBasicInfo))
				}
			case mm.GET_CONTENT:
				{
					data = nil
				}
			case mm.DOWNLOAD:
				{
					data = DownloadFileFromPeer(conn, message.Payload().(mm.TuiMessageBasicInfo))
				}
			}
			if err != nil {
				slog.Error("error when handling message", "type", message.RequestType())
				tuiSender <- mm.ConvertErrorToTuiMessage(err)

			}
			if data != nil && !mm.IsEmpty(data) {
				tuiSender <- data
			}
		}(message)

	}

}
