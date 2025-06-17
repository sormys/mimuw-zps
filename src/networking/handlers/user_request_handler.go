package connection_manager

import (
	"errors"
	"log/slog"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/handler"
	mt "mimuw_zps/src/merkle_tree"
	mm "mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/networking/packet_manager"
	"mimuw_zps/src/networking/peer_conn"
	"mimuw_zps/src/networking/srv_conn"
	pmp "mimuw_zps/src/peer_message_parser"
	"mimuw_zps/src/utility"
	"sync"
)

// Initiates communication with the peer whose addresses are provided
func StartConnection(conn packet_manager.PacketConn, peer peer_conn.Peer, nickname string) mm.TuiMessage {
	addresses := peer.Addresses
	for _, addr := range addresses {
		id := utility.GenerateID()
		message := srv_conn.CreateHandshakeBytes(HELLO, nickname, id)
		info := conn.SendRequest(addr, message, networking.NewPolicyHandshake())
		if verifyIdAndType(info, id, networking.HELLO_REPLY) &&
			encryption.VerifySignature(info.Raw[:networking.MIN_HELLO_SIZE+info.Length], getSignatureFromReceivedHandshake(info), encryption.ParsePublicKey(peer.Key)) {
			return mm.TuiInfo("Successfully connected to address " + addr.String())
		}

	}

	return mm.TuiError("Cannot connect to any of these addresses" + printAddreses(addresses))
}

// reloads all files associated with the provided peer in message
func ReloadPeerContent(conn packet_manager.PacketConn, message mm.TuiMessageBasicInfo) mm.TuiMessage {
	peer := message.FileInfo.Peer
	receivedData, info := sendRootRequest(conn, peer.Addresses)
	if !mm.IsEmpty(info) {
		return info
	}

	return mm.CreateTuiMessageTypeBasicInfo(getHashFromRootReply(receivedData), peer)

}

// return a list with available peers
func ReloadAvailablePeers(server srv_conn.Server) mm.TuiMessage {
	peers, err := server.GetInfoPeers()
	if err != nil {
		return mm.ConvertErrorsToTuiMessage(err)
	}
	return mm.CreateListPeers(peers)
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

	return mm.TuiInfo("Successfully downloaded data from " + fileInfo.Peer.Name + "")
}

type discoveredType struct {
	hash      string
	cacheType mt.NodeType
	msg       pmp.DatumMsg
	err       error
}

func decodeDatumResponse(reqHash string, response networking.ReceivedMessageData) discoveredType {
	responseMessage, err := pmp.DecodeMessage(response)
	if err != nil {
		return discoveredType{hash: reqHash, err: err}
	}
	switch msg := responseMessage.(type) {
	case pmp.NoDatumMsg:
		return discoveredType{hash: reqHash, err: errors.New("no data for given hash")}
	case pmp.DatumMsg:
		if mt.ConvertHashBytesToString(msg.Hash[:]) != reqHash {
			return discoveredType{hash: reqHash, err: errors.New("received hash do not match")}
		}
		return discoveredType{hash: reqHash, msg: msg, err: nil}
	case pmp.ErrorMsg:
		return discoveredType{hash: reqHash, err: errors.New("received error response from peer: " + msg.Message)}
	}
	return discoveredType{hash: reqHash, err: errors.New("received unexpected reply from host")}
}

func discoverNodeType(conn packet_manager.PacketConn, peer peer_conn.Peer, nodeHash string,
	tree mt.RemoteMerkleTree, dscvChan chan<- discoveredType) {
	hashBytes, err := mt.ConvertStringHashToBytes(nodeHash)
	if err != nil {
		dscvChan <- discoveredType{hash: nodeHash, err: errors.New("invalid hash")}
		return
	}
	for {
		// Check if we have it already in the tree - cache
		if node := tree.GetNode(nodeHash); node != nil {
			if node.IsDir() {
				dscvChan <- discoveredType{hash: nodeHash, cacheType: mt.DIRECTORY}
				return
			} else if node.IsFile() {
				dscvChan <- discoveredType{hash: nodeHash, cacheType: mt.CHUNK}
				return
			}
			if len(node.Children()) == 0 {
				dscvChan <- discoveredType{hash: nodeHash, err: errors.New("invalid data in tree")}
				return
			}
			nodeHash = node.Children()[0].Hash()
			hashBytes, err = mt.ConvertStringHashToBytes(nodeHash)
			if err != nil {
				dscvChan <- discoveredType{hash: nodeHash, err: errors.New("invalid hash in tree")}
				return
			}
			continue
		}

		// No such node in memory - ask peer
		request := pmp.DatumRequestMsg{
			UnsignedMessage: pmp.NewEmtpyUnsignedMessage(peer.Addresses[0], utility.GenerateID()),
			Hash:            handler.Hash(hashBytes),
		}
		// FIXME(sormys) send to all addresses, check if any address available
		data := conn.SendRequest(peer.Addresses[0], pmp.EncodeMessage(request),
			networking.NewRetryPolicyRequest())
		if data.Err != nil {
			dscvChan <- discoveredType{hash: nodeHash, err: data.Err}
			return
		}
		dscvType := decodeDatumResponse(nodeHash, data)
		if dscvType.err != nil || dscvType.msg.NodeType != mt.BIG {
			// The type has been discovered or error occured
			dscvChan <- dscvType
			return
		}
		childrenHashes := make([][]byte, len(dscvType.msg.Children))
		for i, ch := range dscvType.msg.Children {
			childrenHashes[i] = ch.Hash
		}
		// If there would be no children this would fail
		err = tree.DiscoverAsBig(nodeHash, childrenHashes)
		if err != nil {
			dscvChan <- dscvType
			return
		}
		nodeHash = mt.ConvertHashBytesToString(childrenHashes[0])
		hashBytes = childrenHashes[0]
	}
}

func GetDirectoryContent(conn packet_manager.PacketConn, message mm.TuiMessageBasicInfo,
	peersTrees map[string]mt.RemoteMerkleTree, treeMutex *sync.Mutex) mm.TuiMessage {
	treeMutex.Lock()
	tree, exist := peersTrees[message.FileInfo.Peer.Name]
	if !exist {
		treeMutex.Unlock()
		return mm.TuiError("No tree for given peer")
	}
	nodeHash := mt.ConvertHashBytesToString(message.FileInfo.Hash[:])
	node := tree.GetNode(nodeHash)
	if node.Type() != mt.DIRECTORY {
		treeMutex.Unlock()
		return mm.TuiError("The node is not a directory")
	}
	// FIXME(sormys) this should probably be an option in packet manager, for now,
	// ignoring issue of creating multiple coroutines here
	responseChan := make(chan discoveredType, len(node.Children()))
	for _, ch := range node.Children() {
		go discoverNodeType(conn, message.FileInfo.Peer, ch.Hash(), tree, responseChan)
	}
	for range node.Children() {
		dscvType := <-responseChan
		if dscvType.err != nil {
			return mm.TuiError(dscvType.err.Error())
		}
		if dscvType.cacheType == mt.DIRECTORY || dscvType.cacheType == mt.CHUNK {
			break
		}
		if dscvType.msg.NodeType == mt.DIRECTORY {
			err := tree.DiscoverAsDirectory(dscvType.hash, dscvType.msg.Children)
			if err != nil {
				return mm.TuiError(dscvType.err.Error())
			}
		}
		if dscvType.msg.NodeType == mt.CHUNK {
			err := tree.DiscoverAsChunk(dscvType.hash, dscvType.msg.Data)
			if err != nil {
				return mm.TuiError(dscvType.err.Error())
			}
		}
	}
	// TODO(sormys) Gather types and send the info using standard inteface
	return mm.TuiInfo("Correctly discovered the type")
}

func RunUserRequestHandler(conn packet_manager.PacketConn,
	tuiReceiver <-chan mm.TuiMessage,
	tuiSender chan<- mm.TuiMessage,
	server srv_conn.Server, nickname string) {

	var mutex sync.Mutex
	var data mm.TuiMessage
	var err error

	peersTrees := map[string]mt.RemoteMerkleTree{}

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
			case mm.EXPAND_FOLDER:
				{
					data = GetDirectoryContent(conn, message.Payload().(mm.TuiMessageBasicInfo), peersTrees, &mutex)
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
