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
		request := pmp.HelloMsg{
			SignedMessage: pmp.NewEmptySignedMessage(utility.GenerateID()),
			Extensions:    pmp.Extensions{},
			Name:          nickname,
		}
		info := conn.SendRequest(addr, pmp.EncodeMessage(request), networking.NewPolicyHandshake())

		decoded, err := pmp.DecodeMessage(info)
		if err != nil {
			return mm.TuiError(err.Error())
		}
		switch msg := decoded.(type) {
		case pmp.ErrorMsg:
			return mm.TuiError("Error reply from peer: " + msg.Message)
		case pmp.HelloReplyMsg:
			if !msg.VerifySignature(encryption.ParsePublicKey(peer.Key)) {
				return mm.TuiError("Invalid hello reply signature")
			}
			return mm.InitConnectionMessage(peer)
			// return mm.TuiInfo("Successfully connected to address " + addr.String())
		}
	}

	return mm.TuiError("Cannot connect to any of these addresses" + printAddreses(addresses))
}

// reloads all files associated with the provided peer in message

func ReloadPeerContent(conn packet_manager.PacketConn, peer peer_conn.Peer, peersTrees map[string]mt.RemoteMerkleTree, mutex *sync.Mutex) mm.TuiMessage {
	receivedData, err := sendRootRequest(conn, peer)
	if err != nil {
		return mm.ConvertErrorToTuiMessage(err)
	}

	hash := mt.ConvertHashBytesToString(receivedData.Hash[:])
	tree := mt.NewRemoteMerkleTree(hash)
	ch := make(chan discoveredType, 1)

	discoverNodeType(conn, peer, hash, tree, ch)

	dscvType := <-ch

	if dscvType.err != nil {
		return mm.TuiError(dscvType.err.Error())
	}
	if dscvType.cacheType == mt.DIRECTORY || dscvType.cacheType == mt.CHUNK {
		return mm.ConvertErrorToTuiMessage(err)
	}
	if dscvType.msg.NodeType == mt.DIRECTORY {
		//jestem folderem
		if err := tree.DiscoverAsDirectory(dscvType.hash, dscvType.msg.Children); err != nil {
			return mm.TuiError(dscvType.err.Error())
		}
	}
	if dscvType.msg.NodeType == mt.CHUNK {
		// jestem plikiem
		if err := tree.DiscoverAsChunk(dscvType.hash, dscvType.msg.Data); err != nil {
			return mm.TuiError(dscvType.err.Error())
		}
	}

	//czy root jest plikiem zcy folderem

	mutex.Lock()
	defer mutex.Unlock()

	peersTrees[peer.Name] = tree

	// slog.Debug("ReloadPeerContent result", "data", data)

	folder := mm.TUIFolder{
		Hash:       handler.Hash{},
		Name:       "root",
		Path:       "root",
		Files:      nil,
		Subfolders: nil,
		Loaded:     false,
		Expanded:   false,
	}

	return mm.CreateTuiFolders(folder)
	// return mm.CreateTuiMessageTypeBasicInfo(getHashFromRootReply(receivedData), peer)

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
	startHash string
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
	startHash := nodeHash
	hashBytes, err := mt.ConvertStringHashToBytes(nodeHash)
	if err != nil {
		dscvChan <- discoveredType{hash: nodeHash, err: errors.New("invalid hash")}
		return
	}
	for {
		// Check if we have it already in the tree - cache
		if node := tree.GetNode(nodeHash); node != nil {
			if node.IsDir() {
				dscvChan <- discoveredType{startHash: startHash, hash: nodeHash, cacheType: mt.DIRECTORY}
				return
			} else if node.IsFile() {
				dscvChan <- discoveredType{startHash: startHash, hash: nodeHash, cacheType: mt.CHUNK}
				return
			}
			if len(node.Children()) == 0 {
				dscvChan <- discoveredType{startHash: startHash, hash: nodeHash, err: errors.New("invalid data in tree")}
				return
			}
			nodeHash = node.Children()[0].Hash()
			hashBytes, err = mt.ConvertStringHashToBytes(nodeHash)
			if err != nil {
				dscvChan <- discoveredType{startHash: startHash, hash: nodeHash, err: errors.New("invalid hash in tree")}
				return
			}
			continue
		}

		// No such node in memory - ask peer
		request := pmp.DatumRequestMsg{
			UnsignedMessage: pmp.NewEmtpyUnsignedMessage(utility.GenerateID()),
			Hash:            handler.Hash(hashBytes),
		}
		// FIXME(sormys) send to all addresses, check if any address available
		data := conn.SendRequest(peer.Addresses[0], pmp.EncodeMessage(request),
			networking.NewRetryPolicyRequest())
		if data.Err != nil {
			dscvChan <- discoveredType{startHash: startHash, hash: nodeHash, err: data.Err}
			return
		}
		dscvType := decodeDatumResponse(nodeHash, data)
		dscvType.startHash = startHash
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

func GetDirectoryContent(conn packet_manager.PacketConn, message mm.BasicFolder,
	peersTrees map[string]mt.RemoteMerkleTree, treeMutex *sync.Mutex) mm.TuiMessage {
	treeMutex.Lock()
	defer treeMutex.Unlock()
	tree, exist := peersTrees[message.Peer.Name]
	if !exist {
		return mm.TuiError("No tree for given peer")
	}
	nodeHash := mt.ConvertHashBytesToString(message.Hash[:])
	node := tree.GetNode(nodeHash)
	if node.Type() != mt.DIRECTORY {
		return mm.TuiError("The node is not a directory")
	}
	// FIXME(sormys) this should probably be an option in packet manager, for now,
	// ignoring issue of creating multiple coroutines here
	responseChan := make(chan discoveredType, len(node.Children()))
	for _, ch := range node.Children() {
		go discoverNodeType(conn, message.Peer, ch.Hash(), tree, responseChan)
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
			if err := tree.DiscoverAsDirectory(dscvType.hash, dscvType.msg.Children); err != nil {
				return mm.TuiError(dscvType.err.Error())
			}
		}
		if dscvType.msg.NodeType == mt.CHUNK {
			if err := tree.DiscoverAsChunk(dscvType.hash, dscvType.msg.Data); err != nil {
				return mm.TuiError(dscvType.err.Error())
			}
		}
	}
	slog.Debug("JESTEM W GET DIRECTORY CONTENT")
	// TODO(sormys) Gather types and send the info using standard inteface
	return mm.TuiInfo("Correctly discovered the type")
}

func RunUserRequestHandler(conn packet_manager.PacketConn,
	tuiReceiver <-chan mm.TuiMessage,
	tuiSender chan<- mm.TuiMessage,
	server srv_conn.Server, nickname string) {

	var mutex sync.Mutex
	var data mm.TuiMessage
	// var err error

	peersTrees := map[string]mt.RemoteMerkleTree{}

	for message := range tuiReceiver {
		go func(message mm.TuiMessage) {
			switch message.RequestType() {
			case mm.CONNECT:
				{
					// Expected output is peer when after successful handshake. You can use
					// message_manager.InitConnectionMessage(peer)

					//data = connect(message.Payload().([]peer_conn.Peer)[0])
					//data = connection_manager.StartConnection(conn, message.Payload().([]peer_conn.Peer)[0], nickname)
					data = StartConnection(conn, message.Payload().([]peer_conn.Peer)[0], nickname)
				}
			case mm.RELOAD_CONTENT:
				{
					// data = ReloadPeerContent(conn, message.Payload().(mm.TuiMessageBasicInfo))

					// in this state handler should reset all his states!

					data = ReloadAvailablePeers(server)
				}
			case mm.EXPAND_FOLDER:
				{
					// In this case the folder's contens are not yet loaded in the TUI.
					// Check if the contents are available in the cache. If not,
					// send a request to fetch data. Expected output is TuiMessage -> see expandFolder

					// message.Payload().(BasicFolder) -> {Path: path, Peer: peer, Name: name, Hash: hash}
					data = GetDirectoryContent(conn, message.Payload().(mm.BasicFolder), peersTrees, &mutex)
				}
			case mm.DOWNLOAD:
				{
					data = DownloadFileFromPeer(conn, message.Payload().(mm.TuiMessageBasicInfo))
				}

			case mm.SHOW_DATA:
				{
					// In this case we want discover user's file. So you have to sent RootRequest
					user := message.Payload().([]peer_conn.Peer)[0]
					// Expected output is TuiMessage -> see expand Folder
					data = ReloadPeerContent(conn, user, peersTrees, &mutex)
				}
			}
			if data != nil && !mm.IsEmpty(data) {
				tuiSender <- data
			}
		}(message)

	}

}
