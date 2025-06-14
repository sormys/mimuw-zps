package connection_manager

import (
	"errors"
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

type DiscoveredType struct {
	hash     string
	nodeType mt.NodeType
	data     []byte
	children []mt.DirectoryRecordRaw
	err      error
}

func getNameFromBytes(nameBytes [32]byte) (string, error) {
	var i int
	for i = 31; i >= 0; i-- {
		if nameBytes[i] != 0x0 {
			break
		}
	}
	if i == 0 {
		return "", errors.New("invalid name of file/directory")
	}
	return string(nameBytes[:min(i, 31)]), nil
}

func decodeDatumResponse(reqHash string, response networking.ReceivedMessageData) DiscoveredType {
	messType, exists := networking.TypeMap[utility.GetMessageType(response.Raw)]
	if !exists {
		return DiscoveredType{err: errors.New("invalid response type")}
	}
	switch messType {
	case networking.NO_DATUM:
		return DiscoveredType{hash: nodeHash, err: errors.New("peer has no node with given hash")}
	case networking.DATUM:
		if response.Length < 1 {
			return DiscoveredType{err: errors.New("datum response has no type")}
		}
		switch response.Data[0] {
		case 0x0:
			// CHUNK
			if response.Length > 1024+1 {
				return DiscoveredType{err: errors.New("chunk data too big")}
			}
			return DiscoveredType{hash: nodeHash, nodeType: mt.CHUNK, data: response.Data[1:]}
		case 0x01:
			// DIRECTORY
			if (response.Length-1)%64 != 0 || (response.Length-1)/64 > 16 {
				return DiscoveredType{err: errors.New("directory entires are of incorrect length")}
			}
			records := make([]mt.DirectoryRecordRaw, (response.Length-1)/64)
			recordStart := 1
			for i := range len(records) {
				n, err := getNameFromBytes([32]byte(response.Data[recordStart : recordStart+32]))
				if err != nil {
					return DiscoveredType{err: err}
				}
				h := response.Data[recordStart+32 : recordStart+64]
				records[i] = mt.DirectoryRecordRaw{Name: n, Hash: h}
				recordStart += 64
			}
			return DiscoveredType{hash: nodeHash, nodeType: mt.DIRECTORY, children: records}
		case 0x03:
			// BIG
			childrenLen := (response.Length - 1) / 32
			if (response.Length-1)%32 != 0 || childrenLen > 32 || childrenLen < 2 {
				return DiscoveredType{err: errors.New("big node children are of incorrect length")}
			}
			children := make([]mt.DirectoryRecordRaw, childrenLen)
			recordStart := 1
			for i := range childrenLen {
				children[i] = mt.DirectoryRecordRaw{Hash: response.Data[recordStart : recordStart+32]}
				recordStart += 32
			}
			return DiscoveredType{hash: nodeHash, nodeType: mt.BIG, children: children}
		}
	}
	return DiscoveredType{err: errors.New("unknown datum type")}
}

func discoverNodeType(conn packet_manager.PacketConn, peer peer_conn.Peer, nodeHash string,
	tree mt.RemoteMerkleTree, dscvChan chan<- DiscoveredType) {
	hashBytes, err := mt.ConvertStringHashToBytes(nodeHash)
	if err != nil {
		dscvChan <- DiscoveredType{err: errors.New("invalid hash")}
		return
	}
	for {
		request := createDatumRequestTemplate(utility.GenerateID(), DATUM_REQUEST, mm.Hash(hashBytes))
		// FIXME(sormys) send to all addresses, check
		data := conn.SendRequest(peer.Addresses[0], request, networking.NewRetryPolicyRequest())
		if data.Err != nil {
			dscvChan <- DiscoveredType{err: data.Err}
			return
		}
		dscvType := decodeDatumResponse(nodeHash, data)
		if dscvType.nodeType != mt.BIG {
			dscvChan <- dscvType
			return
		}
		childrenHashes := make([][]byte, len(dscvType.children))
		for i, ch := range dscvType.children {
			childrenHashes[i] = ch.Hash
		}
		// This is modifies only one node, does not modify parent
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
	responseChan := make(chan DiscoveredType, len(node.Children()))
	for _, ch := range node.Children() {
		go discoverNodeType(conn, message.FileInfo.Peer, ch.Hash(), tree, responseChan)
	}
	for range node.Children() {
		dscvType := <-responseChan
		if dscvType.err != nil {
			return mm.TuiError(dscvType.err.Error())
		}
		if dscvType.nodeType == mt.DIRECTORY {
			err := tree.DiscoverAsDirectory(dscvType.hash, dscvType.children)
			if err != nil {
				return mm.TuiError(dscvType.err.Error())
			}
		}
		if dscvType.nodeType == mt.CHUNK {
			err := tree.DiscoverAsChunk(dscvType.hash, dscvType.data)
			if err != nil {
				return mm.TuiError(dscvType.err.Error())
			}
		}
	}
	// TODO(sormys) send the info using standard inteface
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
			case mm.GET_CONTENT:
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
