package handlers

import (
	"bytes"
	"errors"
	"log/slog"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/handler"
	mt "mimuw_zps/src/merkle_tree"
	"mimuw_zps/src/message_manager"
	mm "mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/networking/packet_manager"
	"mimuw_zps/src/networking/srv_conn"
	pmp "mimuw_zps/src/peer_message_parser"
	"mimuw_zps/src/utility"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

const DOWNLOAD_THREADS = 20
const DOWNLOAD = "Download"

func getDownloadPath(name string, path string) (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("failed to resolve project root path")
	}
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(filename))))
	downloadDir := filepath.Join(projectRoot, DOWNLOAD)
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		return "", err
	}
	userDir := filepath.Join(downloadDir, name)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return "", err
	}
	finalPath := filepath.Join(userDir, path)
	return finalPath, nil
}

// Sends a message of type RootRequest to all provided addresses. Stop automatically upon receiving a valid response
func sendRootRequest(conn packet_manager.PacketConn, peer networking.Peer) (pmp.RootReplyMsg, error) {
	addr := peer.Addresses
	type result struct {
		reply pmp.RootReplyMsg
		err   error
	}
	resultCh := make(chan result, len(addr))
	for _, address := range addr {
		go func(address net.Addr) {
			request := pmp.RootRequestMsg{
				UnsignedMessage: pmp.NewEmptyUnsignedMessage(utility.GenerateID()),
			}
			info := conn.SendRequest(address, pmp.EncodeMessage(request), networking.NewRetryPolicyRequest())

			decoded, err := pmp.DecodeMessage(info)
			if err != nil {
				resultCh <- result{err: err}
			}
			switch msg := decoded.(type) {
			case pmp.ErrorMsg:
				resultCh <- result{err: errors.New(msg.Message)}
			case pmp.RootReplyMsg:
				if !msg.VerifySignature(encryption.ParsePublicKey(peer.Key)) {
					resultCh <- result{err: errors.New("incorrect verify signature")}
				}
				resultCh <- result{reply: msg, err: nil}
			}
		}(address)
	}
	for range addr {
		res := <-resultCh
		if res.err == nil {
			return res.reply, nil
		}
	}
	return pmp.RootReplyMsg{}, errors.New("none of peers responds")
}

func UDPHolePunch(conn packet_manager.PacketConn, peer networking.Peer, nickname string, maxTries int) {
	slog.Info("Trying to hole punch", "dst nickname", nickname)
	NATTraversalExtension := pmp.Extensions{0x0, 0x0, 0x0, 0x1}
	peers := GetPeersWithExtension(NATTraversalExtension)
	slog.Debug("Found peers able to hole punch", "peer count", len(peers))
	successful := 0
	for _, through := range peers {
		for range max(1, maxTries/2) {
			for _, addr := range through.Addresses {
				request := pmp.NATTraversal{
					SignedMessage: pmp.NewEmptySignedMessage(utility.GenerateID()),
					Addr:          peer.Addresses[0],
				}
				slog.Debug("Requesting hole puch", "to", nickname, "through", through.Name)
				reply := conn.SendRequest(addr, pmp.EncodeMessage(request), networking.NewRetryPolicyRequest())
				decoded, _ := pmp.DecodeMessage(reply)
				switch msg := decoded.(type) {
				case pmp.ErrorMsg:
					slog.Error("Got error for natraversal", "msessagae", msg.Message)
				case pmp.PongMsg:
					successful++
					if successful >= maxTries {
						return
					}
				}
			}
		}
	}
}

// Initiates communication with the peer whose addresses are provided
func StartConnection(conn packet_manager.PacketConn, peer networking.Peer, nickname string) mm.TuiMessage {
	addresses := peer.Addresses
	resultCh := make(chan mm.TuiMessage, len(addresses))
	for _, addr := range addresses {
		go func(addr net.Addr) {
			request := pmp.HelloMsg{
				SignedMessage: pmp.NewEmptySignedMessage(utility.GenerateID()),
				Extensions:    pmp.Extensions(pmp.GetExtensions()),
				Name:          nickname,
			}
			info := conn.SendRequest(addr, pmp.EncodeMessage(request), networking.NewPolicyHandshake())

			if info.Err != nil {
				UDPHolePunch(conn, peer, nickname, 5)
			}
			info = conn.SendRequest(addr, pmp.EncodeMessage(request), networking.NewPolicyHandshake())
			decoded, err := pmp.DecodeMessage(info)
			if err != nil {
				resultCh <- mm.TuiError(err.Error())
			}
			switch msg := decoded.(type) {
			case pmp.ErrorMsg:
				resultCh <- mm.TuiError("Error reply from peer: " + msg.Message)
			case pmp.HelloReplyMsg:
				if !msg.VerifySignature(encryption.ParsePublicKey(peer.Key)) {
					resultCh <- mm.TuiError("Invalid hello reply signature")
				}
				ConnectPeer(true, peer, msg.Extensions)
				resultCh <- mm.InitConnectionMessage(peer)
			}
		}(addr)
	}
	for range addresses {
		res := <-resultCh
		if res.RequestType() == mm.CONNECT {
			return res
		}
	}

	return mm.TuiError("Cannot connect to any of these addresses" + printAddreses(addresses))
}

// reloads all files associated with the provided peer in message

func askForData(addr net.Addr,
	conn packet_manager.PacketConn,
	request pmp.DatumRequestMsg,
	tree mt.RemoteMerkleTree,
	hash string,
	peersTrees map[string]mt.RemoteMerkleTree,
	peer networking.Peer) mm.TuiMessage {

	data := conn.SendRequest(addr, pmp.EncodeMessage(request),
		networking.NewRetryPolicyRequest())
	if data.Err != nil {
		return mm.TuiError("Failed to get response from peer" + data.Err.Error())
	}
	dscvType := decodeDatumResponse(hash, data)
	if dscvType.msg.NodeType == mt.DIRECTORY {
		if err := tree.DiscoverAsDirectory(hash, dscvType.msg.Children); err != nil {
			return mm.TuiError(err.Error())
		}
	}
	if dscvType.msg.NodeType == mt.CHUNK {
		if err := tree.DiscoverAsChunk(hash, dscvType.msg.Data); err != nil {
			return mm.TuiError(err.Error())
		}
	}
	if dscvType.msg.NodeType == mt.BIG {
		if err := tree.DiscoverAsBig(hash, dscvType.msg.Children); err != nil {
			return mm.TuiError(err.Error())
		}
	}
	subfolders, files, err := getFoldersAndFiles(tree.GetNode(hash), peer, "root", tree, conn)
	if err != nil {
		return mm.TuiError(err.Error())
	}
	mutex.Lock()
	defer mutex.Unlock()

	peersTrees[peer.Name] = tree
	folder := message_manager.TUIFolder{
		Name:       "root",
		Path:       "root",
		Files:      files,
		Subfolders: subfolders,
		Loaded:     true,
		Expanded:   true,
	}
	return message_manager.CreateTuiFolders(folder)
}

func ReloadPeerContent(conn packet_manager.PacketConn, peer networking.Peer, peersTrees map[string]mt.RemoteMerkleTree, mutex *sync.Mutex) mm.TuiMessage {
	receivedData, err := sendRootRequest(conn, peer)
	if err != nil {
		slog.Warn("Fail during sending root request", "error", err)
		return mm.ConvertErrorToTuiMessage(err)
	}

	hash := mt.ConvertHashBytesToString(receivedData.Hash[:])
	tree := mt.NewRemoteMerkleTree(hash)

	request := pmp.DatumRequestMsg{
		UnsignedMessage: pmp.NewEmptyUnsignedMessage(utility.GenerateID()),
		Hash:            receivedData.Hash,
	}
	return askForData(receivedData.Sender(), conn, request, tree, hash, peersTrees, peer)
}

// return a list with available peers
func ReloadAvailablePeers(server srv_conn.Server) mm.TuiMessage {
	peers, err := server.GetInfoPeers()
	if err != nil {
		slog.Warn("GetInfoPeers returned errors", "errors", err)
	}
	return mm.CreateListPeers(peers)
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
			slog.Error("not matching hashes:", "got", msg.Hash, "expected", reqHash)
			return discoveredType{hash: reqHash, err: errors.New("received hash do not match")}
		}
		return discoveredType{hash: reqHash, msg: msg, err: nil}
	case pmp.ErrorMsg:
		return discoveredType{hash: reqHash, err: errors.New("received error response from peer: " + msg.Message)}
	}
	return discoveredType{hash: reqHash, err: errors.New("received unexpected reply from host")}
}

func sendDatumRequestConcurrently(conn packet_manager.PacketConn, addresses []net.Addr, hash []byte) networking.ReceivedMessageData {
	resultCh := make(chan networking.ReceivedMessageData, len(addresses))

	for _, addr := range addresses {
		go func(addr net.Addr) {
			request := pmp.DatumRequestMsg{
				UnsignedMessage: pmp.NewEmptyUnsignedMessage(utility.GenerateID()),
				Hash:            handler.Hash(hash),
			}
			data := conn.SendRequest(addr, pmp.EncodeMessage(request), networking.NewRetryPolicyRequest())
			resultCh <- data
		}(addr)
	}

	for range addresses {
		res := <-resultCh
		if res.Err == nil {
			return res
		}
	}
	return networking.ReceivedMessageData{Err: errors.New("none of peers responded successfully")}
}
func discoverNodeType(conn packet_manager.PacketConn, peer networking.Peer, nodeHash string,
	tree mt.RemoteMerkleTree, dscvChan chan<- discoveredType) {
	startHash := nodeHash
	hashBytes, err := mt.ConvertStringHashToBytes(nodeHash)
	if err != nil {
		dscvChan <- discoveredType{hash: nodeHash, err: errors.New("invalid hash")}
		return
	}
	for {
		// Check if we have it already in the tree - cache
		if node := tree.GetNode(nodeHash); node != nil && node.Type() != mt.NO_TYPE {
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

		data := sendDatumRequestConcurrently(conn, peer.Addresses, hashBytes)

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
		// If there would be no children this would fail
		err = tree.DiscoverAsBig(nodeHash, dscvType.msg.Children)
		if err != nil {
			dscvChan <- dscvType
			return
		}
		hashBytes = dscvType.msg.Children.Records[0].Hash
		nodeHash = mt.ConvertHashBytesToString(hashBytes)
	}
}

func getFoldersAndFiles(node *mt.RemoteNode,
	peer networking.Peer,
	path string,
	tree mt.RemoteMerkleTree,
	conn packet_manager.PacketConn) ([]mm.TUIFolder, []handler.File, error) {

	subfolders := []mm.TUIFolder{}
	files := []handler.File{}
	for _, child := range node.Children() {
		childHash := child.Hash()
		ch := make(chan discoveredType, 1)
		discoverNodeType(conn, peer, childHash, tree, ch)
		childType := <-ch
		if childType.err != nil {
			slog.Warn("Error discovering child node type", "peer", peer.Name, "childHash", childHash, "err", childType.err)
			return subfolders, files, childType.err
		}
		if childType.cacheType == mt.DIRECTORY || childType.cacheType == mt.CHUNK {
			continue
		}
		if childType.msg.NodeType == mt.DIRECTORY {
			if err := tree.DiscoverAsDirectory(childType.hash, childType.msg.Children); err != nil {
				return subfolders, files, err
			}
			nodeHashBytes, err := mt.ConvertStringHashToBytes(childType.startHash)
			if err != nil {
				return []mm.TUIFolder{}, []handler.File{}, errors.New("failed to convert hash string to bytes")
			}
			if node.Type() == mt.DIRECTORY || len(subfolders) == 0 {
				folder := mm.TUIFolder{
					Hash:       handler.Hash(nodeHashBytes),
					Name:       child.Name(),
					Path:       path + "/" + child.Name(),
					Files:      nil,
					Subfolders: nil,
					Loaded:     false,
					Expanded:   false,
				}
				subfolders = append(subfolders, folder)
			}
		}
		if childType.msg.NodeType == mt.CHUNK {
			if err := tree.DiscoverAsChunk(childType.hash, childType.msg.Data); err != nil {
				return subfolders, files, err
			}
			nodeHashBytes, err := mt.ConvertStringHashToBytes(childType.startHash)
			if err != nil {
				return []mm.TUIFolder{}, []handler.File{}, errors.New("failed to convert hash string to bytes")
			}
			if node.Type() == mt.DIRECTORY || len(subfolders) == 0 {
				file := handler.File{
					Hash: handler.Hash(nodeHashBytes),
					Name: child.Name(),
					Path: path + "/" + child.Name(),
				}
				files = append(files, file)
			}
		}
	}
	return subfolders, files, nil
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
	if node == nil {
		return mm.TuiError("Node does not exist. Hash: " + nodeHash)
	}
	if !node.IsDir() {
		return mm.TuiError("The node is not a directory")
	}
	subfolders, files, err := getFoldersAndFiles(node, message.Peer, message.Path, tree, conn)
	if err != nil {
		return mm.TuiError(err.Error())
	}
	folder := message_manager.TUIFolder{
		Name:       message.Name,
		Path:       message.Path,
		Files:      files,
		Subfolders: subfolders,
		Loaded:     true,
		Expanded:   true,
	}
	return message_manager.CreateTuiFolders(folder)
}

func cacheNodeWorker(conn packet_manager.PacketConn, tree mt.RemoteMerkleTree,
	peer networking.Peer, reqCh chan string, resCh chan int, stopCh chan bool) {
	tryDeferWork := func(hash string) bool {
		select {
		case reqCh <- hash:
			return true
		default:
			slog.Error("File too big to download it efficiently")
			resCh <- -1
			return false
		}
	}
	for {
		select {
		case <-stopCh:
			return
		case hash := <-reqCh:
			slog.Debug("Caching node", "hash", hash)
			// Already in Cache
			if node := tree.GetNode(hash); node != nil && node.Type() != mt.NO_TYPE {
				if node.IsDir() {
					resCh <- -1
					continue
				}
				if node.Type() == mt.CHUNK {
					resCh <- 0
					continue
				}
				if node.Type() != mt.BIG {
					resCh <- -1
					continue
				}
				for _, ch := range node.Children() {
					if ok := tryDeferWork(ch.Hash()); !ok {
						break
					}
				}
				resCh <- len(node.Children())
				continue
			}
			// Download
			hashBytes, err := mt.ConvertStringHashToBytes(hash)
			if err != nil {
				resCh <- -1
				slog.Warn("Failed to convert to bytes", "hash", hash)
				continue
			}
			request := pmp.DatumRequestMsg{
				UnsignedMessage: pmp.NewEmptyUnsignedMessage(utility.GenerateID()),
				Hash:            handler.Hash(hashBytes),
			}
			// FIXME(sormys) send to all addresses, check if any address available
			data := conn.SendRequest(peer.Addresses[0], pmp.EncodeMessage(request),
				networking.NewRetryPolicyRequest())

			if data.Err != nil {
				slog.Warn("Error while receiving reply", "err", data.Err)
				resCh <- -1
				continue
			}
			dscvType := decodeDatumResponse(hash, data)
			if dscvType.err != nil {
				slog.Warn("Error while decoding datum response", "err", dscvType.err)
				resCh <- -1
				continue
			}
			if dscvType.msg.NodeType == mt.CHUNK {
				if err := tree.DiscoverAsChunk(hash, dscvType.msg.Data); err != nil {
					slog.Warn("Error while discovering as chunk", "err", err)
					resCh <- -1
					continue
				}
				resCh <- 0
				continue
			}
			if dscvType.msg.NodeType == mt.DIRECTORY {
				resCh <- -1
				slog.Warn("Invalid type(directory)", "hash", hash)
				continue
			}
			if err := tree.DiscoverAsBig(hash, dscvType.msg.Children); err != nil {
				resCh <- -1
				continue
			}
			for _, ch := range dscvType.msg.Children.Records {
				if ok := tryDeferWork(mt.ConvertHashBytesToString(ch.Hash)); !ok {
					break
				}
			}
			resCh <- len(dscvType.msg.Children.Records)
			continue
		}
	}
}

func cacheFile(conn packet_manager.PacketConn, message mm.BasicFileInfo,
	tree mt.RemoteMerkleTree, nodeHash string) error {
	reqCh := make(chan string, 100000) // Allow for very big files
	resCh := make(chan int, 1000)      // result is how many new nodes have to be queried, -1 means that error has occured
	stopCh := make(chan bool)
	for range DOWNLOAD_THREADS {
		go cacheNodeWorker(conn, tree, message.Peer, reqCh, resCh, stopCh)
	}
	closeWorkers := func() {
		slog.Debug("Closing cache workers")
		for range DOWNLOAD_THREADS {
			stopCh <- true
		}
	}

	reqCh <- nodeHash
	remaining := 1
	for {
		newQueries := <-resCh
		if newQueries == -1 {
			closeWorkers()
			return errors.New("unable to cache file")
		}
		remaining--
		remaining += newQueries
		if remaining == 0 {
			closeWorkers()
			return nil
		}
	}
}

func downloadSubtree(tree mt.RemoteMerkleTree, nodeHash string) []byte {
	node := tree.GetNode(nodeHash)
	if node == nil || (node.Type() != mt.CHUNK && node.Type() != mt.BIG) {
		slog.Error("File was cached correctly but did not find chunk/big node")
		return nil
	}
	if node.Type() == mt.CHUNK {
		return node.Data()
	}
	// mt.BIG
	var data bytes.Buffer
	for _, ch := range node.Children() {
		chData := downloadSubtree(tree, ch.Hash())
		if chData == nil {
			return nil
		}
		data.Write(chData)
	}
	return data.Bytes()
}

func downloadFile(conn packet_manager.PacketConn, message mm.BasicFileInfo,
	tree mt.RemoteMerkleTree, nodeHash string) []byte {
	if err := cacheFile(conn, message, tree, nodeHash); err != nil {
		return nil
	}
	slog.Debug("file has been cached successfuly, gathering data...", "hash", nodeHash)
	return downloadSubtree(tree, nodeHash)
}

func DownloadFile(conn packet_manager.PacketConn, message mm.BasicFileInfo,
	peersTrees map[string]mt.RemoteMerkleTree, treeMutex *sync.Mutex) mm.TuiMessage {
	treeMutex.Lock()
	defer treeMutex.Unlock()
	tree, exist := peersTrees[message.Peer.Name]
	if !exist {
		return mm.TuiError("No tree for given peer")
	}
	nodeHash := mt.ConvertHashBytesToString(message.Hash[:])
	node := tree.GetNode(nodeHash)
	if node == nil {
		return mm.TuiError("Node does not exist. Hash: " + nodeHash)
	}
	if !node.IsFile() {
		return mm.TuiError("The node is not a File")
	}
	slog.Info("Downloading file started")
	data := downloadFile(conn, message, tree, nodeHash)
	if data == nil {
		return mm.TuiError("Failed to download file data")
	}

	// Save data to tmp.tmp file
	slog.Debug("Downloaded file data", "data", message.Name)
	path, err := getDownloadPath(message.Peer.Name, message.Name)
	if err != nil {
		return mm.TuiInfo("Failed to create Folder to downloading" + message.Name)
	}
	err = os.WriteFile(path, data, 0644)
	if err != nil {
		return mm.TuiError("Failed to save file: " + err.Error())
	}

	slog.Debug("File saved successfully", "filename", message.Name, "size", len(data))
	return mm.TuiInfo("File downloaded and saved in" + path)
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
					data = StartConnection(conn, message.Payload().([]networking.Peer)[0], nickname)
				}
			case mm.RELOAD_CONTENT:
				{
					// data = ReloadPeerContent(conn, message.Payload().(mm.TuiMessageBasicInfo))

					// in this state handler should reset all his states!

					for k := range peersTrees {
						delete(peersTrees, k)
					}
					ClearMap()
					data = ReloadAvailablePeers(server)
				}
			case mm.EXPAND_FOLDER:
				{
					// In this case the folder's contens are not yet loaded in the TUI.
					// Check if the contents are available in the cache. If not,
					// send a request to fetch data. Expected output is TuiMessage -> see expandFolder

					data = GetDirectoryContent(conn, message.Payload().(mm.BasicFolder), peersTrees, &mutex)
				}
			case mm.DOWNLOAD:
				{
					data = DownloadFile(conn, message.Payload().(mm.BasicFileInfo), peersTrees, &mutex)
				}

			case mm.SHOW_DATA:
				{
					// In this case we want discover user's file. So you have to sent RootRequest
					user := message.Payload().([]networking.Peer)[0]
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
