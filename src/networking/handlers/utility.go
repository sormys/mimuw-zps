package handlers

import (
	"log/slog"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/networking/packet_manager"
	pmp "mimuw_zps/src/peer_message_parser"
	"mimuw_zps/src/utility"
	"net"
	"strings"
	"sync"
	"time"
)

type PeerStatus struct {
	outgoing   bool
	lastPing   time.Time
	peer       networking.Peer
	extensions pmp.Extensions
}

var connectedPeers map[string]PeerStatus
var mutex sync.Mutex

func init() {
	connectedPeers = map[string]PeerStatus{}
	mutex = sync.Mutex{}
}

func ConnectPeer(outgoing bool, peer networking.Peer, extensions pmp.Extensions) {
	mutex.Lock()
	defer mutex.Unlock()
	connectedPeers[peer.Name] = PeerStatus{outgoing: outgoing,
		lastPing: time.Now(), peer: peer, extensions: extensions}
}

func GetPeersWithExtension(extesionsMask pmp.Extensions) []networking.Peer {
	mutex.Lock()
	defer mutex.Unlock()
	foundPeers := []networking.Peer{}
	for _, peer := range connectedPeers {
		hasExtensions := true
		for i := range peer.extensions {
			if peer.extensions[i]&extesionsMask[i] != extesionsMask[i] {
				hasExtensions = false
				break
			}
		}
		if hasExtensions {
			foundPeers = append(foundPeers, peer.peer)
		}
	}
	return foundPeers
}

func tryPingPeer(conn packet_manager.PacketConn, peer networking.Peer) {
	ping := pmp.PingMsg{
		UnsignedMessage: pmp.NewEmptyUnsignedMessage(utility.GenerateID()),
	}
	for _, addr := range peer.Addresses {
		reply := conn.SendRequest(addr, pmp.EncodeMessage(ping),
			networking.NewRetryPolicyRequest())
		decoded, err := pmp.DecodeMessage(reply)
		if err != nil {
			slog.Warn("Error while pinging", "nickname", peer.Name, "err", err)
			continue
		}
		switch msg := decoded.(type) {
		case pmp.ErrorMsg:
			slog.Warn("Received error reply to ping", "nickname", peer.Name, "message", msg.Message)
		case pmp.PongMsg:
			mutex.Lock()
			defer mutex.Unlock()
			status, exists := connectedPeers[peer.Name]
			if !exists {
				slog.Debug("Pinged user that is no longer connected", "nickname", peer.Name)
				return
			}
			status.lastPing = time.Now()
			connectedPeers[peer.Name] = status
			slog.Debug("Connection refreshed!", "peer", peer.Name)
			continue
		default:
			slog.Warn("Received unexpected reply to ping", "nickname", peer.Name, "message type", msg.Type())
		}
	}
	mutex.Lock()
	defer mutex.Unlock()
	status, exists := connectedPeers[peer.Name]
	if !exists {
		return
	}
	if time.Since(status.lastPing) > 5*time.Minute {
		delete(connectedPeers, peer.Name)
		slog.Info("Removed peer due to ping timeout", "nickname", peer.Name)
	}
}

func RunAutoRefreshConnections(conn packet_manager.PacketConn) {
	for {
		time.Sleep(2 * time.Minute)

		mutex.Lock()
		peers := make([]networking.Peer, 0, len(connectedPeers))
		for _, status := range connectedPeers {
			peers = append(peers, status.peer)
		}
		mutex.Unlock()

		for _, peer := range peers {
			go tryPingPeer(conn, peer)
		}
	}
}

func ClearMap() {
	mutex.Lock()
	defer mutex.Unlock()
	for k := range connectedPeers {
		delete(connectedPeers, k)
	}
}

func ContainsUser(addr net.Addr) bool {
	mutex.Lock()
	defer mutex.Unlock()
	for _, status := range connectedPeers {
		for _, a := range status.peer.Addresses {
			if a.String() == addr.String() {
				return true
			}
		}
	}
	return false
}

func printAddreses(addresses []net.Addr) string {
	result := make([]string, len(addresses))

	for i, addr := range addresses {
		result[i] = "[" + addr.String() + "]"
	}
	return strings.Join(result, ", ")
}
