package peer_conn

import (
	"mimuw_zps/src/encryption"
	"testing"
)

func TestSendHandshake(t *testing.T) {
	//how to get name, addresses and key?
	peer := NewPeer("test", []string{"51.210.14.2:8443"}, encryption.Key{})

	if !peer.SendHandshake(peer) {
		t.Errorf("Failed to send handshake")
	}

}
