package srv_conn

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func registerKeyServer(t *testing.T, peerNickname string,
	key [64]byte, statusCode int) *httptest.Server {
	return httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != fmt.Sprintf("/peers/%s/key", peerNickname) {
				t.Errorf("Expected to request '/peers/%s/key', got: %s",
					peerNickname, r.URL.Path)
			}
			defer r.Body.Close()
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil || !bytes.Equal(key[:], bodyBytes) {
				t.Errorf(
					"Invalid body of request, err=%s, received bytes=%d, expected bytes=%d",
					err, bodyBytes, key[:])
			}
			w.WriteHeader(statusCode)
		}))
}

func TestRegisterKeyCorrectResponse(t *testing.T) {
	peerNickname := "test_peer"
	peerKey := [64]byte{}
	for i := range 64 {
		peerKey[i] = byte(i + 1)
	}
	testServer := registerKeyServer(t, peerNickname, peerKey,
		http.StatusNoContent)
	defer testServer.Close()

	server := NewServer(testServer.URL)
	err := server.RegisterKey(peerNickname, peerKey)

	if err != nil {
		t.Errorf("Failed to register key with error:\n\"%s\"", err)
	}
}

func TestRegisterKeyServerError(t *testing.T) {
	peerNickname := "test_peer"
	peerKey := [64]byte{}
	for i := range 64 {
		peerKey[i] = byte(i + 1)
	}
	testServer := registerKeyServer(t, peerNickname, peerKey,
		http.StatusInternalServerError)
	defer testServer.Close()

	server := NewServer(testServer.URL)
	err := server.RegisterKey(peerNickname, peerKey)

	if err == nil {
		t.Errorf("server failed but no error was returned.")
	}
}

func getPeersServer(t *testing.T, statusCode int, responseBytes []byte) *httptest.Server {
	return httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/peers" {
				t.Errorf("Expected to request '/peers', got: %s", r.URL.Path)
			}
			w.WriteHeader(statusCode)
			w.Write(responseBytes)
		}))
}

func TestGetPeersCorrectResponse(t *testing.T) {
	test_peer1 := "test_peer"
	test_peer2 := "ultimate_peer"
	requiredPeersString := fmt.Sprintf("%s\n%s\n", test_peer1, test_peer2)
	requiredPeers := []string{test_peer1, test_peer2}
	testServer := getPeersServer(t, http.StatusOK, []byte(requiredPeersString))
	defer testServer.Close()

	server := NewServer(testServer.URL)
	peers, err := server.GetPeers()

	if err != nil {
		t.Errorf("Failed to get list of peers with error:\n\"%s\"", err)
	}

	if len(peers) != 2 ||
		!((test_peer1 == peers[0]) != (test_peer1 == peers[1])) ||
		!((test_peer2 == peers[0]) != (test_peer2 == peers[1])) {
		t.Errorf("Got incorrect list of peers,\nexpected: %s,\ngot: %s",
			requiredPeers, peers)
	}
}

func TestGetPeersServerError(t *testing.T) {
	testServer := getPeersServer(t, http.StatusInternalServerError,
		[]byte("Intentional internal server error"))
	defer testServer.Close()

	server := NewServer(testServer.URL)
	_, err := server.GetPeers()

	if err == nil {
		t.Error("Server failed but no error was returned")
	}
}
