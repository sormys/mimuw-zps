package srv_conn

import (
	"bytes"
	"fmt"
	"io"
	"mimuw_zps/src/encryption"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"testing"
)

func equalArrays(arr1 []string, arr2 []string) bool {
	sort.Strings(arr1)
	sort.Strings(arr2)
	return slices.Equal(arr1, arr2)
}

// ========================= Server.RegisterKey =========================

func registerKeyServer(t *testing.T, peerNickname string,
	key encryption.Key, statusCode int) *httptest.Server {
	return httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != fmt.Sprintf("/peers/%s/key", peerNickname) {
				t.Errorf("Expected to request '/peers/%s/key', got: %s",
					peerNickname, r.URL.Path)
			}
			if r.Method != http.MethodPut {
				t.Errorf("Expected to receive PUT request, got %s instead", r.Method)
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
	peerKey := encryption.Key{}
	for i := range encryption.KEY_LENGTH {
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
	peerKey := encryption.Key{}
	for i := range encryption.KEY_LENGTH {
		peerKey[i] = byte(i + 1)
	}
	testServer := registerKeyServer(t, peerNickname, peerKey,
		http.StatusInternalServerError)
	defer testServer.Close()

	server := NewServer(testServer.URL)
	err := server.RegisterKey(peerNickname, peerKey)

	if err == nil {
		t.Errorf("server failed but no error has not occured")
	}
}

// ========================= Server.GetPeers ============================

func getPeersServer(t *testing.T, statusCode int, responseBytes []byte) *httptest.Server {
	return httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/peers" {
				t.Errorf("Expected to request '/peers', got: %s", r.URL.Path)
			}
			if r.Method != http.MethodGet {
				t.Errorf("Expected to receive GET request, got %s instead",
					r.Method)
			}
			w.WriteHeader(statusCode)
			w.Write(responseBytes)
		}))
}

func TestGetPeersCorrectResponse(t *testing.T) {
	peer1 := "test_peer"
	peer2 := "ultimate_peer"
	requiredPeersString := fmt.Sprintf("%s\n%s\n", peer1, peer2)
	requiredPeers := []string{peer1, peer2}
	testServer := getPeersServer(t, http.StatusOK, []byte(requiredPeersString))
	defer testServer.Close()

	server := NewServer(testServer.URL)
	peers, err := server.GetPeers()

	if err != nil {
		t.Errorf("Failed to get list of peers with error:\n\"%s\"", err)
	}

	if !equalArrays(requiredPeers, peers) {
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

// ========================= Server.GetPeerKey ==========================

func getPeerKeyServer(t *testing.T, peerNickname string,
	returnData []byte, statusCode int) *httptest.Server {
	return httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != fmt.Sprintf("/peers/%s/key", peerNickname) {
				t.Errorf("Expected to request '/peers/%s/key', got: %s",
					peerNickname, r.URL.Path)
			}
			if r.Method != http.MethodGet {
				t.Errorf("Expected to receive GET request, got %s instead",
					r.Method)
			}
			w.WriteHeader(statusCode)
			w.Write(returnData)
		}))
}

func TestGetPeerKeyCorrectResponse(t *testing.T) {
	peerNickname := "pudzian"
	expectedPeerKey := encryption.Key{}
	for i := range encryption.KEY_LENGTH {
		expectedPeerKey[i] = byte(i + 1)
	}
	testServer := getPeerKeyServer(t, peerNickname, expectedPeerKey[:],
		http.StatusOK)
	defer testServer.Close()

	server := NewServer(testServer.URL)
	res, err := server.GetPeerKey(peerNickname)

	if err != nil {
		t.Errorf("Failed to get key of the peer")
	}
	if !bytes.Equal(expectedPeerKey[:], res[:]) {
		t.Errorf("GetPeerKey returned incorrect peer key")
	}
}

func TestGetPeerKeyIncorrectResponse(t *testing.T) {
	peerNickname := "pudzian"
	// Not a correct key
	expectedPeerKey := [30]byte{}
	for i := range 30 {
		expectedPeerKey[i] = byte(i + 1)
	}
	testServer := getPeerKeyServer(t, peerNickname, expectedPeerKey[:],
		http.StatusOK)
	defer testServer.Close()

	server := NewServer(testServer.URL)
	_, err := server.GetPeerKey(peerNickname)

	if err == nil {
		t.Errorf("Got incorrect response from server but error did not occur")
	}
}

func TestGetPeerKeyInternalServerError(t *testing.T) {
	peerNickname := "pudzian"
	testServer := getPeerKeyServer(t, peerNickname,
		[]byte("Server error occured"),
		http.StatusInternalServerError)
	defer testServer.Close()

	server := NewServer(testServer.URL)
	_, err := server.GetPeerKey(peerNickname)

	if err == nil {
		t.Errorf("Got 500 response from server but error did not occur")
	}
}

// ======================= Server.GetPeerAdresses =======================

func getPeerAddressesServer(t *testing.T, peerNickname string,
	returnData []byte, statusCode int) *httptest.Server {
	return httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != fmt.Sprintf("/peers/%s/addresses", peerNickname) {
				t.Errorf("Expected to request '/peers/%s/addresses', got: %s",
					peerNickname, r.URL.Path)
			}
			if r.Method != http.MethodGet {
				t.Errorf("Expected to receive GET request, got %s instead", r.Method)
			}
			w.WriteHeader(statusCode)
			w.Write(returnData)
		}))
}

func TestGetPeersAddressesCorrectResponse(t *testing.T) {
	peerNickname := "koziolek"
	address1 := "127.0.0.1"
	address2 := "120.80.24.12"
	peerAddressesString := fmt.Sprintf("%s\n%s\n", address1, address2)
	requiredAddresses := []string{address1, address2}
	testServer := getPeerAddressesServer(t, peerNickname,
		[]byte(peerAddressesString), http.StatusOK)
	defer testServer.Close()

	server := NewServer(testServer.URL)
	addresses, err := server.GetPeerAddresses(peerNickname)

	if err != nil {
		t.Errorf("Failed to get addresses of a peer with err:\n\"%s\"", err)
	}
	if !equalArrays(requiredAddresses, addresses) {
		t.Errorf("Got incorrect list of addresses\nexpected:%s\ngot:%s",
			requiredAddresses, addresses)
	}
}

func TestGetPeersAddressesInternalServerError(t *testing.T) {
	peerNickname := "koziolek"
	testServer := getPeerAddressesServer(t, peerNickname,
		[]byte("Server error occured"), http.StatusInternalServerError)
	defer testServer.Close()

	server := NewServer(testServer.URL)
	_, err := server.GetPeerAddresses(peerNickname)

	if err == nil {
		t.Errorf("Server failed but error did not occur")
	}
}
