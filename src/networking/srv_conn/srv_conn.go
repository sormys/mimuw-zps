package srv_conn

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

const PEERS_ENDPOINT = "peers"

var EmptyKey [64]byte

type Server struct {
	url string
}

func NewServer(url string) Server {
	return Server{url: url}
}

// TODO: add constant for length of the key (maybe even a type?)
func (s Server) Register(nickname string, key [64]byte) error {
	// Construct registration url
	url, err := url.JoinPath(s.url, PEERS_ENDPOINT, nickname, "key")
	if err != nil {
		slog.Error("Failed to create registation url",
			"base url", s.url, "nickname", nickname, "err", err)
		return err
	}
	// Create registration request
	request, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(key[:]))
	if err != nil {
		slog.Error("Failed to create register request", "err", err)
		return err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		slog.Warn("Failed to send register request to server", "err", err)
		return err
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		slog.Info("Successfully registered to server!",
			"status code", response.StatusCode)
		return nil
	}
	defer response.Body.Close()
	body := ""
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		slog.Warn("Failed to read response from server", "err", err)
	} else {
		body = string(bodyBytes)
	}
	slog.Warn("Failed to register to server!",
		"nickname", nickname,
		"status code", response.StatusCode,
		"response body", body)
	return errors.New(body)
}

func (s Server) GetPeers() ([]string, error) {
	url, err := url.JoinPath(s.url, "peers")
	if err != nil {
		slog.Error("Failed to create url for peer endpoint")
		return []string{}, err
	}
	response, err := http.Get(url)
	if err != nil {
		slog.Warn("Failed to send get request to the server", "err", err)
		return []string{}, err
	}
	defer response.Body.Close()
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		slog.Warn("Failed to get response body", "err", err,
			"status code", response.StatusCode)
		return []string{}, err
	}
	body := string(bodyBytes)
	if response.StatusCode != http.StatusOK {
		slog.Warn("Failed to get list of peers",
			"status code", response.StatusCode, "body", body)
		return []string{}, err
	}
	peers := strings.Split(body, "\n")
	// Remove empty line from split
	if len(peers) > 0 && peers[len(peers)-1] == "" {
		peers = peers[:len(peers)-1]
	}
	return peers, nil
}

func (s Server) GetPeerKey(peerNickname string) ([64]byte, error) {
	url, err := url.JoinPath(s.url, "peers", peerNickname, "key")
	if err != nil {
		slog.Error("Failed to create url of server")
		return EmptyKey, err
	}
	response, err := http.Get(url)
	if err != nil {
		slog.Warn("Failed to get list of peers", "err", err)
		return EmptyKey, err
	}
	defer response.Body.Close()
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		slog.Warn("Failed to get response body", "err", err,
			"status code", response.StatusCode, "peer", peerNickname)
		return EmptyKey, err
	}
	if response.StatusCode != http.StatusOK {
		slog.Warn("Failed to get peer key", "peer", peerNickname,
			"status code", response.StatusCode)
		return EmptyKey, errors.New("failed to get peer key")
	}
	if len(bodyBytes) != 64 {
		slog.Warn("Received key from server of wrong lenght",
			"length", len(bodyBytes))
		return EmptyKey, errors.New("wrong key from server")
	}
	return [64]byte(bodyBytes), nil
}
