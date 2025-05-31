package srv_conn

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"mimuw_zps/src/encryption"
	"net/http"
	"net/url"
	"strings"
)

const PEERS_ENDPOINT = "peers"
const ADDRESS_ENDPOINT = "addresses"
const KEY_ENDPOINT = "key"

// Struct used for connection to central server under provided url
type Server struct {
	url string
}

// Creates new instance of Server object with provided url
func NewServer(url string) Server {
	return Server{url: url}
}

// Sends request to server to register private key under the nickname
func (s Server) RegisterKey(nickname string, key encryption.Key) error {
	url, err := url.JoinPath(s.url, PEERS_ENDPOINT, nickname, KEY_ENDPOINT)
	if err != nil {
		slog.Error("Failed to create registation url",
			"base url", s.url, "nickname", nickname, "err", err)
		return err
	}
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
	return errors.New("received wrong response from server")
}

// Gets list of available peers from server
func (s Server) GetPeers() ([]string, error) {
	url, err := url.JoinPath(s.url, PEERS_ENDPOINT)
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
		return []string{}, errors.New("failed to get list of peers")
	}
	return splitLines(body), nil
}

// Gets public key registered under the nickname from server
func (s Server) GetPeerKey(nickname string) (encryption.Key, error) {
	url, err := url.JoinPath(s.url, PEERS_ENDPOINT, nickname, KEY_ENDPOINT)
	if err != nil {
		slog.Error("Failed to create url of server")
		return encryption.Key{}, err
	}
	response, err := http.Get(url)
	if err != nil {
		slog.Warn("Failed to get list of peers", "err", err)
		return encryption.Key{}, err
	}
	defer response.Body.Close()
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		slog.Warn("Failed to get response body", "err", err,
			"status code", response.StatusCode, "peer", nickname)
		return encryption.Key{}, err
	}
	if response.StatusCode != http.StatusOK {
		slog.Warn("Failed to get peer key", "peer", nickname,
			"status code", response.StatusCode)
		return encryption.Key{}, errors.New("failed to get peer key")
	}
	if len(bodyBytes) != encryption.KEY_LENGTH {
		slog.Warn("Received key from server of wrong length",
			"length", len(bodyBytes))
		return encryption.Key{}, errors.New("wrong key from server")
	}
	return encryption.Key(bodyBytes), nil
}

// Gets addresses registered under the nickname from server
func (s Server) GetPeerAddresses(nickname string) ([]string, error) {
	url, err := url.JoinPath(s.url, PEERS_ENDPOINT, nickname, ADDRESS_ENDPOINT)
	if err != nil {
		slog.Error("Failed to create url of server")
		return []string{}, err
	}
	response, err := http.Get(url)
	if err != nil {
		slog.Warn("Failed to get list of peers", "err", err)
		return []string{}, err
	}
	defer response.Body.Close()
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		slog.Warn("Failed to get response body", "err", err,
			"status code", response.StatusCode, "peer", nickname)
		return []string{}, err
	}
	if response.StatusCode != http.StatusOK {
		slog.Warn("Failed to get peer addresses", "peer", nickname,
			"status code", response.StatusCode)
		return []string{}, errors.New("failed to get peer addresses")
	}
	body := string(bodyBytes)
	return splitLines(body), nil
}

func splitLines(str string) []string {
	lines := strings.Split(str, "\n")
	// Remove empty line from split
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}
