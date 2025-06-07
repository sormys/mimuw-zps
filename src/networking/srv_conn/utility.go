package srv_conn

import (
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/utility"
	"net"
	"strings"
)

const HELLO_REPLY uint8 = 120

var HELLO = []byte{0x01}

func getExtensions() []byte {
	return []byte{0x00, 0x00, 0x00, 0x00}
}

func CreateHandshakeBytes(typeMessage encryption.TypeMessage, nickname string, id utility.ID) []byte {
	extensions := getExtensions()
	name := []byte(nickname)
	length := utility.GetBytesFromNumber(len(name) + 4)
	message := utility.GenerateEmptyBuffor()
	message = append(message, id[:]...)
	message = append(message, typeMessage...)
	message = append(message, length...)
	message = append(message, extensions...)
	message = append(message, name...)

	signature := encryption.GetSignature(message)
	message = append(message, signature[:]...)
	return message
}

func convertStringToAddr(string_addresses []string) ([]net.Addr, []error) {
	var addrs []net.Addr
	var errors []error
	for _, addrStr := range string_addresses {
		addr, err := net.ResolveUDPAddr("udp", addrStr)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		addrs = append(addrs, addr)
	}
	return addrs, errors
}

func getUDPaddr(addr string) (*net.UDPAddr, error) {
	if strings.Count(addr, ":") < 2 {
		return net.ResolveUDPAddr("udp4", addr)
	}
	return net.ResolveUDPAddr("udp6", addr)
}
