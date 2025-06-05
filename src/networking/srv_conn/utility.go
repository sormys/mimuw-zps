package srv_conn

import (
	"bytes"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/utility"
	"net"
)

const HELLO_REPLY uint8 = 120

var HELLO = []byte{0x00}

func createHandshakeBytes(nickname string, id utility.ID) []byte {
	extensions := []byte{0x00, 0x00, 0x00, 0x00}
	name := []byte(nickname)
	length := utility.GetBytesFromNumber(len(name))

	message := utility.GenerateEmptyBuffor()
	message = append(message, id[:]...)
	message = append(message, HELLO...)
	message = append(message, length...)
	message = append(message, extensions...)
	message = append(message, name...)

	signature := encryption.GetSignature(message)
	message = append(message, signature[:]...)
	return message
}

func verifyHandshakeServer(data []byte, id utility.ID) bool {
	id2 := utility.GetMessageID(data)
	if bytes.Equal(id2[:], id[:]) {
		return false
	}
	if utility.GetMessageType(data) != HELLO_REPLY {
		return false
	}
	return true
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
