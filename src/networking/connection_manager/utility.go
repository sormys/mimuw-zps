package connection_manager

import (
	"bytes"
	"log/slog"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/handler"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/networking/packet_manager"
	"mimuw_zps/src/networking/srv_conn"
	"mimuw_zps/src/utility"
	"net"
	"strings"
)

var (
	HELLO         = encryption.TypeMessage([]byte{0x01})
	EMPTY_LENGTH  = encryption.TypeMessage([]byte{0x00, 0x00})
	HELLO_REPLY   = encryption.TypeMessage([]byte{0x82})
	ROOT_REQUEST  = encryption.TypeMessage([]byte{0x02})
	ERROR         = encryption.TypeMessage([]byte{0x81})
	DATUM_REQUEST = encryption.TypeMessage([]byte{0x03})
)

const EXT_LEN = 4

func printAddreses(addresses []net.Addr) string {
	result := make([]string, len(addresses))

	for i, addr := range addresses {
		result[i] = "[" + addr.String() + "]"
	}
	return strings.Join(result, ", ")
}

func verifyIdAndType(data networking.ReceivedMessageData, id utility.ID, expectedType networking.MessageType) bool {
	id2 := data.ID
	if !bytes.Equal(id2[:], id[:]) || data.MessType != expectedType {
		return false
	}
	return true
}

func getHashFromRootReply(data networking.ReceivedMessageData) handler.Hash {
	if len(data.Data) != 2+32 {
		return handler.Hash{}
	}
	var hash handler.Hash
	copy(hash[:], data.Data[2:])
	return hash
}

func getNameFromReceivedHandshake(data networking.ReceivedMessageData) string {
	nameBytes := data.Data[EXT_LEN:data.Length]
	slog.Debug("Got name from Hanshake", "name", string(nameBytes))
	return string(nameBytes)
}

func getSignatureFromReceivedHandshake(data networking.ReceivedMessageData) encryption.Signature {
	if len(data.Data) < int(data.Length)+encryption.KEY_LENGTH {
		return encryption.EMPTY_SIGNATURE
	}
	return encryption.Signature(data.Data[data.Length : data.Length+encryption.KEY_LENGTH])
}

func CreateHandshake(address net.Addr, id utility.ID, nickname string) packet_manager.PacketSendRequest {
	message := srv_conn.CreateHandshakeBytes(HELLO, nickname, id)
	return packet_manager.PacketSendRequest{Addr: address, Message: message, MessRetryPolicy: networking.NewPolicyHandshake()}
}
func createHandshakeReply(address net.Addr, id utility.ID, nickname string) packet_manager.PacketSendRequest {
	message := srv_conn.CreateHandshakeBytes(HELLO_REPLY, nickname, id)
	return packet_manager.PacketSendRequest{Addr: address, Message: message, MessRetryPolicy: networking.NewPolicyHandshake()}
}

func createDatumRequestTemplate(id utility.ID, messageType encryption.TypeMessage, hash handler.Hash) encryption.Message {
	length := utility.GetBytesFromNumber(handler.HASH_LENGTH)

	message := utility.GenerateEmptyBuffor()
	message = append(message, id[:]...)
	message = append(message, messageType...)
	message = append(message, length...)
	message = append(message, hash[:]...)
	return message
}
func createRootRequest(address net.Addr, id utility.ID) packet_manager.PacketSendRequest {
	message := createDatumRequestTemplate(id, ROOT_REQUEST, handler.Hash{})
	return packet_manager.PacketSendRequest{Addr: address, Message: message, MessRetryPolicy: networking.NewRetryPolicyRequest()}
}

func createErrorReply(address net.Addr, err error) packet_manager.PacketSendRequest {
	var error_string string = "nil"
	if err != nil {
		error_string = err.Error()
	}

	length := utility.GetBytesFromNumber(len(error_string))
	id := utility.GenerateID()

	message := utility.GenerateEmptyBuffor()
	message = append(message, id[:]...)
	message = append(message, ERROR...)
	message = append(message, length...)
	message = append(message, []byte(error_string)...)
	return packet_manager.PacketSendRequest{Addr: address, Message: message, MessRetryPolicy: networking.NewPolicyHandshake()}
}

func createDatumRequest(address net.Addr, hash handler.Hash) packet_manager.PacketSendRequest {
	id := utility.GenerateID()
	message := createDatumRequestTemplate(id, DATUM_REQUEST, hash)
	return packet_manager.PacketSendRequest{Addr: address, Message: message, MessRetryPolicy: networking.NewRetryPolicyRequest()}
}
