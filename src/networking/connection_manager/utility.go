package connection_manager

import (
	"bytes"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/networking/packet_manager"
	"mimuw_zps/src/networking/srv_conn"
	"mimuw_zps/src/utility"
	"net"
	"strings"
)

var (
	HELLO         = encryption.TypeMessage([]byte{0x00})
	EMPTY_LENGTH  = encryption.TypeMessage([]byte{0x00, 0x00})
	HELLO_REPLY   = encryption.TypeMessage([]byte{0x82})
	ROOT_REQUEST  = encryption.TypeMessage([]byte{0x02})
	ERROR         = encryption.TypeMessage([]byte{0x81})
	DATUM_REQUEST = encryption.TypeMessage([]byte{0x03})
)

func printAddreses(addresses []net.Addr) string {
	var result []string
	for _, ad := range addresses {
		addressString := "[" + ad.String() + "]"
		result = append(result, addressString)
	}
	return "[" + strings.Join(result, ", ") + "]"
}

func verifyIdAndType(data networking.ReceivedMessageData, id utility.ID, expectedType networking.MessageType) bool {
	id2 := data.ID
	if !bytes.Equal(id2[:], id[:]) || data.MessType != expectedType {
		return false
	}
	return true
}

func getHashFromRootReply(data networking.ReceivedMessageData) message_manager.Hash {
	if len(data.Data) != 2+32 {
		return message_manager.Hash{}
	}
	var hash message_manager.Hash
	copy(hash[:], data.Data[2:2+32])
	return hash
}

func getNameFromReceivedHandshake(data []byte) string {
	nameLen := utility.GetNumberFromBytes(data)
	if len(data) < int(nameLen)+2 {
		return ""
	}
	nameBytes := data[2 : 2+int(nameLen)]
	return string(nameBytes)
}

func getSignatureFromReceivedHandshake(data []byte) encryption.Signature {
	nameLen := utility.GetNumberFromBytes(data)
	if len(data) < int(nameLen)+2+32 {
		return encryption.EMPTY_SIGNATURE
	}
	return encryption.Signature(data[2+nameLen:])
}

func CreateHandshake(address net.Addr, id utility.ID, nickname string) packet_manager.PacketSendRequest {
	message := srv_conn.CreateHandshakeBytes(HELLO, nickname, id)
	return packet_manager.PacketSendRequest{Addr: address, Message: message, MessRetryPolicy: RetryPolicyHandshake{}}
}
func createHandshakeReply(address net.Addr, id utility.ID, nickname string) packet_manager.PacketSendRequest {
	message := srv_conn.CreateHandshakeBytes(HELLO_REPLY, nickname, id)
	return packet_manager.PacketSendRequest{Addr: address, Message: message, MessRetryPolicy: RetryPolicyReply{}}
}

func createDatumRequestTemplate(id utility.ID, messageType encryption.TypeMessage, hash message_manager.Hash) encryption.Message {
	length := utility.GetBytesFromNumber(message_manager.HASH_LENGTH)

	message := utility.GenerateEmptyBuffor()
	message = append(message, id[:]...)
	message = append(message, messageType...)
	message = append(message, length...)
	message = append(message, hash[:]...)
	return message
}
func createRootRequest(address net.Addr, id utility.ID) packet_manager.PacketSendRequest {
	message := createDatumRequestTemplate(id, ROOT_REQUEST, message_manager.Hash{})
	return packet_manager.PacketSendRequest{Addr: address, Message: message, MessRetryPolicy: RetryPolicyRequest{}}
}

func createErrorReply(address net.Addr, err error) packet_manager.PacketSendRequest {

	error_string := err.Error()
	length := utility.GetBytesFromNumber(len(error_string))
	id := utility.GenerateID()

	message := utility.GenerateEmptyBuffor()
	message = append(message, id[:]...)
	message = append(message, ERROR...)
	message = append(message, length...)
	message = append(message, []byte(error_string)...)
	return packet_manager.PacketSendRequest{Addr: address, Message: message, MessRetryPolicy: RetryPolicyReply{}}
}

func createDatumRequest(address net.Addr, hash message_manager.Hash) packet_manager.PacketSendRequest {
	id := utility.GenerateID()
	message := createDatumRequestTemplate(id, DATUM_REQUEST, hash)
	return packet_manager.PacketSendRequest{Addr: address, Message: message, MessRetryPolicy: RetryPolicyRequest{}}
}
