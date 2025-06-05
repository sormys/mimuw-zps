package connection_manager

import (
	"bytes"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/networking/packet_manager"
	"mimuw_zps/src/utility"
	"net"
	"strings"
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

func CreateHandshake(address net.Addr, id utility.ID) packet_manager.PacketSendRequest
func createHandshakeReply(address net.Addr, id utility.ID) packet_manager.PacketSendRequest
func createRootRequest(address net.Addr, id utility.ID) packet_manager.PacketSendRequest
func createErrorReply(address net.Addr, err error) packet_manager.PacketSendRequest
func createDatumRequest(address net.Addr, hash message_manager.Hash) packet_manager.PacketSendRequest
