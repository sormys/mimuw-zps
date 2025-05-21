package receiver_test

import (
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/networking/receiver"
	"net"
	"testing"
)

func correctRequest(typeMessage []byte) []byte {
	id := make([]byte, 4)
	extensions := []byte{0x00, 0x00, 0x00, 0x00}
	name := []byte("Mozart")
	length := []byte{0x00, 0x00}

	message := make([]byte, 0)
	message = append(message, id...)
	message = append(message, typeMessage...)
	message = append(message, length...)
	message = append(message, extensions...)
	message = append(message, name...)

	return message
}

// ========================= Receiver.Receiver =========================
func TestCorrectHello(t *testing.T) {
	sender := "0.0.0.0:2138"
	receiver_address := "0.0.0.0:2137"
	name := "koziolek"
	var emptyKey encryption.Key

	go receiver.Receiver(receiver_address, name, emptyKey)

	receiver, err := net.ResolveUDPAddr("udp", receiver_address)
	if err != nil {
		t.Fatalf("Failed to resolve UDP address: %v", err)
	}
	testReceiver, err := net.ListenPacket("udp", sender)
	if err != nil {
		t.Errorf("Fail during creating socket")
	}

	hello := []byte{0x00}
	n, err := testReceiver.WriteTo(correctRequest(hello), receiver)

	defer testReceiver.Close()

	if n <= 0 || err != nil {
		t.Errorf("Failed to send correct Request")
	}
}

func TestCorrectHelloReply(t *testing.T) {
	sender := "0.0.0.0:2138"
	receiver_address := "0.0.0.0:2137"
	name := "koziolek"
	var emptyKey encryption.Key

	go receiver.Receiver(receiver_address, name, emptyKey)

	receiver, err := net.ResolveUDPAddr("udp", receiver_address)
	if err != nil {
		t.Fatalf("Failed to resolve UDP address: %v", err)
	}
	testReceiver, err := net.ListenPacket("udp", sender)
	if err != nil {
		t.Errorf("Fail during creating socket")
	}

	helloReply := []byte{0x00}
	n, err := testReceiver.WriteTo(correctRequest(helloReply), receiver)

	defer testReceiver.Close()

	if n <= 0 || err != nil {
		t.Errorf("Failed to send correct Request")
	}
}
