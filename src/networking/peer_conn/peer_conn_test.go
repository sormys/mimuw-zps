package peer_conn

import (
	"bytes"
	"log/slog"
	"mimuw_zps/src/encryption"
	"mimuw_zps/src/utility"
	"net"
	"os"
	"testing"
	"time"
)

var ch chan string
var myAddress = "localhost:2551"

func equalID(id1 utility.ID, id2 utility.ID) bool {
	return bytes.Equal(id1[:], id2[:])
}

func testReceiver() {
	conn, err := net.ListenPacket("udp", myAddress)
	if err != nil {
		slog.Warn("Failed to create UDP listener", "err", err)
	}

	defer conn.Close()

	buf := make([]byte, 2048)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		slog.Warn("Failed to read data ", "err", err)
	}
	ch <- string(buf[:n])
}

func TestSendMessage(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp4", myAddress)
	if err != nil {
		t.Errorf(
			"Error during resolving UDP address: %v",
			err)
		return
	}
	s := "zupa ogórkowa"
	err = SendMessage(addr, []byte(s))
	if err != nil {
		t.Errorf(
			"Received error in SendMessage %s ",
			err)
	}

	m := <-ch

	if m != s {
		t.Errorf(
			"Received message is not equal sent message, expected %s but received: %s",
			s, m)
	} else {
		slog.Info("Received data successfully")
		return
	}
}

func TestSendHandshake(t *testing.T) {
	hello := encryption.TypeMessage([]byte{0x00})
	helloReply := encryption.TypeMessage([]byte{0x82})
	randomType := encryption.TypeMessage([]byte{69})
	emptyID := utility.ID{}

	addr, err := net.ResolveUDPAddr("udp4", myAddress)
	if err != nil {
		t.Errorf(
			"Error during resolving UDP address: %v",
			err)
		return
	}
	id1 := SendHandshake(hello, addr)
	id2 := SendHandshake(helloReply, addr)
	id3 := SendHandshake(randomType, addr)

	if bytes.Equal(id1[:], emptyID[:]) {
		t.Errorf(
			"Failed to send Handshake")
		return
	}

	if bytes.Equal(id2[:], emptyID[:]) {
		t.Errorf(
			"Failed to send ReplyHandshake")
		return
	}

	if !bytes.Equal(id3[:], emptyID[:]) {
		t.Errorf(
			"Inccorect provided MessageType")
		return
	}
}

/*
type MockServer struct{}

	func (m *MockServer) GetPeerKey(name string) (encryption.Key, error) {
		pubKey := encryption.GetMyPublicKey()
		derBytes, err := x509.MarshalPKIXPublicKey(&pubKey)
		if err != nil {
			return encryption.Key{}, err
		}
		return encryption.Key(derBytes), nil
	}

	func TestReceiveHanshake(t *testing.T) {
		addr, err := net.ResolveUDPAddr("udp4", myAddress)
		if err != nil {
			t.Errorf(
				"Error during resolving UDP address: %v",
				err)
			return
		}
		id := utility.GenerateID()
		hello := encryption.TypeMessage([]byte{0x00})
		message := encodeHandshake(hello, id)
		signature := encryption.GetSignature(message)
		data := append(message, signature...)

		server := srv_conn.NewServer()
		ReceiveHandshake(addr, data, server)

}
*/
func TestEncodeDecodeHandshake(t *testing.T) {
	id := utility.GenerateID()
	typeMessage := encryption.TypeMessage([]byte{0x00})

	mess := encodeHandshake(typeMessage, id)
	signature := encryption.GetSignature(mess)
	message := append(mess, signature...)
	data := append(message, signature...)

	decode := decodeHandshake(data)

	if !bytes.Equal(decode.extensions, getExtensions()) {
		t.Errorf(
			"Incorrect decode extensions, got %s, but expected %s", decode.extensions, getExtensions())
		return
	}

	if decode.name != USER_NAME {
		t.Errorf(
			"Incorrect decode name, got %s, but expected %s", decode.name, USER_NAME)
		return
	}

	if bytes.Equal(decode.signature[:], encryption.Signature{}) {
		t.Errorf(
			"Incorrect decode signature, got  empty Siganture")
		return
	}

	if !bytes.Equal(decode.ID[:], id[:]) {
		t.Errorf(
			"Incorrect decode id, got %s, but expected %s", decode.ID, id[:])
		return
	}

}

func TestEncodeError(t *testing.T) {
	errorName := "pozyczka"
	id := utility.GenerateID()
	typeMessage := encryption.TypeMessage([]byte{0x81})
	m := encodeError(id, errorName)
	length := m[5:7]
	err := m[7 : 7+utility.GetNumberFromBytes(length)]

	if utility.GetMessageType(m) != uint16(typeMessage[0]) {
		t.Errorf(
			"Incorrect MessageType, got %d, but expected %d", utility.GetMessageType(m), typeMessage[0])
		return
	}

	if !equalID(utility.GetMessageID(m), id) {
		t.Errorf(
			"Incorrect id, got %s, but expected %s", utility.GetMessageID(m), id[:])
		return
	}

	if string(err) != errorName {
		t.Errorf(
			"Incorrect error, got %s, but expected %s", string(err), errorName)
		return
	}
}

func TestMain(m *testing.M) {
	ch = make(chan string, 1)
	go testReceiver()
	time.Sleep(100 * time.Millisecond)
	e := m.Run()
	os.Exit(e)
}
