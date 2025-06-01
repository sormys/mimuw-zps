package packet_manager

import (
	"mimuw_zps/src/networking"
	"net"
)

// Worker handles send requests sent via requestChan and informs the writer
// via writerChan about potential retries needed in the future. When an error
// occurs during sending the message, no further retries will be performed and
// the request is deemed failed.
func Sender(conn net.PacketConn,
	requestChan <-chan networking.SendRequest,
	writerChan chan<- networking.SendRequest) {
	for {
		request := <-requestChan
		_, err := conn.WriteTo(request.Message[:], request.Addr)
		if err != nil {
			request.CallbackChan <- networking.ReceivedMessageData{Err: err}
			continue
		}
		writerChan <- request
	}
}
