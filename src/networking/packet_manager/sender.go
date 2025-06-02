package packet_manager

import (
	"mimuw_zps/src/networking"
	"net"
)

// Worker handles send requests sent via requestChan and informs the waiter
// via waiterChan about potential retries needed in the future. When an error
// occurs during sending the message, no further retries will be performed and
// the request is deemed failed.
func Sender(conn net.PacketConn,
	requestChan <-chan networking.SendRequest,
	waiterChan chan<- networking.SendRequest) {
	for {
		request := <-requestChan
		_, err := conn.WriteTo(request.Message[:], request.Addr)
		if err != nil {
			request.CallbackChan <- networking.ReceivedMessageData{Err: err}
			continue
		}
		waiterChan <- request
	}
}
