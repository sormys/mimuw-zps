package packet_manager

import (
	"log/slog"
	"mimuw_zps/src/networking"
	"net"
)

// Worker handles send requests sent via requestChan and informs the waiter
// via waiterChan about potential retries needed in the future. When an error
// occurs during sending the message, no further retries will be performed and
// the request is deemed failed.
func SenderWorker(conn net.PacketConn,
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

func Sender(conn net.PacketConn,
	requestChan <-chan networking.SendRequest,
	waiterChan chan<- networking.SendRequest, workerCount uint32) {
	if workerCount < 1 {
		slog.Error("Invalid number of sender workers provided")
		return
	}
	workers := make([](chan networking.SendRequest), workerCount)
	for i := range workerCount {
		workerChan := make(chan networking.SendRequest, networking.WORKER_CHAN_BUF_SIZE)
		workers[i] = workerChan
		go SenderWorker(conn, workerChan, waiterChan)
	}

	lastId := 0
	for {
		request := <-requestChan
		lastId = (lastId + 1) % int(workerCount)
		workers[lastId] <- request
	}
}
