package packet_manager

import (
	"container/heap"
	"errors"
	"log/slog"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/utility"
	"time"
)

type worker struct {
	send chan<- networking.SendRequest
	recv chan<- networking.ReceivedMessageData
}

type messageStatus struct {
	sendRequest *networking.SendRequest
	reply       *networking.ReceivedMessageData
}

type retryTask struct {
	replyDeadline time.Time
	sendRequestId utility.ID
}

// ============================================================================
// TaskHeap implementation is basically a copy of IntHeap from documentation example:
// https://pkg.go.dev/container/heap
type TaskHeap []retryTask

func (h TaskHeap) Len() int { return len(h) }

// FIXME(sormys) check if order is correct
func (h TaskHeap) Less(i, j int) bool { return h[i].replyDeadline.After(h[j].replyDeadline) }
func (h TaskHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *TaskHeap) Push(x any) {
	*h = append(*h, x.(retryTask))
}

func (h *TaskHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

func (h TaskHeap) Top() any {
	return h[h.Len()-1]
}

// ============================================================================

func createRetryTask(request *networking.SendRequest, id utility.ID) (retryTask, error) {
	wait, err := request.MessRetryPolicy.NextRetry()
	deadline := time.Now().Add(wait)
	return retryTask{replyDeadline: deadline, sendRequestId: id}, err
}

func trySendCallback(callbackChan chan<- networking.ReceivedMessageData,
	data networking.ReceivedMessageData) {
	select {
	case callbackChan <- data:
	default:
		slog.Error("Failed to send data to callback")
	}
}

func calculateSleep(retryHeap *TaskHeap) time.Duration {
	// Long timeout when no messages should be retried
	timeout := time.Duration((2 * time.Minute).Nanoseconds())
	if retryHeap.Len() > 0 {
		minRetry := retryHeap.Top().(retryTask)
		now := time.Now()
		if now.After(minRetry.replyDeadline) {
			// Already past the deadline - send asap
			timeout = time.Nanosecond
		} else {
			timeout = time.Duration(minRetry.replyDeadline.Sub(now).Nanoseconds())
		}
	}
	return timeout
}

func handleRetryRequest(request networking.SendRequest, retryHeap *TaskHeap,
	messagesMap map[utility.ID]messageStatus) {
	if request.MessRetryPolicy == nil {
		// This message should not be retried
		return
	}

	slog.Debug("Received retry request", "addr", request.Addr, "mess id", utility.GetMessageID(request.Message))
	id := utility.GetMessageID(request.Message)
	task, err := createRetryTask(&request, id)
	if err != nil {
		slog.Debug("Retry canceled by retry policy", "request id", utility.GetMessageID(request.Message))
		// No more retries done, will only wait for potential reply
		request.MessRetryPolicy = nil
	}
	heap.Push(retryHeap, task)
	status, exists := messagesMap[id]
	if !exists {
		messagesMap[id] = messageStatus{sendRequest: &request}
		return
	}
	if status.reply != nil {
		// Already got reply for this task
		trySendCallback(request.CallbackChan, *status.reply)
		delete(messagesMap, id)
	} else if status.reply == nil {
		slog.Warn("Received duplicated task, replacing old task", "id", id)
		status.sendRequest = &request
	}
}

func handleReply(reply networking.ReceivedMessageData,
	messagesMap map[utility.ID]messageStatus) {

	// TODO(sormys) handle case where malicious peer tries to clog the system with replies
	slog.Debug("Recevied reply", "reply id", reply.ID)
	status, exists := messagesMap[reply.ID]
	if !exists {
		slog.Debug("Storing reply for later", "id", reply.ID)
		messagesMap[reply.ID] = messageStatus{reply: &reply}
		return
	}
	delete(messagesMap, reply.ID)
	if status.sendRequest != nil {
		trySendCallback((*status.sendRequest).CallbackChan, reply)
	}
}

func handleRetryDeadlinePassed(retryHeap *TaskHeap,
	messagesMap map[utility.ID]messageStatus,
	senderChan chan<- networking.SendRequest) {

	if retryHeap.Len() == 0 {
		return
	}
	minRetry := retryHeap.Top().(retryTask)
	if !time.Now().After(minRetry.replyDeadline) {
		return
	}
	minRetry = retryHeap.Pop().(retryTask)
	status, exists := messagesMap[minRetry.sendRequestId]
	if !exists {
		return
	}
	if status.sendRequest != nil && (*status.sendRequest).CallbackChan != nil {
		if (*status.sendRequest).MessRetryPolicy == nil {
			errData := networking.ReceivedMessageData{
				Err: errors.New("retried canceled by retry policy")}
			trySendCallback((*status.sendRequest).CallbackChan, errData)
		} else {
			select {
			case senderChan <- *status.sendRequest:
				slog.Debug("Retrying message", "message ID", utility.GetMessageID((*status.sendRequest).Message))
			default:
				// We assume that the system is clogged with messages, so we have to skip some of them
				errData := networking.ReceivedMessageData{
					Err: errors.New("could not send data to sender chan retry aborted")}
				trySendCallback((*status.sendRequest).CallbackChan, errData)
			}
		}
	}
	delete(messagesMap, minRetry.sendRequestId)

}

// Main brain of the packet manager.
// Until stopped:
//   - Receives schedule retry requests via retryReqChan
//   - Receives reply messages from receiver and sends the data to callback
//     channel provided in retry request - handling of the retry request ends here
//   - Sends send requests to sender via senderChan when retry deadline of
//     received retry request has passed without receiving a reply
//
// Important Note:
// WaiterWorker assumes senderChan and callbackChan in SendRequest can immediately
// receive data. If data cannot be send through a channel it will be skipped
// and forgotten.
func WaiterWorker(
	senderChan chan<- networking.SendRequest,
	retryReqChan <-chan networking.SendRequest,
	receiverChan <-chan networking.ReceivedMessageData) {

	messagesMap := map[utility.ID]messageStatus{}
	retryHeap := &TaskHeap{}
	heap.Init(retryHeap)
	for {
		timeout := calculateSleep(retryHeap)

		select {
		case request := <-retryReqChan:
			handleRetryRequest(request, retryHeap, messagesMap)
		case reply := <-receiverChan:
			handleReply(reply, messagesMap)
		case <-time.After(timeout):
			handleRetryDeadlinePassed(retryHeap, messagesMap, senderChan)
		}

	}
}

func Waiter(senderChan chan<- networking.SendRequest,
	retryReqChan <-chan networking.SendRequest,
	receiverChan <-chan networking.ReceivedMessageData, workerCount uint32) {
	if workerCount < 1 {
		slog.Error("Invalid number of sender workers provided")
		return
	}
	workers := make([]worker, workerCount)
	for i := range workerCount {
		workerSend := make(chan networking.SendRequest, networking.WORKER_CHAN_BUF_SIZE)
		workerRecv := make(chan networking.ReceivedMessageData, networking.WORKER_CHAN_BUF_SIZE)
		workers[i] = worker{send: workerSend, recv: workerRecv}
		go WaiterWorker(senderChan, workerSend, workerRecv)
	}

	bucketSize := utility.MAX_ID / uint32(workerCount)
	getWorker := func(id uint32) worker {
		// Make sure we will be in the array range
		messageId := min(id, utility.MAX_ID-1)
		return workers[messageId/uint32(bucketSize)]
	}
	for {
		select {
		case request := <-retryReqChan:
			messageId := utility.ConvertIDToUint(utility.GetMessageID(request.Message))
			getWorker(messageId).send <- request
		case data := <-receiverChan:
			messageId := utility.ConvertIDToUint(data.ID)
			getWorker(messageId).recv <- data
		}
	}
}
