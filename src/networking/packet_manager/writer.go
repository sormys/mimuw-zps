package packet_manager

import (
	"container/heap"
	"log/slog"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/utility"
	"time"
)

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
	if err != nil {
		return retryTask{}, err
	}
	deadline := time.Now().Add(wait)
	return retryTask{replyDeadline: deadline, sendRequestId: id}, nil
}

// Main brain of the packet manager.
// Until stopped:
//   - Receives retry requests via retryReqChan
//   - Receives reply messages from receiver and sends the data to callback
//     channel provided in retry request - handling of the retry request ends here
//   - Sends send requests to sender via senderChan when retry deadline of
//     received retry request has passed without receving a reply
func Writer(
	senderChan chan<- networking.SendRequest,
	retryReqChan <-chan networking.SendRequest,
	receiverChan chan networking.ReceivedMessageData) {
	messagesMap := map[utility.ID]messageStatus{}
	retryHeap := &TaskHeap{}
	heap.Init(retryHeap)
	longTimeout := time.Duration((2 * time.Minute).Nanoseconds())
	for {
		// Long timeout when no messages should be retried
		timeout := longTimeout
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

		select {
		case request := <-retryReqChan:
			// TODO(sormys) handle case where reply is received before the retry request
			id := utility.GetMessageID(request.Message)
			task, err := createRetryTask(&request, id)
			if err != nil {
				// No more retries allowed by retry policy
				request.CallbackChan <- networking.ReceivedMessageData{ID: id, Err: err}
				break
			}
			heap.Push(retryHeap, task)
			status := messageStatus{sendRequest: new(networking.SendRequest)}
			*status.sendRequest = request
			messagesMap[id] = status
		case reply := <-receiverChan:
			status, exists := messagesMap[reply.ID]
			if !exists {
				messagesMap[reply.ID] = messageStatus{reply: &reply}
				break
			}
			request := status.sendRequest
			request.CallbackChan <- reply
			delete(messagesMap, reply.ID)
		case <-time.After(timeout):
			minRetry := retryHeap.Top().(retryTask)
			if !time.Now().After(minRetry.replyDeadline) {
				break
			}
			minRetry = retryHeap.Pop().(retryTask)
			status, exists := messagesMap[minRetry.sendRequestId]
			if !exists {
				slog.Warn("Deadline passed for request but no request was found in the retry map")
				break
			}
			senderChan <- *status.sendRequest
			delete(messagesMap, minRetry.sendRequestId)
		}

	}
}
