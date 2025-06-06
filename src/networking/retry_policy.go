package networking

import "time"

type RetryPolicy interface {
	NextRetry() (time.Duration, error)
}

type RetryPolicyHandshake struct {
	retryCount int
}

func NewPolicyHandshake() *RetryPolicyHandshake {
	return &RetryPolicyHandshake{retryCount: 3}
}

func NewPolicyReply() *RetryPolicyReply {
	return &RetryPolicyReply{retryCount: 3}
}

func NewRetryPolicyRequest() *RetryPolicyRequest {
	return &RetryPolicyRequest{retryCount: 2}
}

func (rp RetryPolicyHandshake) NextRetry() (time.Duration, error) {
	rp.retryCount++
	if rp.retryCount > 1 {
		return time.Microsecond, nil
	}
	return time.Second, nil
}

type RetryPolicyReply struct {
	retryCount int
}

func (rp RetryPolicyReply) NextRetry() (time.Duration, error) {
	rp.retryCount++
	if rp.retryCount > 1 {
		return time.Microsecond, nil
	}
	return time.Second, nil
}

type RetryPolicyRequest struct {
	retryCount int
}

func (rp RetryPolicyRequest) NextRetry() (time.Duration, error) {
	rp.retryCount++
	if rp.retryCount > 1 {
		return time.Microsecond, nil
	}
	return time.Second, nil
}
