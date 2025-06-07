package networking

import (
	"errors"
	"time"
)

type RetryPolicy interface {
	NextRetry() (time.Duration, error)
}

type RetryPolicyHandshake struct {
	retryCount int
	retryLimit int
}

func NewPolicyHandshake() *RetryPolicyHandshake {
	return &RetryPolicyHandshake{retryLimit: 3}
}

func NewRetryPolicyRequest() *RetryPolicyRequest {
	return &RetryPolicyRequest{retryCount: 2}
}

func (rp RetryPolicyHandshake) NextRetry() (time.Duration, error) {
	rp.retryCount++
	if rp.retryCount > rp.retryLimit {
		return time.Second, errors.New("no more retries")
	}
	return time.Second, nil
}

type RetryPolicyRequest struct {
	retryCount int
	retryLimit int
}

func (rp RetryPolicyRequest) NextRetry() (time.Duration, error) {
	rp.retryCount++
	if rp.retryCount > rp.retryLimit {
		return time.Second, errors.New("no more retries")
	}
	return time.Second, nil
}
