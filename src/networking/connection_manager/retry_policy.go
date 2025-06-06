package connection_manager

import "time"

type RetryPolicyHandshake struct {
	retryCount int
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
