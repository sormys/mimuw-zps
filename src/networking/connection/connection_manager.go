package connection_manager

import (
	"mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking"
	"mimuw_zps/src/networking/packet_manager"
	"time"
)

type RetryPolicyMock struct {
	retryCount int
}

func (rp RetryPolicyMock) NextRetry() (time.Duration, error) {
	rp.retryCount++
	if rp.retryCount > 1 {
		return time.Microsecond, nil
	}
	return time.Second, nil
}

func StartConnection(conn packet_manager.PacketConn, addresses []string) networking.ReceivedMessageData
func ReloadContent(conn packet_manager.PacketConn, message message_manager.TuiMessage) networking.ReceivedMessageData
func SendMessage(conn packet_manager.PacketConn, message message_manager.TuiMessage) networking.ReceivedMessageData
func SendData(conn packet_manager.PacketConn, data networking.ReceivedMessageData) error
func SendRoot(conn packet_manager.PacketConn, data networking.ReceivedMessageData) error
func SendHello(conn packet_manager.PacketConn, data networking.ReceivedMessageData) error
