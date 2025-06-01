package packet_manager

import (
	"net"
	"time"

	"github.com/stretchr/testify/mock"
)

type mockSendUDPConn struct {
	mock.Mock
}

func (m *mockSendUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) { return 0, nil }

func (m *mockSendUDPConn) ReadFrom(buf []byte) (int, net.Addr, error) { return 0, nil, nil }
func (m *mockSendUDPConn) Close() error                               { return nil }
func (m *mockSendUDPConn) LocalAddr() net.Addr                        { return &net.UDPAddr{} }
func (m *mockSendUDPConn) SetDeadline(t time.Time) error              { return nil }
func (m *mockSendUDPConn) SetReadDeadline(t time.Time) error          { return nil }
func (m *mockSendUDPConn) SetWriteDeadline(t time.Time) error         { return nil }
