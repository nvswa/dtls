package util

import (
	"net"
	"time"

	"github.com/pion/sctp"
)

// SCTPConn implements the net.Conn interface using sctp stream and DTLS conn
type SCTPConn struct {
	stream *sctp.Stream
	conn   net.Conn
}

func NewSCTPConn(stream *sctp.Stream, conn net.Conn) *SCTPConn {
	return &SCTPConn{stream: stream, conn: conn}
}

func (s *SCTPConn) Close() error {
	err := s.stream.Close()
	if err != nil {
		return err
	}
	return s.conn.Close()
}

func (s *SCTPConn) Write(b []byte) (int, error) {
	return s.stream.Write(b)
}

func (s *SCTPConn) Read(b []byte) (int, error) {
	return s.stream.Read(b)
}

func (s *SCTPConn) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *SCTPConn) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

func (s *SCTPConn) SetDeadline(t time.Time) error {
	return s.conn.SetDeadline(t)
}

func (s *SCTPConn) SetWriteDeadline(t time.Time) error {
	return s.conn.SetWriteDeadline(t)
}

func (s *SCTPConn) SetReadDeadline(t time.Time) error {
	return s.stream.SetReadDeadline(t)
}
