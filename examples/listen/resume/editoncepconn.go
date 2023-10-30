package main

import (
	"net"
	"sync"
)

type edit1pconn struct {
	net.PacketConn
	onceBytes []byte
	remote    net.Addr
	doOnce    sync.Once
}

func (c *edit1pconn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var copied int
	c.doOnce.Do(func() {
		copied = copy(p, c.onceBytes)
	})
	if copied > 0 {
		return copied, c.remote, nil
	}

	return c.PacketConn.ReadFrom(p)
}
