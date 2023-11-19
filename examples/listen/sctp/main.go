// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements a DTLS client using a client certificate.
package main

import (
	"net"

	"github.com/pion/dtls/v2/examples/util"
	"github.com/pion/logging"
	"github.com/pion/sctp"
)

func main() {

	dialer := &net.Dialer{LocalAddr: &net.UDPAddr{IP: []byte{127, 0, 0, 1}, Port: 4444}}

	hub := util.NewHub()
	go func() {
		for {

			udpConn, err := dialer.Dial("udp4", "127.0.0.1:4443")
			util.Check(err)

			client, err := sctp.Server(sctp.Config{
				NetConn:       udpConn,
				LoggerFactory: logging.NewDefaultLoggerFactory(),
			})
			util.Check(err)

			stream, err := client.AcceptStream()
			util.Check(err)

			conn := util.NewSCTPConn(stream, udpConn)
			hub.Register(conn)
		}
	}()

	hub.Chat()

}
