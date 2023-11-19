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

	dialer := &net.Dialer{LocalAddr: &net.UDPAddr{IP: []byte{127, 0, 0, 1}, Port: 4443}}

	udpConn, err := dialer.Dial("udp4", "127.0.0.1:4444")
	util.Check(err)

	client, err := sctp.Client(sctp.Config{
		NetConn:       udpConn,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	util.Check(err)

	stream, err := client.OpenStream(0, sctp.PayloadTypeWebRTCString)
	util.Check(err)

	conn := util.NewSCTPConn(stream, udpConn)

	util.Chat(conn)

}
