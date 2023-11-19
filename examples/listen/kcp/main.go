// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements a DTLS client using a client certificate.
package main

import (
	"github.com/pion/dtls/v2/examples/util"
	"github.com/xtaci/kcp-go"
)

func main() {

	ls, err := kcp.Listen("127.0.0.1:4444")
	util.Check(err)

	hub := util.NewHub()
	go func() {
		for {

			conn, err := ls.Accept()
			util.Check(err)

			hub.Register(conn)
		}
	}()

	hub.Chat()

}
