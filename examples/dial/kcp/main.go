// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements a DTLS client using a client certificate.
package main

import (
	"github.com/pion/dtls/v2/examples/util"
	"github.com/xtaci/kcp-go"
)

func main() {

	conn, err := kcp.Dial("127.0.0.1:4444")
	util.Check(err)

	util.Chat(conn)

}
