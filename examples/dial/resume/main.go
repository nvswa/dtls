// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements a DTLS client using a client certificate.
package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/examples/util"
)

func main() {
	// Prepare the IP to connect to
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4444}

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		KeyLogWriter:         log.Default().Writer(),
	}

	// Connect to a DTLS server
	readData, err := os.ReadFile("resume.bin")
	util.Check(err)

	state := &dtls.State{}
	err = state.UnmarshalBinary(readData)
	util.Check(err)

	pConn, err := net.ListenUDP("udp", nil)
	util.Check(err)

	dtlsConn, err := dtls.Resume(state, pConn, addr, config)

	util.Check(err)
	defer func() {
		util.Check(dtlsConn.Close())
	}()

	fmt.Println("Connected; type 'exit' to shutdown gracefully")

	util.Chat(dtlsConn)
}
