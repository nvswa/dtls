// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements a DTLS client using a client certificate.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/examples/util"
)

func main() {
	var remoteAddr = flag.String("raddr", "127.0.0.1:4444", "remote address")
	var resumeFile = flag.String("file", "", "resume file")
	var secret = flag.String("secret", "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "shared secret")

	// Prepare the IP to connect to
	raddr, err := net.ResolveUDPAddr("udp", *remoteAddr)
	util.Check(err)

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		KeyLogWriter:         log.Default().Writer(),
	}

	state := &dtls.State{}

	if *resumeFile != "" {
		fmt.Println("from file")
		readData, err := os.ReadFile(*resumeFile)
		util.Check(err)

		err = state.UnmarshalBinary(readData)
		util.Check(err)
	} else {
		sharedSecret := []byte(*secret)
		state, err = util.DTLSClientState(sharedSecret)
		util.Check(err)
	}

	pConn, err := net.ListenUDP("udp", nil)
	util.Check(err)

	dtlsConn, err := dtls.Resume(state, pConn, raddr, config)

	util.Check(err)
	defer func() {
		util.Check(dtlsConn.Close())
	}()

	fmt.Println("Connected; type 'exit' to shutdown gracefully")

	util.Chat(dtlsConn)
}
