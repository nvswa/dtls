// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements an example DTLS server which verifies client certificates.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/examples/util"
)

func main() {
	// Prepare the IP to connect to
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4444}

	// Create parent context to cleanup handshaking connections on exit.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ClientAuth:           dtls.RequireAndVerifyClientCert,
		// Create timeout context for accepted connection.
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(ctx, 30*time.Second)
		},
		ConnectionIDGenerator: dtls.RandomCIDGenerator(8),
		KeyLogWriter:          log.Default().Writer(),
	}

	// Connect to a DTLS server
	listener, err := dtls.NewResumeListener("udp", addr, config)
	util.Check(err)
	defer func() {
		util.Check(listener.Close())
	}()

	readData, err := os.ReadFile("resume_server.bin")
	util.Check(err)

	state := &dtls.State{}
	err = state.UnmarshalBinary(readData)
	util.Check(err)

	fmt.Println("Listening")

	// Simulate a chat session
	hub := util.NewHub()

	go func() {
		for {
			// Wait for a connection.
			pconn, addr, err := listener.Accept()
			util.Check(err)

			conn, err := dtls.ResumeWithContext(ctx, state, pconn, addr, config)
			util.Check(err)

			// `conn` is of type `net.Conn` but may be casted to `dtls.Conn`
			// using `dtlsConn := conn.(*dtls.Conn)` in order to to expose
			// functions like `ConnectionState` etc.

			// Register the connection with the chat hub
			hub.Register(conn)
		}
	}()

	// Start chatting
	hub.Chat()
}
