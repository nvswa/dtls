// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/examples/util"
	"github.com/pion/dtls/v2/pkg/protocol"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
)

const (
	receiveMTU = 8192
	cidSize    = 8
)

func main() {
	var resumeFile = flag.String("file", "", "resume file")
	var secret = flag.String("secret", "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "shared secret")
	flag.Parse()

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
		ConnectionIDGenerator: dtls.RandomCIDGenerator(cidSize),
		KeyLogWriter:          log.Default().Writer(),
	}

	// Connect to a DTLS server
	listener, err := dtls.NewResumeListener("udp", addr, config)
	util.Check(err)
	defer func() {
		util.Check(listener.Close())
	}()

	state := &dtls.State{}

	if *resumeFile != "" {
		readData, err := os.ReadFile(*resumeFile)
		util.Check(err)

		err = state.UnmarshalBinary(readData)
		util.Check(err)
	} else {
		sharedSecret := []byte(*secret)
		state, err = util.DTLSServerState(sharedSecret)
		util.Check(err)
	}

	fmt.Println("Listening")

	// Simulate a chat session
	hub := util.NewHub()

	go func() {
		for {
			// Wait for a connection.
			pconn, addr, err := listener.Accept()
			util.Check(err)

			packet := make([]byte, receiveMTU)
			n, readAddr, err := pconn.ReadFrom(packet)
			util.Check(err)

			pkts, err := recordlayer.ContentAwareUnpackDatagram(packet[:n], cidSize)
			util.Check(err)

			h := &recordlayer.Header{
				ConnectionID: make([]byte, cidSize),
			}
			for i, pkt := range pkts {
				if err := h.Unmarshal(pkt); err != nil {
					continue
				}

				if h.ContentType != protocol.ContentTypeConnectionID {
					continue
				}

				start := recordlayer.FixedHeaderSize + cidSize
				appData := pkt[start:]
				fmt.Printf("%+v\n", h)

				newData, err := hex.DecodeString("0d52a86717999798f89aa0b28cf0b684f5aed6069bc76003e3d2ec2e3dbcaa093729d3db5b")
				util.Check(err)

				h.ContentLen = uint16(len(newData))

				newHeader, err := h.Marshal()
				util.Check(err)

				combined := make([]byte, 0, len(newHeader)+len(newData))
				combined = append(combined, newHeader...)
				combined = append(combined, newData...)

				pkts[i] = combined

				fmt.Printf("%v\n", hex.EncodeToString(appData))
			}

			var flatData []byte
			for _, d := range pkts {
				flatData = append(flatData, d...)
			}

			epconn := &edit1pconn{
				PacketConn: pconn,
				onceBytes:  flatData,
				remote:     readAddr,
			}

			conn, err := dtls.Resume(state, epconn, addr, config)
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
