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
	"github.com/refraction-networking/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
)

const (
	receiveMTU      = 8192
	cidSize         = 8
	keySize         = 32
	station_privkey = "203963feed62ddda89b98857940f09866ae840f42e8c90160e411a0029b87e60"
)

func main() {
	var resumeFile = flag.String("file", "", "resume file")
	var secret = flag.String("secret", "", "shared secret")
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

			pkt := pkts[0]
			if err := h.Unmarshal(pkt); err != nil {
				continue
			}

			if h.ContentType != protocol.ContentTypeConnectionID {
				continue
			}

			start := recordlayer.FixedHeaderSize + cidSize
			representative := &[32]byte{}
			n = copy(representative[:], pkt[start:start+keySize])
			if n != len(representative) {
				panic("worng copy size")
			}

			representative[31] &= 0x3F

			pubkey := &[32]byte{}
			extra25519.RepresentativeToPublicKey(pubkey, representative)

			priv, err := hex.DecodeString(station_privkey)
			util.Check(err)

			newSharedSecret, err := curve25519.X25519(priv, pubkey[:])
			util.Check(err)

			fmt.Printf("representative: %v\n", hex.EncodeToString(representative[:]))
			fmt.Printf("shared secret : %v\n", hex.EncodeToString(newSharedSecret))

			newData := pkt[start+keySize:]

			h.ContentLen = uint16(len(newData))

			newHeader, err := h.Marshal()
			util.Check(err)

			combined := make([]byte, 0, len(newHeader)+len(newData))
			combined = append(combined, newHeader...)
			combined = append(combined, newData...)

			pkts[0] = combined

			var flatData []byte
			for _, d := range pkts {
				flatData = append(flatData, d...)
			}

			epconn := &edit1pconn{
				PacketConn: pconn,
				onceBytes:  flatData,
				remote:     readAddr,
			}

			state := &dtls.State{}

			if *resumeFile != "" {
				readData, err := os.ReadFile(*resumeFile)
				util.Check(err)

				err = state.UnmarshalBinary(readData)
				util.Check(err)
			} else if *secret != "" {
				sharedSecret := []byte(*secret)
				state, err = util.DTLSServerState(sharedSecret)
				util.Check(err)
			} else {
				state, err = util.DTLSServerState(newSharedSecret)
				util.Check(err)
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
