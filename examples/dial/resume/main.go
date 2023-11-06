// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/examples/util"
	pb "github.com/pion/dtls/v2/examples/util/proto"
	"github.com/pion/dtls/v2/pkg/protocol"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
	"github.com/refraction-networking/conjure/pkg/core"
	"google.golang.org/protobuf/proto"
)

const cidSize = 8

func main() {
	var remoteAddr = flag.String("raddr", "127.0.0.1:4444", "remote address")
	var resumeFile = flag.String("file", "", "resume file")
	var secret = flag.String("secret", "", "shared secret")
	var covert = flag.String("covert", "example.com:22", "covert addr")
	var pubkey = flag.String("pubkey", "0b63baad7f2f4bb5b547c53adc0fbb179852910607935e6f4b5639fd989b1156", "pubkey")
	flag.Parse()

	// Prepare the IP to connect to
	raddr, err := net.ResolveUDPAddr("udp", *remoteAddr)
	util.Check(err)

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		KeyLogWriter:         log.Default().Writer(),
	}

	var pConn net.PacketConn

	pConn, err = net.ListenUDP("udp", nil)
	util.Check(err)

	state := &dtls.State{}

	if *resumeFile != "" {
		readData, err := os.ReadFile(*resumeFile)
		util.Check(err)

		err = state.UnmarshalBinary(readData)
		util.Check(err)
	} else if *secret != "" {
		sharedSecret := []byte(*secret)
		state, err = util.DTLSClientState(sharedSecret)
		util.Check(err)
	} else {

		pubkeyBytes, err := hex.DecodeString(*pubkey)
		util.Check(err)
		if len(pubkeyBytes) != 32 {
			panic("pubkey incorrect lenth")
		}

		pubkey32Bytes := [32]byte{}
		copy(pubkey32Bytes[:], pubkeyBytes)

		keys, err := core.GenerateClientSharedKeys(pubkey32Bytes)
		util.Check(err)

		fmt.Printf("representative: %v\n", hex.EncodeToString(keys.Representative))
		fmt.Printf("shared secret : %v\n", hex.EncodeToString(keys.SharedSecret))

		pConn = &write1pconn{
			PacketConn: pConn,
			onceBytes:  keys.Representative,
		}

		state, err = util.DTLSClientState(keys.SharedSecret)
		util.Check(err)
	}

	dtlsConn, err := dtls.Resume(state, pConn, raddr, config)

	conn := &write1conn{
		Conn:   dtlsConn,
		covert: *covert,
	}

	util.Check(err)
	defer func() {
		util.Check(conn.Close())
	}()

	fmt.Println("Connected; type 'exit' to shutdown gracefully")

	util.Chat(conn)
}

type write1pconn struct {
	net.PacketConn
	onceBytes []byte
	doOnce    sync.Once
}

func (c *write1pconn) WriteTo(p []byte, addr net.Addr) (int, error) {
	var n int
	var err error
	c.doOnce.Do(func() {
		var new []byte
		new, err = c.editBuf(p)
		if err != nil {
			return
		}

		n, err = c.PacketConn.WriteTo(new, addr)
	})
	if err != nil {
		return 0, err
	}
	if n > 0 {
		return n, nil
	}

	return c.PacketConn.WriteTo(p, addr)
}

func (c *write1pconn) editBuf(p []byte) ([]byte, error) {
	pkts, err := recordlayer.ContentAwareUnpackDatagram(p, cidSize)
	if err != nil {
		return nil, err
	}

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

		h.ContentLen = uint16(len(c.onceBytes) + len(appData))

		newHeader, err := h.Marshal()
		if err != nil {
			return nil, err
		}

		combined := make([]byte, 0, len(newHeader)+len(c.onceBytes)+len(appData))
		combined = append(combined, newHeader...)
		combined = append(combined, c.onceBytes...)
		combined = append(combined, appData...)

		pkts[i] = combined
	}

	var flatData []byte
	for _, d := range pkts {
		flatData = append(flatData, d...)
	}

	return flatData, nil

}

type write1conn struct {
	net.Conn
	doOnce sync.Once
	covert string
}

func (c *write1conn) Write(p []byte) (int, error) {
	var n int
	var err error

	c.doOnce.Do(func() {
		id := make([]byte, 16)
		if _, err = rand.Read(id); err != nil {
			return
		}

		toSend := &pb.ConnInfo{
			Id:        id,
			EarlyData: p,
			Covert:    &c.covert,
		}

		var send []byte
		send, err = proto.Marshal(toSend)
		if err != nil {
			return
		}

		n, err = c.Conn.Write(send)
	})
	if err != nil {
		return 0, err
	}
	if n > 0 {
		return len(p), nil
	}

	return c.Conn.Write(p)
}
