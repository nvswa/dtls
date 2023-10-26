// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"net"

	"github.com/pion/dtls/v2/internal/net/udp"
	dtlsnet "github.com/pion/dtls/v2/pkg/net"
)

// Listen creates a DTLS listener
func NewResumeListener(network string, laddr *net.UDPAddr, config *Config) (dtlsnet.PacketListener, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	lc := udp.ListenConfig{}
	// If connection ID support is enabled, then they must be supported in
	// routing.
	if config.ConnectionIDGenerator != nil {
		lc.DatagramRouter = cidDatagramRouter(len(config.ConnectionIDGenerator()))
		lc.ConnectionIdentifier = cidConnIdentifier()
	}
	return lc.Listen(network, laddr)
}
