// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"net"
)

// Resume imports an already established dtls connection using a specific dtls state.
// If you want to specify the timeout duration, use ResumeWithContext() instead.
func Resume(state *State, conn net.PacketConn, rAddr net.Addr, config *Config) (*Conn, error) {
	return ResumeWithContext(context.Background(), state, conn, rAddr, config)
}

// ResumeWithContext imports an already established dtls connection using a specific dtls state.
func ResumeWithContext(ctx context.Context, state *State, conn net.PacketConn, rAddr net.Addr, config *Config) (*Conn, error) {
	if err := state.initCipherSuite(); err != nil {
		return nil, err
	}
	c, err := createConn(ctx, conn, rAddr, config, state.isClient, state)
	if err != nil {
		return nil, err
	}

	return c, nil
}
