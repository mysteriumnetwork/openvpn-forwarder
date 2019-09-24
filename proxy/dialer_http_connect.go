/*
 * Copyright (C) 2019 The "MysteriumNetwork/openvpn-forwarder" Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"

	netproxy "golang.org/x/net/proxy"
)

// NewDialerHTTPConnect returns a new Dialer that dials through the provided
// proxy server's network and address.
func NewDialerHTTPConnect(forwardDialer netproxy.Dialer, forwardAddress string) *dialerHTTPConnect {
	return &dialerHTTPConnect{
		forwardDialer:  forwardDialer,
		forwardAddress: forwardAddress,
	}
}

type dialerHTTPConnect struct {
	forwardDialer  netproxy.Dialer
	forwardAddress string
}

type Connection struct {
	net.Conn
}

// Dial makes actual connection to specified address through intermediate HTTP proxy
func (dialer *dialerHTTPConnect) Dial(network, address string) (net.Conn, error) {
	conn, err := dialer.forwardDialer.Dial(network, dialer.forwardAddress)
	return &Connection{conn}, err
}

func (c *Connection) ConnectTo(conn net.Conn, address string, userID string) error {
	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Host: address},
		Host:   address,
	}
	if len(userID) > 0 {
		req.Header = make(http.Header)
		req.Header.Add("UserID", userID)
	}

	if err := req.Write(conn); err != nil {
		return fmt.Errorf("failed to write the HTTP request: %s", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return fmt.Errorf("failed to read the HTTP response: %s", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to do connect handshake, status code: %s", resp.Status)
	}

	return nil
}
