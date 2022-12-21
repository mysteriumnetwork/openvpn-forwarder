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
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
	netproxy "golang.org/x/net/proxy"
)

// NewDialerHTTPConnect returns a new Dialer that dials through the provided
// proxy server's network and address.
func NewDialerHTTPConnect(forwardDialer netproxy.Dialer, forwardUrl *url.URL, user, pass, country string) *dialerHTTPConnect {
	return &dialerHTTPConnect{
		forwardDialer: forwardDialer,
		forwardURL:    forwardUrl,
		user:          user,
		pass:          pass,
		country:       country,
	}
}

type dialerHTTPConnect struct {
	forwardDialer       netproxy.Dialer
	forwardURL          *url.URL
	user, pass, country string
}

// Connection wraps net.Conn to provide extra method for establishing CONNECT session.
type Connection struct {
	net.Conn
	user, pass, country string
}

// Dial makes actual connection to specified address through intermediate HTTP proxy
func (dialer *dialerHTTPConnect) Dial(network, address string) (net.Conn, error) {
	conn, err := dialer.forwardDialer.Dial(network, dialer.forwardURL.Host)

	if dialer.forwardURL.Scheme == "https" {
		tlsConn := tls.Client(conn.(net.Conn), &tls.Config{ServerName: dialer.forwardURL.Hostname()})
		if err := tlsConn.Handshake(); err != nil {
			return nil, errors.Wrap(err, "failed to perform TLS handshake")
		}
		conn = tlsConn
	}

	return &Connection{
		Conn:    conn,
		user:    dialer.user,
		pass:    dialer.pass,
		country: dialer.country,
	}, err
}

// ConnectTo establishes new CONNECT session within existing connection.
// It allows to pass UserID to enable sticky sessions.
func (c *Connection) ConnectTo(conn io.ReadWriter, address string, userID string) error {
	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Host: address},
		Host:   address,
		Header: make(http.Header),
	}

	if userID != "" {
		req.Header.Add("User-Id", userID)
	}

	if c.country != "" {
		req.Header.Add("Country", c.country)
	}

	if len(c.user) > 0 && len(c.pass) > 0 {
		req.Header.Add("Proxy-Authorization", basicAuth(c.user, c.pass))
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

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}
