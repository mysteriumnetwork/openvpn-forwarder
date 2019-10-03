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
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_dialerHTTPConnect_DialCreatesValidRequest(t *testing.T) {
	server := proxyServerStub{}
	server.run()
	defer server.stop()

	dialer := &dialerHTTPConnect{forwardDialer: DialerDirect, forwardAddress: ":6969"}
	conn, err := dialer.Dial("tcp", "domain.com:80")
	assert.NotNil(t, conn)
	assert.NoError(t, err)

	err = conn.(*Connection).ConnectTo(conn, "domain.com:80", "")
	assert.NoError(t, err)

	req := server.getLastRequest()
	assert.NoError(t, server.getLastError())
	assert.Equal(t, "HTTP/1.1", req.Proto)
	assert.Equal(t, "CONNECT", req.Method)
	assert.Equal(t, &url.URL{Host: "domain.com:80"}, req.URL)
	assert.Equal(t, "domain.com:80", req.Host)
	assert.Equal(t, "domain.com:80", req.RequestURI)
}

type proxyServerStub struct {
	listener net.Listener
	conn     net.Conn

	lastRequest *http.Request
	lastError   error
	mu          sync.Mutex
}

func (server *proxyServerStub) run() {
	l, err := net.Listen("tcp", ":6969")
	server.mu.Lock()
	server.listener, server.lastError = l, err
	server.mu.Unlock()
	if err != nil {
		return
	}

	go func() {
		c, err := server.listener.Accept()
		server.mu.Lock()
		server.conn, server.lastError = c, err
		server.mu.Unlock()
		if err != nil {
			return
		}

		r, err := http.ReadRequest(bufio.NewReader(server.conn))
		server.mu.Lock()
		server.lastRequest, server.lastError = r, err
		server.mu.Unlock()
		if err != nil {
			return
		}

		resp := http.Response{StatusCode: 200, Proto: "HTTP/1.0"}
		resp.Write(server.conn)
	}()
}

func (server *proxyServerStub) stop() {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.listener != nil {
		server.listener.Close()
	}
	if server.conn != nil {
		server.conn.Close()
	}
}

func (server *proxyServerStub) getLastError() error {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.lastError
}

func (server *proxyServerStub) getLastRequest() http.Request {
	server.mu.Lock()
	defer server.mu.Unlock()
	return *server.lastRequest
}
