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

	"net/http/httptest"

	"github.com/stretchr/testify/assert"
)

func Test_Server_ServeHTTP(t *testing.T) {
	t.Skip()

	upstreamServer := upstreamServerStub{}
	upstreamServer.run()
	defer upstreamServer.stop()

	upstreamDialer := NewDialerHTTPConnect(DialerDirect, "http://localhost:6969")

	req, _ := http.NewRequest("GET", "http://domain.com", nil)
	resp := httptest.NewRecorder()

	proxyServer := NewServer(upstreamDialer, func(_ string) string { return "" })
	proxyServer.ServeHTTP(resp, req)

	t.Log(resp.Code)
	t.Log(resp.Body.String())

	upstreamReq := upstreamServer.getLastRequest()
	assert.NoError(t, upstreamServer.getLastError())
	assert.Equal(t, "HTTP/1.1", upstreamReq.Proto)
	assert.Equal(t, "CONNECT", upstreamReq.Method)
	assert.Equal(t, &url.URL{Host: "domain.com:80"}, upstreamReq.URL)
	assert.Equal(t, "domain.com:80", upstreamReq.Host)
	assert.Equal(t, "domain.com:80", upstreamReq.RequestURI)
}

type upstreamServerStub struct {
	listener net.Listener
	conn     net.Conn

	lastRequest *http.Request
	lastError   error
	mu          sync.Mutex
}

func (server *upstreamServerStub) run() {
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

func (server *upstreamServerStub) stop() {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.listener != nil {
		server.listener.Close()
	}
	if server.conn != nil {
		server.conn.Close()
	}
}

func (server *upstreamServerStub) getLastError() error {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.lastError
}

func (server *upstreamServerStub) getLastRequest() http.Request {
	server.mu.Lock()
	defer server.mu.Unlock()
	return *server.lastRequest
}
