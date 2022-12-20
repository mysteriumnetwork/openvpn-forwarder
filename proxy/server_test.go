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
	"time"

	log "github.com/cihub/seelog"
	"github.com/soheilhy/cmux"
	"github.com/stretchr/testify/assert"
)

func Test_Server_ServeHTTP(t *testing.T) {
	upstreamServer := upstreamServerStub{}
	upstreamAddr := upstreamServer.run()
	defer upstreamServer.stop()

	upstreamDialer := NewDialerHTTPConnect(DialerDirect, upstreamAddr, "", "", "")

	req, _ := http.NewRequest("GET", "http://domain.com", nil)

	proxyServer := NewServer(nil, []net.IP{net.ParseIP("::1")}, upstreamDialer, &url.URL{}, &stickyMapperStub{}, &noopTracer{}, nil)
	proxyAddr := listenAndServe(proxyServer)

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	client := &http.Client{Transport: transport}
	client.Do(req)

	upstreamReq := upstreamServer.getLastRequest()
	assert.NoError(t, upstreamServer.getLastError())
	assert.Equal(t, "HTTP/1.1", upstreamReq.Proto)
	assert.Equal(t, "CONNECT", upstreamReq.Method)
	assert.Equal(t, &url.URL{Host: "domain.com:80"}, upstreamReq.URL)
	assert.Equal(t, "domain.com:80", upstreamReq.Host)
	assert.Equal(t, "domain.com:80", upstreamReq.RequestURI)
	assert.Empty(t, upstreamReq.Header.Get("Proxy-Authorization"))
}

func Test_Server_AuthHeaderAdded(t *testing.T) {
	upstreamServer := upstreamServerStub{}
	upstreamAddr := upstreamServer.run()
	defer upstreamServer.stop()

	upstreamDialer := NewDialerHTTPConnect(DialerDirect, upstreamAddr, "uuuu", "1234", "")

	req, _ := http.NewRequest("GET", "http://domain.com", nil)

	proxyServer := NewServer(nil, []net.IP{net.ParseIP("::1")}, upstreamDialer, &url.URL{}, &stickyMapperStub{}, &noopTracer{}, nil)
	proxyAddr := listenAndServe(proxyServer)

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	client := &http.Client{Transport: transport}
	client.Do(req)

	upstreamReq := upstreamServer.getLastRequest()
	assert.Equal(t, upstreamReq.Header.Get("Proxy-Authorization"), "Basic dXV1dToxMjM0")
}

func listenAndServe(s *proxyServer) string {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Criticalf("Error listening for https connections - %v", err)
	}

	m := cmux.New(ln)

	httpsL := m.Match(cmux.TLS())
	httpL := m.Match(cmux.HTTP1Fast())

	go s.handler(httpL, s.serveHTTP)
	go s.handler(httpsL, s.serveTLS)

	go m.Serve()
	time.Sleep(100 * time.Millisecond) // waiting for server to start

	return ln.Addr().String()
}

type stickyMapperStub struct{}

func (sms *stickyMapperStub) Save(ip, userID string) {}
func (sms *stickyMapperStub) Hash(ip string) string {
	return "stubhash"
}

type upstreamServerStub struct {
	listener net.Listener
	conn     net.Conn

	lastRequest *http.Request
	lastError   error
	mu          sync.Mutex
}

func (server *upstreamServerStub) run() string {
	l, err := net.Listen("tcp", ":0")
	server.mu.Lock()
	server.listener, server.lastError = l, err
	server.mu.Unlock()
	if err != nil {
		return ""
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
		c.Close()
	}()
	return l.Addr().String()
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
