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
	"io"
	"log"
	"net"
	"net/http/httputil"
	"strings"

	"github.com/inconshreveable/go-vhost"
	"github.com/pkg/errors"
	"github.com/soheilhy/cmux"
	netproxy "golang.org/x/net/proxy"
)

type domainTracker interface {
	Inc(domain string)
}

type proxyServer struct {
	addr   string
	dialer netproxy.Dialer
	sm     *stickyMapper
	dt     domainTracker
}

// NewServer returns new instance of HTTP transparent proxy server
func NewServer(addr string, upstreamDialer netproxy.Dialer, mapper *stickyMapper, dt domainTracker) *proxyServer {
	return &proxyServer{
		addr:   addr,
		dialer: upstreamDialer,
		sm:     mapper,
		dt:     dt,
	}
}

func (s *proxyServer) ListenAndServe() {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		log.Fatalf("Error listening for https connections - %v", err)
	}

	m := cmux.New(ln)

	httpsL := m.Match(cmux.TLS())
	httpL := m.Match(cmux.HTTP1Fast())

	go s.handler(httpL, s.serveHTTP)
	go s.handler(httpsL, s.serveTLS)

	m.Serve()
}

func (s *proxyServer) handler(l net.Listener, f func(c net.Conn)) {
	for {
		c, err := l.Accept()
		if err != nil {
			log.Printf("Error accepting new connection - %v", err)
			continue
		}
		go f(c)
	}
}

func (s *proxyServer) serveHTTP(c net.Conn) {
	sc := httputil.NewServerConn(c, nil)
	req, err := sc.Read()
	if err != nil {
		log.Printf("Failed to read HTTP request: %v", err)
		return
	}

	remoteHost := net.JoinHostPort(req.Host, "80")
	conn, err := s.connectTo(c, remoteHost)
	if err != nil {
		log.Printf("Error establishing connection to %s: %v", remoteHost, err)
		return
	}
	defer conn.Close()

	if err := req.Write(conn); err != nil {
		log.Printf("Failed to forward HTTP request to %s: %v", remoteHost, err)
		return
	}

	go io.Copy(conn, c)
	io.Copy(c, conn)
}

func (s *proxyServer) serveTLS(c net.Conn) {
	tlsConn, err := vhost.TLS(c)
	if err != nil {
		log.Printf("Error accepting new connection - %v", err)
		return
	}
	defer tlsConn.Close()

	if tlsConn.Host() == "" {
		log.Printf("Cannot support non-SNI enabled TLS sessions")
		return
	}

	remoteHost := net.JoinHostPort(tlsConn.Host(), "443")
	conn, err := s.connectTo(c, remoteHost)
	if err != nil {
		log.Printf("Error establishing connection to %s: %v", remoteHost, err)
		return
	}
	defer conn.Close()

	go io.Copy(conn, tlsConn)
	io.Copy(tlsConn, conn)
}

func (s *proxyServer) connectTo(c net.Conn, remoteHost string) (net.Conn, error) {
	conn, err := s.dialer.Dial("tcp", remoteHost)
	if err != nil {
		return nil, errors.Wrap(err, "failed to establish connection")
	}

	domain := strings.Split(remoteHost, ":")
	s.dt.Inc(domain[0])

	if proxyConnection, ok := conn.(*Connection); ok {
		clientHost, _, err := net.SplitHostPort(c.RemoteAddr().String())
		if err != nil {
			return nil, errors.Wrap(err, "failed to get host from address")
		}
		if err := proxyConnection.ConnectTo(conn, remoteHost, s.sm.Hash(clientHost)); err != nil {
			return nil, errors.Wrap(err, "failed to establish CONNECT tunnel")
		}
	}

	return conn, nil
}
