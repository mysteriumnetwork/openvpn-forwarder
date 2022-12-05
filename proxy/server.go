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
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	log "github.com/cihub/seelog"
	"github.com/inconshreveable/go-vhost"
	"github.com/pkg/errors"
	"github.com/soheilhy/cmux"
	netproxy "golang.org/x/net/proxy"
)

type domainTracker interface {
	Inc(domain string)
}

type proxyServer struct {
	dialer   netproxy.Dialer
	sm       StickyMapper
	dt       domainTracker
	upstream *url.URL
	portMap  map[string]string
}

// StickyMapper represent connection stickiness storage.
type StickyMapper interface {
	Save(ip, userID string)
	Hash(ip string) (hash string)
}

// NewServer returns new instance of HTTP transparent proxy server
func NewServer(upstreamDialer netproxy.Dialer, upstreamHost *url.URL, mapper StickyMapper, dt domainTracker, portMap map[string]string) *proxyServer {
	return &proxyServer{
		dialer:   upstreamDialer,
		sm:       mapper,
		dt:       dt,
		upstream: upstreamHost,
		portMap:  portMap,
	}
}

func (s *proxyServer) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return errors.Wrap(err, "failed to listen http connections")
	}

	m := cmux.New(ln)

	httpsL := m.Match(cmux.TLS())
	httpL := m.Match(cmux.HTTP1Fast())

	go s.handler(httpL, s.serveHTTP)
	go s.handler(httpsL, s.serveTLS)

	return m.Serve()
}

func (s *proxyServer) handler(l net.Listener, f func(c *Context)) {
	for {
		conn, err := l.Accept()
		if err != nil {
			_ = log.Errorf("Error accepting new connection - %v", err)
			continue
		}

		go func() {
			f(&Context{conn: conn})
			conn.Close()
		}()
	}
}

func (s *proxyServer) serveHTTP(c *Context) {
	req, err := http.ReadRequest(bufio.NewReader(c.conn))
	if err != nil {
		_ = log.Errorf("Failed to read HTTP request: %v", err)
		return
	}

	c.destinationHost = req.Host
	c.destinationAddress = s.authorityAddr("http", c.destinationHost)
	s.accessLog("HTTP request", c)

	conn, err := s.connectTo(c.conn, c.destinationAddress)
	if err != nil {
		_ = log.Errorf("Error establishing connection to %s: %v", c.destinationAddress, err)
		return
	}
	defer conn.Close()

	if req.Method == http.MethodConnect {
		c.conn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	} else if err := req.Write(conn); err != nil {
		_ = log.Errorf("Failed to forward HTTP request to %s: %v", c.destinationAddress, err)
		return
	}

	go io.Copy(conn, c.conn)
	io.Copy(c.conn, conn)
}

func (s *proxyServer) authorityAddr(scheme, authority string) string {
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		port = "443"
		if scheme == "http" {
			port = "80"
		}
		host = authority
	}

	if p, ok := s.portMap[port]; ok {
		port = p
	}
	return net.JoinHostPort(host, port)
}

func (s *proxyServer) serveTLS(c *Context) {
	defer func() {
		// For some malformed TLS connection vhost.TLS could panic.
		// We don't care about a single failed request, service should keep working.
		if r := recover(); r != nil {
			_ = log.Error("Recovered panic in serveTLS", r)
		}
	}()

	tlsConn, err := vhost.TLS(c.conn)
	if err != nil {
		_ = log.Errorf("Error accepting new connection - %v", err)
		return
	}
	defer tlsConn.Close()

	if tlsConn.Host() == "" {
		_ = log.Error("Cannot support non-SNI enabled TLS sessions")
		return
	}

	_, port, err := net.SplitHostPort(tlsConn.LocalAddr().String())
	if err != nil {
		_ = log.Error("Cannot parse local address")
		return
	}

	c.destinationHost = tlsConn.Host() + ":" + port
	c.destinationAddress = s.authorityAddr("https", c.destinationHost)
	s.accessLog("HTTPS request", c)

	conn, err := s.connectTo(c.conn, c.destinationAddress)
	if err != nil {
		_ = log.Errorf("Error establishing connection to %s: %v", c.destinationAddress, err)
		return
	}
	defer conn.Close()

	go io.Copy(conn, tlsConn)
	io.Copy(tlsConn, conn)
}

func (s *proxyServer) connectTo(c net.Conn, remoteHost string) (conn io.ReadWriteCloser, err error) {
	conn, err = s.dialer.Dial("tcp", remoteHost)
	if err != nil {
		return nil, errors.Wrap(err, "failed to establish connection")
	}

	domain := strings.Split(remoteHost, ":")
	s.dt.Inc(domain[0])

	if proxyConnection, ok := conn.(*Connection); ok {
		if s.upstream.Scheme == "https" {
			tlsConn := tls.Client(conn.(net.Conn), &tls.Config{ServerName: s.upstream.Hostname()})
			if err := tlsConn.Handshake(); err != nil {
				return nil, errors.Wrap(err, "failed to perform TLS handshake")
			}
			conn = tlsConn
		}

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

func (s *proxyServer) accessLog(message string, c *Context) {
	log.Tracef(
		"%s [client_addr=%s, dest_addr=%s, destination_host=%s, destination_addr=%s]",
		message,
		c.conn.RemoteAddr().String(),
		c.conn.LocalAddr().String(),
		c.destinationHost,
		c.destinationAddress,
	)
}
