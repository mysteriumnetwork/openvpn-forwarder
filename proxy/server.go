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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"unsafe"

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
		var c Context
		var err error

		c.conn, err = l.Accept()
		connMux, ok := c.conn.(*cmux.MuxConn)
		if !ok {
			err = fmt.Errorf("unsupported connection: %T", c.conn)
		}
		connTCP, ok := connMux.Conn.(*net.TCPConn)
		if !ok {
			err = fmt.Errorf("non-TCP connection: %T", connMux.Conn)
		}
		if err != nil {
			_ = log.Errorf("Error accepting new connection. %v", err)
			continue
		}

		c.connOriginalDst, err = getOriginalDst(connTCP)
		if err != nil {
			_ = log.Errorf("Error recovering original destination address. %v", err)
		}

		go func() {
			f(&c)
			c.conn.Close()
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
		_ = log.Errorf("Error accepting new TLS connection - %v", err)
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

const SO_ORIGINAL_DST = 0x50

// getOriginalDst retrieves the original destination address from
// NATed connection.  Currently, only Linux iptables using DNAT/REDIRECT
// is supported.  For other operating systems, this will just return
// conn.LocalAddr().
//
// Note that this function only works when nf_conntrack_ipv4 and/or
// nf_conntrack_ipv6 is loaded in the kernel.
func getOriginalDst(conn *net.TCPConn) (*net.TCPAddr, error) {
	f, err := conn.File()
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fd := int(f.Fd())
	// revert to non-blocking mode.
	// see http://stackoverflow.com/a/28968431/1493661
	if err = syscall.SetNonblock(fd, true); err != nil {
		return nil, os.NewSyscallError("setnonblock", err)
	}

	// IPv4
	var addr syscall.RawSockaddrInet4
	var len uint32
	len = uint32(unsafe.Sizeof(addr))
	err = getSockOpt(fd, syscall.IPPROTO_IP, SO_ORIGINAL_DST, unsafe.Pointer(&addr), &len)
	if err != nil {
		return nil, os.NewSyscallError("getSockOpt", err)
	}

	ip := make([]byte, 4)
	for i, b := range addr.Addr {
		ip[i] = b
	}
	pb := *(*[2]byte)(unsafe.Pointer(&addr.Port))

	return &net.TCPAddr{
		IP:   ip,
		Port: int(pb[0])*256 + int(pb[1]),
	}, nil
}

func getSockOpt(s int, level int, optname int, optval unsafe.Pointer, optlen *uint32) (err error) {
	_, _, e := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(s),
		uintptr(level),
		uintptr(optname),
		uintptr(optval),
		uintptr(unsafe.Pointer(optlen)),
		0,
	)
	if e != 0 {
		return e
	}
	return
}

func (s *proxyServer) accessLog(message string, c *Context) {
	log.Tracef(
		"%s [client_addr=%s, dest_addr=%s, original_dest_addr=%s destination_host=%s, destination_addr=%s]",
		message,
		c.conn.RemoteAddr().String(),
		c.conn.LocalAddr().String(),
		c.connOriginalDst,
		c.destinationHost,
		c.destinationAddress,
	)
}
