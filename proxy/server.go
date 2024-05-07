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
	"io"
	"net"
	"net/http"
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

type HandlerMiddleware func(func(c *Context), string) func(*Context)

type Listener interface {
	OnProxyConnectionAccept()
}

type domainTracker interface {
	Inc(domain string)
}

type proxyServer struct {
	allowedSubnets    []*net.IPNet
	allowedIPs        []net.IP
	dialer            netproxy.Dialer
	sm                StickyMapper
	dt                domainTracker
	portMap           map[string]string
	handlerMiddleware HandlerMiddleware

	listeners []Listener
}

// StickyMapper represent connection stickiness storage.
type StickyMapper interface {
	Save(ip, userID string)
	Hash(ip string) (hash string)
}

// NewServer returns new instance of HTTP transparent proxy server
func NewServer(
	allowedSubnets []*net.IPNet,
	allowedIPs []net.IP,
	upstreamDialer netproxy.Dialer,
	mapper StickyMapper,
	dt domainTracker,
	portMap map[string]string,
	handlerMiddleware HandlerMiddleware,
) *proxyServer {
	return &proxyServer{
		allowedSubnets:    allowedSubnets,
		allowedIPs:        allowedIPs,
		dialer:            upstreamDialer,
		sm:                mapper,
		dt:                dt,
		portMap:           portMap,
		handlerMiddleware: handlerMiddleware,
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

	httpHandler := s.serveHTTP
	tlsHandler := s.serveTLS

	if s.handlerMiddleware != nil {
		httpHandler = s.handlerMiddleware(httpHandler, "HTTP")
		tlsHandler = s.handlerMiddleware(tlsHandler, "HTTPS")
	}

	go s.handler(httpL, httpHandler)
	go s.handler(httpsL, tlsHandler)

	return m.Serve()
}

func (s *proxyServer) AddListener(listener Listener) {
	s.listeners = append(s.listeners, listener)
}

func (s *proxyServer) handler(l net.Listener, f func(c *Context)) {
	for {
		var c Context
		var err error

		c.conn, err = l.Accept()
		s.sendOnProxyConnectionAccept()
		connMux, ok := c.conn.(*cmux.MuxConn)
		if !ok {
			err = fmt.Errorf("unsupported connection: %T", c.conn)
		}
		connTCP, ok := connMux.Conn.(*net.TCPConn)
		if !ok {
			err = fmt.Errorf("non-TCP connection: %T", connMux.Conn)
		}
		clientAddr, ok := connTCP.RemoteAddr().(*net.TCPAddr)
		if !ok {
			err = fmt.Errorf("non-TCP address: %T", connTCP.RemoteAddr())
			continue
		}
		if err != nil {
			s.logError(fmt.Sprintf("Error accepting new connection. %v", err), &c)
			continue
		}

		clientAddrAllowed := false
		for _, subnet := range s.allowedSubnets {
			if subnet.Contains(clientAddr.IP) {
				clientAddrAllowed = true
				break
			}
		}
		for _, ip := range s.allowedIPs {
			if ip.Equal(clientAddr.IP) {
				clientAddrAllowed = true
				break
			}
		}
		if !clientAddrAllowed {
			s.logWarn(fmt.Sprintf("Access restricted from address %s", clientAddr.IP.String()), &c)
			continue
		}

		c.connOriginalDst, err = getOriginalDst(connTCP)
		if c.connOriginalDst.String() == c.conn.LocalAddr().String() {
			c.connOriginalDst = nil
		}

		go func() {
			f(&c)
			c.conn.Close()

			if c.connOriginalDst == nil {
				s.logWarn("Failure recovering original destination address. Are you redirecting from same host network?", &c)
			}
		}()
	}
}

func (s *proxyServer) serveHTTP(c *Context) {
	req, err := http.ReadRequest(bufio.NewReader(c.conn))
	if err != nil {
		s.logAccess(fmt.Sprintf("Failed to accept new HTTP request: %v", err), c)
		return
	}

	c.destinationHost = req.Host
	c.destinationAddress = s.authorityAddr("http", c.destinationHost)
	s.logAccess("HTTP request", c)

	conn, err := s.connectTo(c, c.destinationAddress)
	if err != nil {
		s.logError(fmt.Sprintf("Failed to establishing connection. %v", err), c)
		return
	}
	defer conn.Close()

	if req.Method == http.MethodConnect {
		c.conn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	} else if err := req.Write(conn); err != nil {
		s.logError(fmt.Sprintf("Failed to forward HTTP request. %v", err), c)
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
			s.logError(fmt.Sprintf("Recovered panic in serveTLS. %v", r), c)
		}
	}()

	tlsConn, err := vhost.TLS(c.conn)
	if err != nil {
		s.logError(fmt.Sprintf("Failed to accept new TLS request. %v", err), c)
		return
	}
	defer tlsConn.Close()

	if tlsConn.Host() != "" {
		_, port, err := net.SplitHostPort(tlsConn.LocalAddr().String())
		if err != nil {
			s.logError("Cannot parse local address", c)
			return
		}

		c.destinationHost = tlsConn.Host() + ":" + port
		c.destinationAddress = s.authorityAddr("https", c.destinationHost)
	} else if c.connOriginalDst != nil {
		c.destinationHost = ""
		c.destinationAddress = c.connOriginalDst.String()
		s.logWarn("Cannon parse SNI in TLS request", c)
	} else {
		s.logError("Cannot support non-SNI enabled TLS sessions", c)
		return
	}
	s.logAccess("HTTPS request", c)

	conn, err := s.connectTo(c, c.destinationAddress)
	if err != nil {
		s.logError(fmt.Sprintf("Failed to establishing connection. %v", err), c)
		return
	}
	defer conn.Close()

	go io.Copy(conn, tlsConn)
	io.Copy(tlsConn, conn)
}

func (s *proxyServer) connectTo(c *Context, remoteHost string) (conn io.ReadWriteCloser, err error) {
	domain := strings.Split(remoteHost, ":")
	s.dt.Inc(domain[0])

	conn, err = s.dialer.Dial("tcp", remoteHost)
	if err != nil {
		return nil, errors.Wrap(err, "failed to establish connection")
	}

	if proxyConnection, ok := conn.(*Connection); ok {
		clientHost, _, err := net.SplitHostPort(c.conn.RemoteAddr().String())
		if err != nil {
			return nil, errors.Wrap(err, "failed to get host from address")
		}
		if err := proxyConnection.ConnectTo(conn, remoteHost, s.sm.Hash(clientHost)); err != nil {
			return nil, errors.Wrap(err, "failed to establish CONNECT tunnel")
		}
	}

	return conn, nil
}

func (s *proxyServer) sendOnProxyConnectionAccept() {
	for _, listener := range s.listeners {
		go listener.OnProxyConnectionAccept()
	}
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

func (s *proxyServer) logAccess(message string, c *Context) {
	log.Tracef(
		"%s [client_addr=%s, dest_addr=%s, original_dest_addr=%s destination_host=%s, destination_addr=%s]",
		message,
		c.conn.RemoteAddr().String(),
		c.conn.LocalAddr().String(),
		c.connOriginalDst.String(),
		c.destinationHost,
		c.destinationAddress,
	)
}

func (s *proxyServer) logError(message string, c *Context) {
	_ = log.Errorf(
		"%s [client_addr=%s, dest_addr=%s, original_dest_addr=%s destination_host=%s, destination_addr=%s]",
		message,
		c.conn.RemoteAddr().String(),
		c.conn.LocalAddr().String(),
		c.connOriginalDst.String(),
		c.destinationHost,
		c.destinationAddress,
	)
}

func (s *proxyServer) logWarn(message string, c *Context) {
	_ = log.Warnf(
		"%s [client_addr=%s, dest_addr=%s, original_dest_addr=%s destination_host=%s, destination_addr=%s]",
		message,
		c.conn.RemoteAddr().String(),
		c.conn.LocalAddr().String(),
		c.connOriginalDst.String(),
		c.destinationHost,
		c.destinationAddress,
	)
}
