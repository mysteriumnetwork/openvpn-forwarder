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

package main

import (
	"bufio"
	"bytes"
	"flag"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/inconshreveable/go-vhost"
	"github.com/mysteriumnetwork/openvpn-forwarder/proxy"
	netproxy "golang.org/x/net/proxy"
)

var proxyHTTPAddr = flag.String("proxy.http-bind", ":8080", "HTTP proxy address for incoming connections")
var proxyHTTPSAddr = flag.String("proxy.https-bind", ":8443", "HTTPS proxy address for incoming connections")
var proxyUpstreamURL = flag.String(
	"proxy.upstream-url",
	"",
	`Upstream HTTPS proxy where to forward traffic (e.g. "http://superproxy.com:8080")`,
)

var filterHostnames = FlagArray(
	"filter.hostnames",
	`Explicitly forward just several hostnames (separated by comma - "ipinfo.io,ipify.org")`,
)
var filterZones = FlagArray(
	"filter.zones",
	`Explicitly forward just several DNS zones. A zone of "example.com" matches "example.com" and all of its subdomains. (separated by comma - "ipinfo.io,ipify.org",)`,
)

// DNS suffix that will use the bypass proxy. A zone of
// //
func main() {
	flag.Parse()

	dialerUpstreamURL, err := url.Parse(*proxyUpstreamURL)
	if err != nil || dialerUpstreamURL.Scheme != "http" {
		log.Fatalf("Invalid upstream URL: %s", *proxyUpstreamURL)
	}
	dialerUpstream := proxy.NewDialerHTTPConnect(proxy.DialerDirect, dialerUpstreamURL.Host)

	var dialer netproxy.Dialer = dialerUpstream
	if len(*filterHostnames) > 0 || len(*filterZones) > 0 {
		dialerPerHost := netproxy.NewPerHost(proxy.DialerDirect, dialerUpstream)
		for _, host := range *filterHostnames {
			dialerPerHost.AddHost(host)
		}
		for _, host := range *filterZones {
			dialerPerHost.AddZone(host)
		}
		dialer = dialerPerHost
	}

	proxyServer := proxy.NewServer(dialer)
	log.Print("Serving HTTP proxy on ", *proxyHTTPAddr)
	go http.ListenAndServe(*proxyHTTPAddr, proxyServer)

	log.Print("Serving HTTPS proxyServer on ", *proxyHTTPSAddr)
	ln, err := net.Listen("tcp", *proxyHTTPSAddr)
	if err != nil {
		log.Fatalf("Error listening for https connections - %v", err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting new connection - %v", err)
			continue
		}
		go func(c net.Conn) {
			tlsConn, err := vhost.TLS(c)
			if err != nil {
				log.Printf("Error accepting new connection - %v", err)
			}
			if tlsConn.Host() == "" {
				log.Printf("Cannot support non-SNI enabled clients")
				return
			}
			connectReq := &http.Request{
				Method: "CONNECT",
				URL: &url.URL{
					Opaque: tlsConn.Host(),
					Host:   net.JoinHostPort(tlsConn.Host(), "443"),
				},
				Host:   tlsConn.Host(),
				Header: make(http.Header),
			}
			resp := dumbResponseWriter{tlsConn}
			proxyServer.ServeHTTP(resp, connectReq)
		}(c)
	}
}

// FlagArray defines a string array flag
func FlagArray(name string, usage string) *flagArray {
	p := &flagArray{}
	flag.Var(p, name, usage)
	return p
}

type flagArray []string

func (flag *flagArray) String() string {
	return strings.Join(*flag, ",")
}

func (flag *flagArray) Set(s string) error {
	*flag = strings.FieldsFunc(s, func(c rune) bool {
		return c == ','
	})
	return nil
}

type dumbResponseWriter struct {
	net.Conn
}

func (dumb dumbResponseWriter) Header() http.Header {
	panic("Header() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		return len(buf), nil // throw away the HTTP OK response from the faux CONNECT request
	}
	return dumb.Conn.Write(buf)
}

func (dumb dumbResponseWriter) WriteHeader(code int) {
	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}
