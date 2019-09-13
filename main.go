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
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"

	"flag"

	"strings"

	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
)

var proxyHTTPAddr = flag.String("proxy.http-bind", ":8080", "HTTP proxy address for incoming connections")
var proxyHTTPSAddr = flag.String("proxy.https-bind", ":8081", "HTTPS proxy address for incoming connections")
var proxyUpstreamURL = flag.String("proxy.upstream-url", "http://superproxy.com:8080", "Upstream HTTPS proxy where to forward traffic")
var filterDomains = flag.String("filter.domains", "", `Filter which domains to forward (separated by comma - "ipinfo.io,ipify.org")`)

func main() {
	flag.Parse()

	var forwardConditions []goproxy.ReqCondition
	if *filterDomains != "" {
		proxyFilterDomainsArr := strings.Split(*filterDomains, ",")
		if len(proxyFilterDomainsArr) > 0 {
			forwardConditions = append(forwardConditions, goproxy.ReqHostIs(proxyFilterDomainsArr...))
		}
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	proxy.Tr.Proxy = func(req *http.Request) (*url.URL, error) {
		return url.Parse(*proxyUpstreamURL)
	}
	proxy.ConnectDial = proxy.NewConnectDialToProxy(*proxyUpstreamURL)
	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host == "" {
			fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
		proxy.ServeHTTP(w, req)
	})

	proxy.OnRequest(forwardConditions...).DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		conn, err := net.Dial("tcp", *proxyUpstreamURL)
		if err != nil {
			return req, nil
		}

		connectReq, err := http.NewRequest(http.MethodConnect, "", nil)
		connectReq.URL.Opaque = req.Host + ":80"
		if err != nil {
			return req, nil
		}

		connectReq.Write(conn)
		bufio.NewReader(conn).ReadLine()
		req.Write(conn)

		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			return req, nil
		}

		return req, resp
	})
	log.Print("Serving HTTP proxy on ", *proxyHTTPAddr)
	go http.ListenAndServe(*proxyHTTPAddr, proxy)

	log.Print("Serving HTTPS proxy on ", *proxyHTTPSAddr)
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
			proxy.ServeHTTP(resp, connectReq)
		}(c)
	}
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
