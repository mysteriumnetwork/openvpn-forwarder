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
	"net"
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"
	netproxy "golang.org/x/net/proxy"
)

type stickyHasher interface {
	Hash(ip string) string
}

type domainTracker interface {
	Inc(domain string)
}

// NewServer returns new instance of HTTP transparent proxy server
func NewServer(addr string, upstreamDialer netproxy.Dialer, mapper stickyHasher, dt domainTracker) *http.Server {
	server := goproxy.NewProxyHttpServer()
	server.Verbose = true
	server.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host == "" {
			fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
		server.ServeHTTP(w, req)
	})

	server.ConnectDial = upstreamDialer.Dial
	server.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return goproxy.OkConnect, host
	})

	server.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		conn, err := upstreamDialer.Dial("tcp", req.Host+":80")
		if err != nil {
			return req, nil
		}

		domain := strings.Split(req.Host, ":")
		dt.Inc(domain[0])

		if proxyConnection, ok := conn.(*Connection); ok {
			clientHost, _, _ := net.SplitHostPort(req.RemoteAddr)
			if err := proxyConnection.ConnectTo(conn, req.Host+":80", mapper.Hash(clientHost)); err != nil {
				return req, nil
			}
		}

		err = req.Write(conn)
		if err != nil {
			return req, nil
		}

		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			return req, nil
		}

		return req, resp
	})

	return &http.Server{
		Addr:    addr,
		Handler: server,
	}
}
