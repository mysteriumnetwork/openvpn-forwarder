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
	"flag"
	"io"
	"log"
	"net"
	"net/url"
	"strings"

	"github.com/inconshreveable/go-vhost"
	"github.com/mysteriumnetwork/openvpn-forwarder/api"
	"github.com/mysteriumnetwork/openvpn-forwarder/proxy"
	netproxy "golang.org/x/net/proxy"
)

var proxyAPIAddr = flag.String("proxy.api-bind", ":8000", "HTTP proxy API address")
var proxyHTTPAddr = flag.String("proxy.http-bind", ":8080", "HTTP proxy address for incoming connections")
var proxyHTTPSAddr = flag.String("proxy.https-bind", ":8443", "HTTPS proxy address for incoming connections")
var proxyUpstreamURL = flag.String(
	"proxy.upstream-url",
	"",
	`Upstream HTTPS proxy where to forward traffic (e.g. "http://superproxy.com:8080")`,
)

var stickyStoragePath = flag.String("stickiness-db-path", proxy.MemoryStorage, "Path to the database for stickiness mapping")

var filterHostnames = FlagArray(
	"filter.hostnames",
	`Explicitly forward just several hostnames (separated by comma - "ipinfo.io,ipify.org")`,
)
var filterZones = FlagArray(
	"filter.zones",
	`Explicitly forward just several DNS zones. A zone of "example.com" matches "example.com" and all of its subdomains. (separated by comma - "ipinfo.io,ipify.org")`,
)

type stickyMapper interface {
	Save(ip string, userID string)
	Hash(ip string) string
}

func main() {
	flag.Parse()

	dialerUpstreamURL, err := url.Parse(*proxyUpstreamURL)
	if err != nil || dialerUpstreamURL.Scheme != "http" {
		log.Fatalf("Invalid upstream URL: %s", *proxyUpstreamURL)
	}

	sm, err := proxy.NewStickyMapper(*stickyStoragePath)
	if err != nil {
		log.Fatalf("Failed to create sticky mapper, %v", err)
	}

	apiServer := api.NewServer(*proxyAPIAddr, sm)
	go apiServer.ListenAndServe()

	dialerUpstream := proxy.NewDialerHTTPConnect(proxy.DialerDirect, dialerUpstreamURL.Host)

	var dialer netproxy.Dialer
	if len(*filterHostnames) > 0 || len(*filterZones) > 0 {
		dialerPerHost := netproxy.NewPerHost(proxy.DialerDirect, dialerUpstream)
		for _, host := range *filterHostnames {
			log.Printf("Redirecting: %s -> %s", host, dialerUpstreamURL)
			dialerPerHost.AddHost(host)
		}
		for _, zone := range *filterZones {
			log.Printf("Redirecting: *.%s -> %s", zone, dialerUpstreamURL)
			dialerPerHost.AddZone(zone)
		}
		dialer = dialerPerHost
	} else {
		dialer = dialerUpstream
		log.Printf("Redirecting: * -> %s", dialerUpstreamURL)
	}

	proxyServer := proxy.NewServer(*proxyHTTPAddr, dialer, sm)
	log.Print("Serving HTTP proxy on ", *proxyHTTPAddr)
	go proxyServer.ListenAndServe()

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
		go serveTLS(c, dialer, sm)
	}
}

func serveTLS(c net.Conn, dialer netproxy.Dialer, sm stickyMapper) {
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
	conn, err := dialer.Dial("tcp", remoteHost)
	if err != nil {
		log.Printf("Error establishing connection to %s: %v", remoteHost, err)
		return
	}
	defer conn.Close()

	if proxyConnection, ok := conn.(*proxy.Connection); ok {
		clientHost, _, err := net.SplitHostPort(c.RemoteAddr().String())
		if err != nil {
			log.Printf("Failed to get host from address %s: %v", c.RemoteAddr(), err)
			return
		}
		if err := proxyConnection.ConnectTo(conn, remoteHost, sm.Hash(clientHost)); err != nil {
			log.Printf("Error establishing CONNECT tunnel to %s: %v", remoteHost, err)
			return
		}
	}

	go io.Copy(conn, tlsConn)
	io.Copy(tlsConn, conn)
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
