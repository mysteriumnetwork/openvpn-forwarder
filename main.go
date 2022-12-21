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
	"net"
	"net/url"
	"os"
	"strings"
	"sync"

	log "github.com/cihub/seelog"
	"github.com/mysteriumnetwork/openvpn-forwarder/api"
	"github.com/mysteriumnetwork/openvpn-forwarder/proxy"
	"github.com/pkg/errors"
	netproxy "golang.org/x/net/proxy"
)

var logLevel = flag.String("log.level", log.InfoStr, "Set the logging level (trace, debug, info, warn, error, critical)")
var proxyAddr = flag.String("proxy.bind", ":8443", "Proxy address for incoming connections")
var proxyAllow = FlagArray("proxy.allow", `Proxy allows connection from these addresses only (separated by comma - "10.13.0.1,10.13.0.0/16")`)
var proxyAPIAddr = flag.String("proxy.api-bind", ":8000", "HTTP proxy API address")
var proxyUpstreamURL = flag.String(
	"proxy.upstream-url",
	"",
	`Upstream HTTPS proxy where to forward traffic (e.g. "http://superproxy.com:8080")`,
)
var proxyUser = flag.String("proxy.user", "", "HTTP proxy auth user")
var proxyPass = flag.String("proxy.pass", "", "HTTP proxy auth password")
var proxyCountry = flag.String("proxy.country", "", "HTTP proxy country targeting")
var proxyMapPort = FlagArray(
	"proxy.port-map",
	`Explicitly map source port to destination port (separated by comma - "8443:443,18443:8443")`,
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
var excludeHostnames = FlagArray(
	"exclude.hostnames",
	`Exclude from forwarding several hostnames (separated by comma - "ipinfo.io,ipify.org")`,
)
var excludeZones = FlagArray(
	"exclude.zones",
	`Exclude from forwarding several DNS zones. A zone of "example.com" matches "example.com" and all of its subdomains. (separated by comma - "ipinfo.io,ipify.org")`,
)

var enableDomainTracer = flag.Bool("enable-domain-tracer", false, "Enable tracing domain names from requests")

type domainTracker interface {
	Inc(domain string)
	Dump() map[string]uint64
}

func main() {
	flag.Parse()
	setLoggerFormat(*logLevel)

	dialerUpstreamURL, err := url.Parse(*proxyUpstreamURL)
	if err != nil {
		_ = log.Criticalf("Invalid upstream URL: %s", *proxyUpstreamURL)
		os.Exit(1)
	}

	sm, err := proxy.NewStickyMapper(*stickyStoragePath)
	if err != nil {
		_ = log.Criticalf("Failed to create sticky mapper, %v", err)
		os.Exit(1)
	}

	var domainTracer domainTracker = proxy.NewNoopTracer()
	if *enableDomainTracer {
		domainTracer = proxy.NewDomainTracer()
	}

	apiServer := api.NewServer(*proxyAPIAddr, sm, domainTracer)
	go apiServer.ListenAndServe()

	dialerUpstream := proxy.NewDialerHTTPConnect(proxy.DialerDirect, dialerUpstreamURL, *proxyUser, *proxyPass, *proxyCountry)

	var dialer netproxy.Dialer
	if len(*filterHostnames) > 0 || len(*filterZones) > 0 {
		dialerUpstreamFiltered := netproxy.NewPerHost(proxy.DialerDirect, dialerUpstream)
		for _, host := range *filterHostnames {
			log.Infof("Redirecting: %s -> %s", host, dialerUpstreamURL)
			dialerUpstreamFiltered.AddHost(host)
		}
		for _, zone := range *filterZones {
			log.Infof("Redirecting: *.%s -> %s", zone, dialerUpstreamURL)
			dialerUpstreamFiltered.AddZone(zone)
		}
		dialer = dialerUpstreamFiltered
	} else {
		dialer = dialerUpstream
		log.Infof("Redirecting: * -> %s", dialerUpstreamURL)
	}
	if len(*excludeHostnames) > 0 || len(*excludeZones) > 0 {
		dialerUpstreamExcluded := netproxy.NewPerHost(dialer, proxy.DialerDirect)
		for _, host := range *excludeHostnames {
			log.Infof("Excluding: %s -> %s", host, dialerUpstreamURL)
			dialerUpstreamExcluded.AddHost(host)
		}
		for _, zone := range *excludeZones {
			log.Infof("Excluding: *.%s -> %s", zone, dialerUpstreamURL)
			dialerUpstreamExcluded.AddZone(zone)
		}
		dialer = dialerUpstreamExcluded
	}

	allowedSubnets, allowedIPs, err := parseAllowedAddresses(*proxyAllow)
	if err != nil {
		_ = log.Criticalf("Failed to parse allowed addresses: %v", err)
		os.Exit(1)
	}
	portMap, err := parsePortMap(*proxyMapPort, *proxyAddr)
	if err != nil {
		_ = log.Criticalf("Failed to parse port map: %v", err)
		os.Exit(1)
	}
	proxyServer := proxy.NewServer(allowedSubnets, allowedIPs, dialer, sm, domainTracer, portMap)

	var wg sync.WaitGroup
	for p := range portMap {
		wg.Add(1)
		go func(p string) {
			log.Infof("Serving HTTPS proxy on %s", p)
			if err := proxyServer.ListenAndServe(":" + p); err != nil {
				_ = log.Criticalf("Failed to listen http requests: %v", err)
				os.Exit(1)
			}
			wg.Done()
		}(p)
	}

	wg.Wait()
}

func setLoggerFormat(levelStr string) {
	level, _ := log.LogLevelFromString(levelStr)
	writer, _ := log.NewConsoleWriter()
	logger, _ := log.LoggerFromWriterWithMinLevelAndFormat(writer, level, "%Date %Time [%LEVEL] %Msg%n")
	log.ReplaceLogger(logger)
}

func parseAllowedAddresses(addresses flagArray) (subnets []*net.IPNet, ips []net.IP, _ error) {
	for _, address := range addresses {
		if _, subnet, err := net.ParseCIDR(address); err == nil {
			subnets = append(subnets, subnet)
			continue
		}
		if ip := net.ParseIP(address); ip != nil {
			ips = append(ips, ip)
			continue
		}
		return nil, nil, errors.Errorf("invalid subnet or IP: %s", address)
	}

	return subnets, ips, nil
}

func parsePortMap(ports flagArray, proxyAddr string) (map[string]string, error) {
	_, port, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse port")
	}

	portsMap := map[string]string{port: "443"}

	for _, p := range ports {
		portMap := strings.Split(p, ":")
		if len(portMap) != 2 {
			return nil, errors.Errorf("failed to parse port mapping: %s", p)
		}
		portsMap[portMap[0]] = portMap[1]
	}
	return portsMap, nil
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
