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
	"fmt"
	"github.com/mysteriumnetwork/openvpn-forwarder/metrics"
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
var upstreamConfigs = FlagUpstreamConfig()
var proxyMapPort = FlagArray(
	"proxy.port-map",
	`Explicitly map source port to destination port (separated by comma - "8443:443,18443:8443")`,
)
var stickyStoragePath = flag.String("stickiness-db-path", proxy.MemoryStorage, "Path to the database for stickiness mapping")
var enableDomainTracer = flag.Bool("enable-domain-tracer", false, "Enable tracing domain names from requests")

type domainTracker interface {
	Inc(domain string)
	Dump() map[string]uint64
}

func main() {
	flag.Parse()
	setLoggerFormat(*logLevel)

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

	var dialer netproxy.Dialer
	for _, upstreamConfig := range upstreamConfigs.configs {
		var dialerDefault netproxy.Dialer = proxy.DialerDirect
		if dialer != nil {
			dialerDefault = dialer
		}
		dialerUpstream := proxy.NewDialerHTTPConnect(proxy.DialerDirect, upstreamConfig.url, upstreamConfig.user, upstreamConfig.password, upstreamConfig.country)

		if len(upstreamConfig.filterHostnames) > 0 || len(upstreamConfig.filterZones) > 0 {
			dialerUpstreamFiltered := netproxy.NewPerHost(dialerDefault, dialerUpstream)
			for _, host := range upstreamConfig.filterHostnames {
				log.Infof("Redirecting: %s -> %s", host, upstreamConfig.url)
				dialerUpstreamFiltered.AddHost(host)
			}
			for _, zone := range upstreamConfig.filterZones {
				log.Infof("Redirecting: *.%s -> %s", zone, upstreamConfig.url)
				dialerUpstreamFiltered.AddZone(zone)
			}
			dialer = dialerUpstreamFiltered
		} else {
			dialer = dialerUpstream
			log.Infof("Redirecting: * -> %s", upstreamConfig.url)
		}
		if len(upstreamConfig.excludeHostnames) > 0 || len(upstreamConfig.excludeZones) > 0 {
			dialerUpstreamExcluded := netproxy.NewPerHost(dialer, dialerDefault)
			for _, host := range upstreamConfig.excludeHostnames {
				log.Infof("Excluding: %s -> %s", host, upstreamConfig.url)
				dialerUpstreamExcluded.AddHost(host)
			}
			for _, zone := range upstreamConfig.excludeZones {
				log.Infof("Excluding: *.%s -> %s", zone, upstreamConfig.url)
				dialerUpstreamExcluded.AddZone(zone)
			}
			dialer = dialerUpstreamExcluded
		}
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
	metricService, err := metrics.NewMetricsService()
	if err != nil {
		_ = log.Criticalf("Failed to start metrics service: %s", err)
		os.Exit(1)
	}

	proxyServer := proxy.NewServer(allowedSubnets, allowedIPs, dialer, sm, domainTracer, portMap, metricService.ProxyHandlerMiddleware)
	proxyServer.AddListener(metricService)

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

type flagUpstreamConfig struct {
	url              *url.URL
	user             string
	password         string
	country          string
	filterHostnames  flagArray
	filterZones      flagArray
	excludeHostnames flagArray
	excludeZones     flagArray
}

// FlagUpstreamConfig defines list of configure upstream proxies.
func FlagUpstreamConfig() *flagUpstreamConfigs {
	fuc := &flagUpstreamConfigs{
		configs: []flagUpstreamConfig{
			{},
		},
		configCurrent: 0,
	}
	flag.Func(
		"proxy.upstream-url",
		`Upstream HTTPS proxy where to forward traffic (e.g. "http://superproxy.com:8080")`,
		fuc.parseUpstreamUrl,
	)
	flag.Func("proxy.user", "HTTPS proxy auth user", fuc.parseUpstreamUser)
	flag.Func("proxy.pass", "HTTP proxy auth password", fuc.parseUpstreamPass)
	flag.Func("proxy.country", "HTTP proxy country targeting", fuc.parseUpstreamCountry)
	flag.Func(
		"filter.hostnames",
		`Explicitly forward just several hostnames (separated by comma - "ipinfo.io,ipify.org")`,
		fuc.parseFilterHostnames,
	)
	flag.Func(
		"filter.zones",
		`Explicitly forward just several DNS zones. A zone of "example.com" matches "example.com" and all of its subdomains. (separated by comma - "ipinfo.io,ipify.org")`,
		fuc.parseFilterZones,
	)
	flag.Func(
		"exclude.hostnames",
		`Exclude from forwarding several hostnames (separated by comma - "ipinfo.io,ipify.org")`,
		fuc.parseExcludeHostnames,
	)
	flag.Func(
		"exclude.zones",
		`Exclude from forwarding several DNS zones. A zone of "example.com" matches "example.com" and all of its subdomains. (separated by comma - "ipinfo.io,ipify.org")`,
		fuc.parseExcludeZones,
	)

	return fuc
}

type flagUpstreamConfigs struct {
	configs       []flagUpstreamConfig
	configCurrent int
}

func (fuc *flagUpstreamConfigs) current() *flagUpstreamConfig {
	return &fuc.configs[fuc.configCurrent]
}

func (fuc *flagUpstreamConfigs) increment() {
	fuc.configs = append(fuc.configs, flagUpstreamConfig{})
	fuc.configCurrent++
}

func (fuc *flagUpstreamConfigs) parseUpstreamUrl(s string) error {
	upstreamUrl, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("invalid upstream URL: %s. %v", s, err)
	}

	if fuc.configs[fuc.configCurrent].url != nil {
		fuc.increment()
	}
	fuc.configs[fuc.configCurrent].url = upstreamUrl
	return nil
}

func (fuc *flagUpstreamConfigs) parseUpstreamUser(s string) error {
	fuc.configs[fuc.configCurrent].user = s
	return nil
}

func (fuc *flagUpstreamConfigs) parseUpstreamPass(s string) error {
	fuc.configs[fuc.configCurrent].password = s
	return nil
}

func (fuc *flagUpstreamConfigs) parseUpstreamCountry(s string) error {
	fuc.configs[fuc.configCurrent].country = s
	return nil
}

func (fuc *flagUpstreamConfigs) parseFilterHostnames(s string) error {
	return fuc.configs[fuc.configCurrent].filterHostnames.Set(s)
}

func (fuc *flagUpstreamConfigs) parseFilterZones(s string) error {
	return fuc.configs[fuc.configCurrent].filterZones.Set(s)
}

func (fuc *flagUpstreamConfigs) parseExcludeHostnames(s string) error {
	return fuc.configs[fuc.configCurrent].excludeHostnames.Set(s)
}

func (fuc *flagUpstreamConfigs) parseExcludeZones(s string) error {
	return fuc.configs[fuc.configCurrent].excludeZones.Set(s)
}
