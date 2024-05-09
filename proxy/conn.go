/*
 * Copyright (C) 2024 The "MysteriumNetwork/openvpn-forwarder" Authors.
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
	"net"

	"github.com/prometheus/client_golang/prometheus"
)

var proxyRequestData = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "proxy_request_data",
	Help: "Proxy request data in bytes",
}, []string{"request_type", "direction"})

func init() {
	prometheus.MustRegister(proxyRequestData)
}

// NewConn returns net.Conn wrapped with metrics.
func NewConn(conn net.Conn, context *Context) *Conn {
	return &Conn{
		Conn:    conn,
		Context: context,
	}
}

// Conn wraps net.Conn with intercepts of read/write events.
type Conn struct {
	net.Conn

	Context *Context
}

// Read bytes from net.Conn and count read bytes
func (c Conn) Read(b []byte) (n int, err error) {
	count, err := c.Conn.Read(b)

	proxyRequestData.MustCurryWith(prometheus.Labels{
		"request_type": c.Context.RequestType(),
	}).WithLabelValues("received").Add(float64(count))

	return count, err
}

// Write bytes to net.Conn and counts written bytes
func (c Conn) Write(b []byte) (n int, err error) {
	count, err := c.Conn.Write(b)

	proxyRequestData.MustCurryWith(prometheus.Labels{
		"request_type": c.Context.RequestType(),
	}).WithLabelValues("sent").Add(float64(count))

	return count, err
}

var _ net.Conn = (*Conn)(nil)
