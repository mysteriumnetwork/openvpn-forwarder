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
)

// Context is the Proxy context, contains useful information about every request.
type Context struct {
	scheme          string
	conn            net.Conn
	connOriginalDst *net.TCPAddr

	destinationHost    string
	destinationAddress string
}

// RequestType HTTP or HTTPS
func (c Context) RequestType() string {
	return c.scheme
}
