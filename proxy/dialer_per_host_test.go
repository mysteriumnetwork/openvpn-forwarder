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
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/proxy"
)

func Test_dialerPerHost_AddHost(t *testing.T) {
	dialViaDefault := errors.New("default")
	dialViaBypass := errors.New("bypass")

	dialer := proxy.NewPerHost(&dialerStub{dialViaDefault}, &dialerStub{dialViaBypass})
	dialer.AddHost("domain.com")

	_, err := dialer.Dial("tcp", "whatever.com:80")
	assert.Exactly(t, dialViaDefault, err)

	_, err = dialer.Dial("tcp", "domain.com:80")
	assert.Exactly(t, dialViaBypass, err)

	_, err = dialer.Dial("tcp", "sub.domain.com:80")
	assert.Exactly(t, dialViaDefault, err)
}

func Test_dialerPerHost_AddZone(t *testing.T) {
	dialViaDefault := errors.New("default")
	dialViaBypass := errors.New("bypass")

	dialer := proxy.NewPerHost(&dialerStub{dialViaDefault}, &dialerStub{dialViaBypass})
	dialer.AddZone("domain.com")

	_, err := dialer.Dial("tcp", "whatever.com:80")
	assert.Exactly(t, dialViaDefault, err)

	_, err = dialer.Dial("tcp", "domain.com:80")
	assert.Exactly(t, dialViaBypass, err)

	_, err = dialer.Dial("tcp", "sub.domain.com:80")
	assert.Exactly(t, dialViaBypass, err)
}

type dialerStub struct {
	mockError error
}

// Dial directly invokes net.Dial with the supplied parameters.
func (dialer *dialerStub) Dial(network, addr string) (net.Conn, error) {
	return nil, dialer.mockError
}
