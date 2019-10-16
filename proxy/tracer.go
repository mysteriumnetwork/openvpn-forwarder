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

import "sync"

type domainTracer struct {
	sync.Mutex
	domains map[string]uint64
}

// NewDomainTracer creates new domain tracer instace.
func NewDomainTracer() *domainTracer {
	return &domainTracer{
		domains: make(map[string]uint64),
	}
}

func (dt *domainTracer) Inc(domain string) {
	go func() {
		dt.Lock()
		defer dt.Unlock()

		dt.domains[domain]++
	}()
}

func (dt *domainTracer) Dump() (dump map[string]uint64) {
	dt.Lock()
	defer dt.Unlock()

	dump = make(map[string]uint64)
	for k, v := range dt.domains {
		dump[k] = v
	}

	return dump
}

type noopTracer struct{}

// NewNoopTracer creates new noop domain tracer instace.
func NewNoopTracer() *noopTracer { return &noopTracer{} }

func (nt *noopTracer) Inc(_ string)            {}
func (nt *noopTracer) Dump() map[string]uint64 { return nil }
