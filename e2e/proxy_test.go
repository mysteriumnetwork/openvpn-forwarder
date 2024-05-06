//go:build e2e
// +build e2e

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

package e2e

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/magefile/mage/sh"
)

// TestHTTPS runs end-to-end test for HTTPS traffic forwarding
func TestHTTPS(t *testing.T) {
	// given
	originalIP, err := checkIP("https://api.ipify.org/?format=text")
	t.Log("Original IP:", originalIP)
	assert.NoError(t, err)

	forwarderIP, err := getForwarderIP()
	assert.NoError(t, err)

	// when
	redirectRule := []string{"OUTPUT", "-p", "tcp", "-m", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", forwarderIP + ":8443"}
	err = ipTablesAppend(redirectRule)
	defer ipTablesDelete(redirectRule)
	assert.NoError(t, err)

	// then
	currentIP, err := checkIP("https://api.ipify.org/?format=text")
	t.Log("Current IP:", currentIP)
	assert.NoError(t, err)

	assert.NotEqualf(t, originalIP, currentIP, "Request proxying failed: %s -> %s", originalIP, currentIP)
}

// TestHTTP runs end-to-end test for HTTP traffic forwarding
func TestHTTP(t *testing.T) {
	// given
	originalIP, err := checkIP("http://api.ipify.org/?format=text")
	t.Log("Original IP:", originalIP)
	assert.NoError(t, err)

	forwarderIP, err := getForwarderIP()
	assert.NoError(t, err)

	// when
	redirectRule := []string{"OUTPUT", "-p", "tcp", "-m", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", forwarderIP + ":8443"}
	err = ipTablesAppend(redirectRule)
	defer ipTablesDelete(redirectRule)
	assert.NoError(t, err)

	currentIP, err := checkIP("http://api.ipify.org/?format=text")
	t.Log("Current IP:", currentIP)
	assert.NoError(t, err)

	assert.NotEqualf(t, originalIP, currentIP, "Request proxying failed: %s -> %s", originalIP, currentIP)
}

func TestHTTPWithCloseHeader(t *testing.T) {
	// given
	originalIP, err := checkIP("http://api.ipify.org/?format=text")
	t.Log("Original IP:", originalIP)
	assert.NoError(t, err)

	forwarderIP, err := getForwarderIP()
	assert.NoError(t, err)

	// when
	redirectRule := []string{"OUTPUT", "-p", "tcp", "-m", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", forwarderIP + ":8443"}
	err = ipTablesAppend(redirectRule)
	defer ipTablesDelete(redirectRule)
	assert.NoError(t, err)

	cmd, args := execInTestMachineCmd(
		"curl", "-s",
		"--http1.1",
		"-H", "Connection: close",
		"http://api.ipify.org/?format=text",
	)
	currentIP, err := sh.Output(cmd, args...)
	t.Log("Current IP:", currentIP)
	assert.NoError(t, err)

	assert.NotEqualf(t, originalIP, currentIP, "Request proxying failed: %s -> %s", originalIP, currentIP)
}

func getForwarderIP() (string, error) {
	cmd, args := execInTestMachineCmd("dig", "forwarder", "+short")
	return sh.Output(cmd, args...)
}

func checkIP(apiURL string) (string, error) {
	cmd, args := execInTestMachineCmd("curl", "-s", apiURL)
	return sh.Output(cmd, args...)
}

func ipTablesAppend(ruleArgs []string) error {
	return execInTestMachine(
		append(
			[]string{"iptables", "-t", "nat", "-A"},
			ruleArgs...,
		)...,
	)
}

func ipTablesDelete(ruleArgs []string) error {
	return execInTestMachine(
		append(
			[]string{"iptables", "-t", "nat", "-D"},
			ruleArgs...,
		)...,
	)
}

func execInTestMachine(args ...string) error {
	cmd, args := execInTestMachineCmd(args...)
	return sh.RunV(cmd, args...)
}

func execInTestMachineCmd(args ...string) (string, []string) {
	return runComposeCmd(append(
		[]string{"exec", "-T", "machine"},
		args...,
	)...)
}
