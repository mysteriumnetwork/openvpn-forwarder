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

package commands

import (
	"errors"
	"fmt"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

var (
	dockerCompose    = sh.RunCmd("docker-compose", "-f", "docker-compose.yml")
	dockerComposeOut = sh.OutCmd("docker-compose", "-f", "docker-compose.yml")
	ipTablesAppend   = sh.RunCmd("docker-compose", "exec", "forwarder", "iptables", "-t", "nat", "-A")
	ipTablesDelete   = sh.RunCmd("docker-compose", "exec", "forwarder", "iptables", "-t", "nat", "-D")
)

// TestE2E runs end-to-end test
func TestE2E() {
	dockerCompose("up", "-d")
	defer dockerCompose("down")

	mg.Deps(TestE2EHTTP, TestE2EHTTPS)
}

// TestE2EHTTPS runs end-to-end test for HTTPS traffic forwarding
func TestE2EHTTPS() error {
	originalIP := checkIP("https://api.ipify.org/?format=text")
	fmt.Println("Original IP:", originalIP)

	redirectRule := []string{"OUTPUT", "-p", "tcp", "-m", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", "8443"}
	if err := ipTablesAppend(redirectRule...); err != nil {
		return err
	}
	defer ipTablesDelete(redirectRule...)

	currentIP := checkIP("https://api.ipify.org/?format=text")
	fmt.Println("Current IP:", currentIP)

	if currentIP == originalIP {
		return errors.New("request proxying failed")
	}
	fmt.Printf("Request successfuly proxied: %s -> %s", originalIP, currentIP)
	return nil
}

// TestE2EHTTP runs end-to-end test for HTTP traffic forwarding
func TestE2EHTTP() error {
	originalIP := checkIP("http://api.ipify.org/?format=text")
	fmt.Println("Original IP:", originalIP)

	redirectRule := []string{"OUTPUT", "-p", "tcp", "-m", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", "8443"}
	if err := ipTablesAppend(redirectRule...); err != nil {
		return err
	}
	defer ipTablesDelete(redirectRule...)

	currentIP := checkIP("http://api.ipify.org/?format=text")
	fmt.Println("Current IP:", currentIP)

	if currentIP == originalIP {
		return errors.New("request proxying failed")
	}
	fmt.Printf("Request successfuly proxied: %s -> %s", originalIP, currentIP)
	return nil
}

func checkIP(apiURL string) string {
	ip, err := dockerComposeOut("exec", "forwarder", "wget", "-q", "-O", "-", apiURL)
	if err != nil {
		panic(err)
	}

	return ip
}
