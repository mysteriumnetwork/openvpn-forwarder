//go:build mage
// +build mage

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
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/mysteriumnetwork/go-ci/commands"

	// mage:import
	_ "github.com/mysteriumnetwork/openvpn-forwarder/ci/commands"
)

const buildPath = "./build/forwarder"

// Builds the application
func Build() error {
	return sh.RunV("go", "build", "-o", buildPath, "./main.go")
}

// Run the application
func Run() error {
	return sh.RunV(buildPath,
		"--log.level=trace",
		"--proxy.bind=:8443",
		"--proxy.allow=0.0.0.0/0",
		"--proxy.upstream-url=http://superproxy.com:8080",
		"--proxy.user=",
		"--proxy.pass=",
		"--filter.zones=api.ipify.org",
		"--exclude.hostnames=ipify.org",
	)
}

// Runs the test suite against the repo
func Test() error {
	return commands.Test("./...")
}

// Checks that the source is compliant with go vet
func Check() {
	mg.Deps(CheckGoImports, CheckGoLint, CheckGoVet, CheckCopyright)
}

// Checks for issues with go imports
func CheckGoImports() error {
	return commands.GoImports("./...")
}

// Reports linting errors in the solution
func CheckGoLint() error {
	return commands.GoLint("./...")
}

// Checks that the source is compliant with go vet
func CheckGoVet() error {
	return commands.GoVet("./...")
}

// Checks for copyright headers in files
func CheckCopyright() error {
	return commands.Copyright("./...")
}
