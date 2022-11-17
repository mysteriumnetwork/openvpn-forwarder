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
	"fmt"

	"github.com/magefile/mage/sh"
)

var dockerCompose = sh.RunCmd("docker-compose", "-f", "docker-compose.yml")

// TestE2E runs end-to-end test
func TestE2E() (err error) {
	fmt.Println("Starting E2E containers")
	if err = runCompose("up", "-d"); err != nil {
		return err
	}

	defer func() {
		fmt.Println("Forwarder logs:")
		_ = runCompose("logs", "forwarder")
		fmt.Println()

		err = runCompose("down")
	}()

	fmt.Println("Starting E2E tests")
	return runCompose("run", "-T", "machine", "go", "test", "-v", "-tags=e2e", "./e2e/...")
}

func runCompose(args ...string) error {
	return sh.RunV(
		"docker-compose",
		append(
			[]string{
				"-f", "docker-compose.yml",
			},
			args...,
		)...,
	)
}
