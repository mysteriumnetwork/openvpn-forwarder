//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"os"
	"testing"

	log "github.com/cihub/seelog"
	"github.com/magefile/mage/sh"
	"github.com/pkg/errors"
)

func TestMain(m *testing.M) {
	log.Info("E2E setup started")
	if err := Setup(); err != nil {
		_ = log.Errorf("E2E setup failed. %v")
		return
	}
	log.Trace("E2E setup done")

	log.Info("Starting E2E tests")
	code := m.Run()

	log.Info("E2E teardown started")
	if err := Teardown(); err != nil {
		_ = log.Errorf("E2E teardown failed. %v", err)
	}
	log.Trace("E2E teardown done")

	os.Exit(code)
}

func Setup() (err error) {
	log.Debug("Starting E2E containers")
	if err = runCompose("up", "-d"); err != nil {
		return errors.Wrap(err, "could not start server")
	}

	log.Debug("Started E2E containers:")
	if err = runCompose("ps", "-a"); err != nil {
		return err
	}
	fmt.Println()

	log.Debug("Forwarder logs:")
	if err = runCompose("logs", "forwarder"); err != nil {
		return err
	}
	fmt.Println()

	return nil
}

func Teardown() (err error) {
	log.Debug("Forwarder logs:")
	_ = runCompose("logs", "forwarder")
	fmt.Println()

	err = runCompose("down")
	return err
}

func runCompose(args ...string) error {
	cmd, args := runComposeCmd(args...)
	return sh.RunV(cmd, args...)
}

func runComposeCmd(args ...string) (string, []string) {
	return "docker-compose", append(
		[]string{
			"-f", "../docker-compose.yml",
		},
		args...,
	)
}
