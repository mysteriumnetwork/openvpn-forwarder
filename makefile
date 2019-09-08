# This Makefile is meant to be used by people that do not usually work with Go source code.
# If you know what GOPATH is then you probably don't need to bother with make.

GO_PATH=$(shell go env GOPATH)
DEP_PATH=$(GO_PATH)/bin/dep
MAGE=go run ci/mage.go

% :
ifeq ("$(wildcard $(DEP_PATH))", "")
	go get -u github.com/golang/dep/cmd/dep
endif
	${DEP_PATH} ensure -v -vendor-only
	${MAGE} $(MAKECMDGOALS)
