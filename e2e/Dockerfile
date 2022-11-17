FROM golang:1.18-alpine

# Install packages
RUN apk add --update --no-cache bash git gcc musl-dev make iptables bind-tools

# Install application
WORKDIR /go/src/github.com/mysteriumnetwork/openvpn-forwarder
ADD . .