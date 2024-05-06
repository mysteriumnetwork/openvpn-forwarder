FROM golang:1.18-alpine

# Install packages
RUN apk add --update --no-cache bash git gcc musl-dev make iptables bind-tools curl

# Waiting for E2E tests to be executed
ENTRYPOINT ["tail", "-f", "/dev/null"]