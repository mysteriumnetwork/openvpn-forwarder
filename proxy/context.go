package proxy

import (
	"net"
)

// Context is the Proxy context, contains useful information about every request.
type Context struct {
	scheme          string
	conn            net.Conn
	connOriginalDst *net.TCPAddr

	destinationHost    string
	destinationAddress string
}
