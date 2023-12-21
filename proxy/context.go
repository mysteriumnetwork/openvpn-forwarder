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

	bytesSent     int64
	bytesReceived int64
}

func (c *Context) BytesSent() int64 {
	return c.bytesSent
}

func (c *Context) BytesReceived() int64 {
	return c.bytesReceived
}
