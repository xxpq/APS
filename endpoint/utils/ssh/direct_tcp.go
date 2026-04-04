package ssh

import (
	"io"
	"net"
	"strconv"
)

// The `handleDirectTCPConnection` function is a method of the `session` struct. It takes three
// parameters: `conn` of type `net.Conn`, `destAddr` of type `string`, and `destPort` of type `int`.
func (s *session) handleDirectTCPConnection(conn net.Conn, destAddr string, destPort int) {
	defer conn.Close()

	destConn, err := net.Dial("tcp", net.JoinHostPort(destAddr, strconv.Itoa(destPort)))
	if err != nil {
		return
	}
	defer destConn.Close()

	// Forward data between the connections
	go func() {
		io.Copy(destConn, conn)
	}()

	io.Copy(conn, destConn)
}
