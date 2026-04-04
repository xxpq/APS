package ssh

import (
	"fmt"
	"io"
	"net"
	"strconv"
)

// The `handleForwardedTCPConnection` function is responsible for handling a forwarded TCP connection.
// It takes a `net.Conn` object as a parameter, which represents the connection that has been forwarded
// to the SSH server.
func (s *session) handleForwardedTCPConnection(conn net.Conn) {
	defer conn.Close()

	// Handle the forwarded TCP connection here
	// You can perform any necessary operations on the connection
	// For example, you can forward the connection to another destination
	// or handle the data flowing through the connection.

	// Example: Simply print the data received from the forwarded connection
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		fmt.Println("Received from forwarded connection:", string(buf[:n]))
	}
}

// The `handleForwardedTCPIPConnection` function is responsible for handling a forwarded TCP/IP
// connection. It takes three parameters: `conn` which represents the connection that has been
// forwarded to the SSH server, `originAddr` which is the address of the original destination, and
// `originPort` which is the port of the original destination.
func (s *session) handleForwardedTCPIPConnection(conn net.Conn, originAddr string, originPort int) {
	defer conn.Close()

	originConn, err := net.Dial("tcp", net.JoinHostPort(originAddr, strconv.Itoa(originPort)))
	if err != nil {
		return
	}
	defer originConn.Close()

	// Forward data between the connections
	go func() {
		io.Copy(originConn, conn)
	}()

	io.Copy(conn, originConn)
}
