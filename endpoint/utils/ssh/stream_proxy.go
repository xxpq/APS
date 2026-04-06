package ssh

import (
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

func pipeChannelAndConn(channel ssh.Channel, conn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(channel, conn)
		_ = channel.CloseWrite()
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, channel)
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
	_ = channel.Close()
	_ = conn.Close()
}
