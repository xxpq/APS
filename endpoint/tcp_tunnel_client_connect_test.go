package main

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestConnectWithHTTPTunnelHandshakeDoesNotBlockOn200Body(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		reqLine, err := reader.ReadString('\n')
		if err != nil {
			serverErr <- err
			return
		}
		if !strings.HasPrefix(reqLine, "CONNECT /.tunnel HTTP/1.1") {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				serverErr <- readErr
				return
			}
			if line == "\r\n" {
				break
			}
		}

		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			serverErr <- err
			return
		}
		if _, err := io.WriteString(conn, "PING"); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	clientConn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer clientConn.Close()

	done := make(chan struct{})
	var upgraded net.Conn
	var upgradeErr error
	go func() {
		upgraded, upgradeErr = connectWithHTTPTunnelHandshake(clientConn, ln.Addr().String())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("connectWithHTTPTunnelHandshake timed out")
	}

	if upgradeErr != nil {
		t.Fatalf("handshake failed: %v", upgradeErr)
	}
	defer upgraded.Close()

	buf := make([]byte, 4)
	if _, err := io.ReadFull(upgraded, buf); err != nil {
		t.Fatalf("failed to read tunneled payload: %v", err)
	}
	if string(buf) != "PING" {
		t.Fatalf("unexpected tunneled payload: %q", string(buf))
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server goroutine error: %v", err)
	}
}
