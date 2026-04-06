package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

func TestDirectTCPIPAndRemoteForwarding(t *testing.T) {
	serverAddr, stopServer := startTestSSHServer(t)
	defer stopServer()

	client := connectTestSSHClient(t, serverAddr)
	defer client.Close()

	t.Run("direct-tcpip", func(t *testing.T) {
		echoAddr, stopEcho := startEchoServer(t)
		defer stopEcho()

		conn, err := client.Dial("tcp", echoAddr)
		if err != nil {
			t.Fatalf("client.Dial via direct-tcpip failed: %v", err)
		}
		defer conn.Close()

		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		want := []byte("ping")
		if _, err := conn.Write(want); err != nil {
			t.Fatalf("write through direct-tcpip failed: %v", err)
		}

		got := make([]byte, len(want))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("read through direct-tcpip failed: %v", err)
		}
		if string(got) != string(want) {
			t.Fatalf("direct-tcpip response = %q, want %q", got, want)
		}
	})

	t.Run("tcpip-forward-and-forwarded-tcpip", func(t *testing.T) {
		remoteListener, err := client.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("client.Listen (tcpip-forward) failed: %v", err)
		}
		forwardAddr := remoteListener.Addr().String()

		acceptCh := make(chan net.Conn, 1)
		errCh := make(chan error, 1)
		go func() {
			conn, err := remoteListener.Accept()
			if err != nil {
				errCh <- err
				return
			}
			acceptCh <- conn
		}()

		dialConn, err := net.DialTimeout("tcp", remoteListener.Addr().String(), 3*time.Second)
		if err != nil {
			t.Fatalf("dial forwarded listener failed: %v", err)
		}
		defer dialConn.Close()

		var forwardedConn net.Conn
		select {
		case forwardedConn = <-acceptCh:
		case err := <-errCh:
			t.Fatalf("accept forwarded connection failed: %v", err)
		case <-time.After(3 * time.Second):
			t.Fatal("timeout waiting for forwarded-tcpip connection")
		}
		defer forwardedConn.Close()

		_ = dialConn.SetDeadline(time.Now().Add(3 * time.Second))
		_ = forwardedConn.SetDeadline(time.Now().Add(3 * time.Second))

		c2s := []byte("client->server")
		if _, err := dialConn.Write(c2s); err != nil {
			t.Fatalf("write to forwarded listener failed: %v", err)
		}
		gotC2S := make([]byte, len(c2s))
		if _, err := io.ReadFull(forwardedConn, gotC2S); err != nil {
			t.Fatalf("read forwarded-tcpip channel failed: %v", err)
		}
		if string(gotC2S) != string(c2s) {
			t.Fatalf("forwarded payload = %q, want %q", gotC2S, c2s)
		}

		s2c := []byte("server->client")
		if _, err := forwardedConn.Write(s2c); err != nil {
			t.Fatalf("write forwarded-tcpip channel failed: %v", err)
		}
		gotS2C := make([]byte, len(s2c))
		if _, err := io.ReadFull(dialConn, gotS2C); err != nil {
			t.Fatalf("read from forwarded listener failed: %v", err)
		}
		if string(gotS2C) != string(s2c) {
			t.Fatalf("reverse forwarded payload = %q, want %q", gotS2C, s2c)
		}

		if err := remoteListener.Close(); err != nil {
			t.Fatalf("close remote listener failed: %v", err)
		}

		// Closing the listener sends cancel-tcpip-forward. Wait until the remote
		// port is actually revoked.
		deadline := time.Now().Add(2 * time.Second)
		for {
			conn, err := net.DialTimeout("tcp", forwardAddr, 200*time.Millisecond)
			if err != nil {
				break
			}
			_ = conn.Close()
			if time.Now().After(deadline) {
				t.Fatalf("remote forwarded listener still accepts connections after cancel: %s", forwardAddr)
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
}

func startTestSSHServer(t *testing.T) (string, func()) {
	t.Helper()

	srv, err := NewServer()
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	hostKey, err := generateTestHostKeyPEM()
	if err != nil {
		t.Fatalf("generate host key failed: %v", err)
	}
	if err := srv.SetHostKey(hostKey); err != nil {
		t.Fatalf("SetHostKey failed: %v", err)
	}
	srv.SetAuthorizedPassword("tester", "secret")

	addr := getFreeTCPAddr(t)
	runDone := make(chan error, 1)
	go func() {
		runDone <- srv.Run(addr)
	}()

	waitForTCPReady(t, addr)

	stop := func() {
		srv.Stop()
		select {
		case <-runDone:
		case <-time.After(3 * time.Second):
			t.Log("timeout waiting for ssh server shutdown")
		}
	}
	return addr, stop
}

func connectTestSSHClient(t *testing.T, addr string) *gossh.Client {
	t.Helper()

	cfg := &gossh.ClientConfig{
		User:            "tester",
		Auth:            []gossh.AuthMethod{gossh.Password("secret")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := gossh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("ssh dial failed: %v", err)
	}
	return client
}

func startEchoServer(t *testing.T) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start echo listener failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	stop := func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(1 * time.Second):
			t.Log("timeout waiting echo server shutdown")
		}
	}
	return ln.Addr().String(), stop
}

func getFreeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate free tcp addr failed: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func waitForTCPReady(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("ssh server did not become ready at %s", addr)
}

func generateTestHostKeyPEM() ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	bytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if len(bytes) == 0 {
		return nil, fmt.Errorf("empty private key")
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: bytes,
	}), nil
}
