package main

import (
	"crypto/tls"
	"net"
	"time"
)

type TlsListener struct {
	net.Listener
	tlsConfig *tls.Config
}

func NewTlsListener(inner net.Listener, tlsConfig *tls.Config) *TlsListener {
	return &TlsListener{
		Listener:  inner,
		tlsConfig: tlsConfig,
	}
}

func (l *TlsListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Sniff the first byte to determine if it's a TLS handshake
	buf := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, err = conn.Read(buf)
	conn.SetReadDeadline(time.Time{}) // Clear deadline

	if err != nil {
		// Could be a timeout if the client doesn't send data, treat as HTTP
		return &prefixedConn{conn, buf[:0]}, nil
	}

	// If the first byte is 0x16 (SSL/TLS handshake), wrap in TLS
	if buf[0] == 0x16 {
		return tls.Server(&prefixedConn{conn, buf}, l.tlsConfig), nil
	}

	// Otherwise, treat as plain HTTP
	return &prefixedConn{conn, buf}, nil
}

// prefixedConn is a net.Conn that allows peeking at the first byte(s)
type prefixedConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixedConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}