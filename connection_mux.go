package main

import (
	"bufio"
	"errors"
	"io"
	"net"
	"sync"
)

// ConnectionMux multiplexes connections based on protocol detection
// It reads the first bytes to determine if it's HTTP or TCP Tunnel protocol
type ConnectionMux struct {
	listener      net.Listener
	httpHandler   func(net.Conn) // Handler for HTTP connections
	tunnelHandler func(net.Conn) // Handler for TCP tunnel connections
	mu            sync.RWMutex
	running       bool
}

// PeekConn wraps a net.Conn with peek/unread capability
type PeekConn struct {
	net.Conn
	reader *bufio.Reader
}

// NewPeekConn wraps a connection with peek capability using pooled bufio.Reader
func NewPeekConn(conn net.Conn) *PeekConn {
	return &PeekConn{
		Conn:   conn,
		reader: GetBufioReader(conn),
	}
}

// Close returns the bufio.Reader to the pool and closes the underlying connection
func (c *PeekConn) Close() error {
	// PutBufioReader(c.reader) // Unsafe to recycle as Read might be concurrent
	return c.Conn.Close()
}

// Read reads from the buffered reader
func (c *PeekConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// Peek returns the next n bytes without advancing the reader
func (c *PeekConn) Peek(n int) ([]byte, error) {
	return c.reader.Peek(n)
}

// NewConnectionMux creates a new connection multiplexer
func NewConnectionMux(listener net.Listener) *ConnectionMux {
	return &ConnectionMux{
		listener: listener,
	}
}

// SetHTTPHandler sets the handler for HTTP connections
func (m *ConnectionMux) SetHTTPHandler(handler func(net.Conn)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.httpHandler = handler
}

// SetTunnelHandler sets the handler for TCP tunnel connections
func (m *ConnectionMux) SetTunnelHandler(handler func(net.Conn)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunnelHandler = handler
}

// Start starts accepting and routing connections
func (m *ConnectionMux) Start() {
	m.mu.Lock()
	m.running = true
	m.mu.Unlock()

	for {
		conn, err := m.listener.Accept()
		if err != nil {
			m.mu.RLock()
			running := m.running
			m.mu.RUnlock()
			if !running {
				return
			}
			continue
		}

		go m.handleConnection(conn)
	}
}

// Stop stops the multiplexer
func (m *ConnectionMux) Stop() {
	m.mu.Lock()
	m.running = false
	m.mu.Unlock()
	m.listener.Close()
}

// handleConnection detects protocol and routes connection
func (m *ConnectionMux) handleConnection(conn net.Conn) {
	peekConn := NewPeekConn(conn)

	// Peek first 5 bytes (our tunnel header size)
	header, err := peekConn.Peek(5)
	if err != nil {
		if err != io.EOF {
			conn.Close()
		}
		return
	}

	m.mu.RLock()
	httpHandler := m.httpHandler
	tunnelHandler := m.tunnelHandler
	m.mu.RUnlock()

	// Detect protocol based on first bytes
	if isTunnelProtocol(header) {
		// TCP Tunnel protocol
		if tunnelHandler != nil {
			tunnelHandler(peekConn)
		} else {
			conn.Close()
		}
	} else {
		// Assume HTTP
		if httpHandler != nil {
			httpHandler(peekConn)
		} else {
			// Return reader to pool before closing
			peekConn.Close()
		}
	}
}

// isTunnelProtocol checks if the data looks like our tunnel protocol
// Our tunnel messages start with 4-byte length + 1-byte type
// HTTP requests start with method (GET, POST, PUT, etc.)
func isTunnelProtocol(header []byte) bool {
	if len(header) < 5 {
		return false
	}

	// Check if first byte looks like ASCII HTTP method using O(1) lookup
	firstByte := header[0]
	if httpMethodFirstBytes[firstByte] {
		return false // Looks like HTTP
	}

	// Stricter check for Tunnel Protocol
	// Our protocol uses a 4-byte Big Endian length prefix.
	// The maximum message size is 10MB, so the first byte (MSB) MUST be 0.
	// This effectively filters out TLS (starts with 0x16) and many other protocols.
	if firstByte != 0x00 {
		return false
	}

	// Check if message type is valid tunnel type using O(1) lookup
	msgType := header[4]
	return validTunnelTypes[msgType]
}

// ChannelListener implements net.Listener using a channel
type ChannelListener struct {
	ch   chan net.Conn
	addr net.Addr
	mu   sync.Mutex
	done chan struct{}
}

// NewChannelListener creates a new ChannelListener
func NewChannelListener(addr net.Addr) *ChannelListener {
	return &ChannelListener{
		ch:   make(chan net.Conn, 100), // Buffer to avoid blocking Mux too much
		addr: addr,
		done: make(chan struct{}),
	}
}

// Accept waits for and returns the next connection to the listener.
func (l *ChannelListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.ch:
		if !ok {
			return nil, errors.New("listener closed")
		}
		return c, nil
	case <-l.done:
		return nil, errors.New("listener closed")
	}
}

// Close closes the listener.
func (l *ChannelListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.done:
		return nil // Already closed
	default:
		close(l.done)
		// We don't close l.ch here to avoid panic if someone writes to it
		// But we should signal writers to stop?
		// Since Mux writes to it, Mux should handle it.
	}
	return nil
}

// Addr returns the listener's network address.
func (l *ChannelListener) Addr() net.Addr {
	return l.addr
}

// Push adds a connection to the listener
func (l *ChannelListener) Push(conn net.Conn) {
	select {
	case l.ch <- conn:
	case <-l.done:
		conn.Close()
	}
}
