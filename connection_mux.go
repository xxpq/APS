package main

import (
	"bufio"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// ConnectionMux multiplexes connections based on protocol detection
// It reads the first bytes to determine if it's HTTP or TCP Tunnel protocol
type ConnectionMux struct {
	listener      net.Listener
	httpHandler   func(net.Conn) // Handler for HTTP connections
	tunnelHandler func(net.Conn) // Handler for TCP tunnel connections
	rateLimiter   *RateLimitEngine
	ruleNames     []string
	serverName    string
	mu            sync.RWMutex
	running       bool
}

// RateLimitConn wraps a net.Conn to track connection end
type RateLimitConn struct {
	net.Conn
	onClose func(bytes int64)
	once    sync.Once
	readN   int64
	writeN  int64
}

func (c *RateLimitConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		atomic.AddInt64(&c.readN, int64(n))
	}
	return n, err
}

func (c *RateLimitConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		atomic.AddInt64(&c.writeN, int64(n))
	}
	return n, err
}

func (c *RateLimitConn) totalBytes() int64 {
	return atomic.LoadInt64(&c.readN) + atomic.LoadInt64(&c.writeN)
}

func (c *RateLimitConn) Close() error {
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose(c.totalBytes())
		}
	})
	return c.Conn.Close()
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

// SetRateLimiter sets the rate limiter for connection tracking
func (m *ConnectionMux) SetRateLimiter(limiter *RateLimitEngine, serverName string, ruleNames []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rateLimiter = limiter
	m.serverName = serverName
	m.ruleNames = ruleNames
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
	// Extract IP from connection
	ip := extractIPFromAddr(conn.RemoteAddr().String())

	// Check if IP is banned
	// Check if IP is banned or rate limited
	m.mu.RLock()
	rateLimiter := m.rateLimiter
	serverName := m.serverName
	ruleNames := m.ruleNames
	m.mu.RUnlock()

	if rateLimiter != nil {
		// 1. Check if banned (fast check)
		if rateLimiter.IsBanned(ip) {
			DebugLog("[RATE LIMIT] Blocked connection from banned IP: %s", ip)
			conn.Close()
			return
		}

		// 2. Check rules if any
		if len(ruleNames) > 0 {
			bindings := map[string][]string{
				"server:" + serverName: ruleNames,
			}
			result := rateLimiter.CheckRequest(ip, "", bindings)
			if !result.Allowed {
				DebugLog("[RATE LIMIT] Connection rejected by rule: %s", result.Message)
				conn.Close()
				return
			}

			// 3. Track connection
			rateLimiter.OnRequestStart(ip, "", bindings)

			// Wrap connection to track end
			conn = &RateLimitConn{
				Conn: conn,
				onClose: func(bytes int64) {
					rateLimiter.OnRequestEnd(ip, "", bindings, bytes)
				},
			}
		}
	}

	reader := bufio.NewReader(conn)

	// Peek first 5 bytes (our tunnel header size)
	header, err := reader.Peek(5)
	if err != nil {
		if err != io.EOF {
			conn.Close()
		}
		return
	}

	// Drain all currently buffered bytes into a prefix replay connection so that
	// downstream protocols (HTTP/TLS/smux tunnel) read directly from the raw
	// socket after the initial protocol sniffing step.
	buffered := reader.Buffered()
	prefixBytes, err := reader.Peek(buffered)
	if err != nil {
		conn.Close()
		return
	}
	prefix := make([]byte, len(prefixBytes))
	copy(prefix, prefixBytes)
	routedConn := &prefixedConn{Conn: conn, prefix: prefix}

	m.mu.RLock()
	httpHandler := m.httpHandler
	tunnelHandler := m.tunnelHandler
	m.mu.RUnlock()

	// Detect protocol based on first bytes
	if isTunnelProtocol(header) {
		// TCP Tunnel protocol
		if tunnelHandler != nil {
			tunnelHandler(routedConn)
		} else {
			DebugLog("[MUX] Raw tunnel protocol connection rejected from %s (raw tunnel disabled)", conn.RemoteAddr().String())
			conn.Close()
		}
	} else {
		// Assume HTTP
		if httpHandler != nil {
			httpHandler(routedConn)
		} else {
			routedConn.Close()
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
	// Registration frames are expected to be small, so requiring MSB=0 is a fast filter.
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
