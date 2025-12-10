package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RawTCPServer manages a raw TCP server for forwarding connections
type RawTCPServer struct {
	name          string
	config        *ListenConfig
	appConfig     *Config
	listener      net.Listener
	tunnelManager TunnelManagerInterface
	trafficShaper *TrafficShaper
	stats         *StatsCollector
	dataStore     *DataStore
	mappings      []*Mapping
	mu            sync.Mutex
	closed        bool
}

// NewRawTCPServer creates a new raw TCP server
func NewRawTCPServer(name string, config *ListenConfig, appConfig *Config, mappings []*Mapping,
	tunnelManager TunnelManagerInterface, trafficShaper *TrafficShaper, stats *StatsCollector, dataStore *DataStore) *RawTCPServer {
	return &RawTCPServer{
		name:          name,
		config:        config,
		appConfig:     appConfig,
		mappings:      mappings,
		tunnelManager: tunnelManager,
		trafficShaper: trafficShaper,
		stats:         stats,
		dataStore:     dataStore,
	}
}

// Start starts the TCP server and begins accepting connections
func (s *RawTCPServer) Start() error {
	// Determine bind address
	host := "127.0.0.1"
	if s.config.Public == nil || *s.config.Public {
		host = "0.0.0.0"
	}
	addr := fmt.Sprintf("%s:%d", host, s.config.Port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = listener

	log.Printf("[RAW TCP] Server '%s' listening on %s", s.name, addr)

	go s.acceptLoop()
	return nil
}

// Stop stops the TCP server
func (s *RawTCPServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// UpdateMappings updates the mappings for this server (for config hot reload)
func (s *RawTCPServer) UpdateMappings(mappings []*Mapping) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mappings = mappings
	log.Printf("[RAW TCP] Server '%s' mappings updated (%d mappings)", s.name, len(mappings))
}

// acceptLoop accepts incoming connections
func (s *RawTCPServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			log.Printf("[RAW TCP] Accept error on '%s': %v", s.name, err)
			continue
		}

		go s.handleConnection(conn)
	}
}

// handleConnection handles a single TCP connection
func (s *RawTCPServer) handleConnection(clientConn net.Conn) {
	// Note: bidirectionalCopy will close clientConn when done
	// We only need to close it here if we return early

	startTime := time.Now()
	s.stats.IncTotalRequests()
	s.stats.IncActiveConnections()
	defer s.stats.DecActiveConnections()

	clientAddr := clientConn.RemoteAddr().String()
	log.Printf("[RAW TCP] New connection from %s on server '%s'", clientAddr, s.name)

	// Find matching mapping for this server
	mapping := s.findMapping()
	if mapping == nil {
		log.Printf("[RAW TCP] No mapping found for server '%s'", s.name)
		clientConn.Close()
		return
	}

	// Parse target URL from mapping
	toURL := mapping.GetToURL()
	targetHost, targetPort, useTLS, err := parseTCPURL(toURL)
	if err != nil {
		log.Printf("[RAW TCP] Invalid target URL '%s': %v", toURL, err)
		clientConn.Close()
		return
	}

	// Check if we need to use tunnel/proxy via 'via' configuration
	// via.tunnels -> mapping.tunnelNames
	// via.endpoints -> mapping.endpointNames
	if mapping.Via != nil && (len(mapping.tunnelNames) > 0 || len(mapping.endpointNames) > 0) {
		s.forwardViaTunnel(clientConn, mapping, targetHost, targetPort, useTLS, clientAddr)
	} else if mapping.resolvedProxy != nil {
		s.forwardViaProxy(clientConn, mapping, targetHost, targetPort)
	} else {
		s.forwardDirect(clientConn, targetHost, targetPort)
	}

	responseTime := time.Since(startTime)
	log.Printf("[RAW TCP] Connection from %s closed after %v", clientAddr, responseTime)
}

// findMapping finds a matching mapping for this TCP server
func (s *RawTCPServer) findMapping() *Mapping {
	// First, try to find a mapping explicitly assigned to this server
	for _, m := range s.mappings {
		for _, serverName := range m.serverNames {
			if serverName == s.name {
				fromURL := m.GetFromURL()
				if strings.HasPrefix(fromURL, "tcp://") {
					log.Printf("[RAW TCP] Found explicit mapping for server '%s': %s -> %s", s.name, fromURL, m.GetToURL())
					return m
				}
			}
		}
	}

	// If no explicit mapping, try to match by port
	// This handles the case where mapping doesn't specify servers
	serverPort := s.config.Port
	for _, m := range s.mappings {
		fromURL := m.GetFromURL()
		if !strings.HasPrefix(fromURL, "tcp://") {
			continue
		}

		// Parse the from URL to get the port
		u, err := url.Parse(fromURL)
		if err != nil {
			continue
		}

		portStr := u.Port()
		if portStr == "" {
			continue
		}

		mappingPort, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		// If ports match, use this mapping
		if mappingPort == serverPort {
			log.Printf("[RAW TCP] Found port-based mapping for server '%s' (port %d): %s -> %s",
				s.name, serverPort, fromURL, m.GetToURL())
			return m
		}
	}

	log.Printf("[RAW TCP] No matching mapping found for server '%s' (port %d)", s.name, serverPort)
	return nil
}

// parseTCPURL parses a tcp:// or tcps:// URL and returns host, port, and TLS flag
func parseTCPURL(rawURL string) (host string, port int, useTLS bool, err error) {
	// Handle tcps:// for TLS
	if strings.HasPrefix(rawURL, "tcps://") {
		useTLS = true
		rawURL = "tcp://" + strings.TrimPrefix(rawURL, "tcps://")
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return "", 0, false, err
	}

	if u.Scheme != "tcp" {
		return "", 0, false, fmt.Errorf("unsupported scheme: %s, expected tcp:// or tcps://", u.Scheme)
	}

	host = u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		return "", 0, false, fmt.Errorf("port is required in tcp:// URL")
	}

	port, err = strconv.Atoi(portStr)
	if err != nil {
		return "", 0, false, fmt.Errorf("invalid port: %s", portStr)
	}

	return host, port, useTLS, nil
}

// forwardDirect forwards the connection directly to the target
func (s *RawTCPServer) forwardDirect(clientConn net.Conn, targetHost string, targetPort int) {
	targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	log.Printf("[RAW TCP] Forwarding to %s (direct)", targetAddr)

	targetConn, err := net.DialTimeout("tcp", targetAddr, 30*time.Second)
	if err != nil {
		log.Printf("[RAW TCP] Failed to connect to %s: %v", targetAddr, err)
		return
	}
	log.Printf("[RAW TCP] Connected to target %s, starting bidirectional copy", targetAddr)

	// Don't defer close here - bidirectionalCopy will handle closing
	s.bidirectionalCopy(clientConn, targetConn)
	log.Printf("[RAW TCP] Bidirectional copy finished for %s", targetAddr)
}

// forwardViaProxy forwards the connection via HTTP CONNECT proxy
func (s *RawTCPServer) forwardViaProxy(clientConn net.Conn, mapping *Mapping, targetHost string, targetPort int) {
	proxyURL := mapping.resolvedProxy.GetRandomProxy()
	if proxyURL == "" {
		log.Printf("[RAW TCP] No proxy available")
		s.forwardDirect(clientConn, targetHost, targetPort)
		return
	}

	log.Printf("[RAW TCP] Forwarding to %s:%d via proxy %s", targetHost, targetPort, proxyURL)

	// Parse proxy URL
	u, err := url.Parse(proxyURL)
	if err != nil {
		log.Printf("[RAW TCP] Invalid proxy URL: %v", err)
		clientConn.Close()
		return
	}

	// Connect to proxy
	proxyConn, err := net.DialTimeout("tcp", u.Host, 30*time.Second)
	if err != nil {
		log.Printf("[RAW TCP] Failed to connect to proxy %s: %v", u.Host, err)
		clientConn.Close()
		return
	}

	// Send CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n", targetHost, targetPort, targetHost, targetPort)

	// Add proxy auth if present
	if u.User != nil {
		password, _ := u.User.Password()
		auth := u.User.Username() + ":" + password
		encoded := encodeBase64(auth)
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", encoded)
	}
	connectReq += "\r\n"

	_, err = proxyConn.Write([]byte(connectReq))
	if err != nil {
		log.Printf("[RAW TCP] Failed to send CONNECT request: %v", err)
		proxyConn.Close()
		clientConn.Close()
		return
	}

	// Read response (simple check for 200)
	buf := make([]byte, 1024)
	n, err := proxyConn.Read(buf)
	if err != nil {
		log.Printf("[RAW TCP] Failed to read CONNECT response: %v", err)
		proxyConn.Close()
		clientConn.Close()
		return
	}

	response := string(buf[:n])
	if !strings.Contains(response, "200") {
		log.Printf("[RAW TCP] CONNECT failed: %s", strings.TrimSpace(response))
		proxyConn.Close()
		clientConn.Close()
		return
	}

	log.Printf("[RAW TCP] CONNECT tunnel established via proxy")
	// bidirectionalCopy will close both connections
	s.bidirectionalCopy(clientConn, proxyConn)
}

// forwardViaTunnel forwards the connection via the tunnel
func (s *RawTCPServer) forwardViaTunnel(clientConn net.Conn, mapping *Mapping, targetHost string, targetPort int, useTLS bool, clientAddr string) {
	log.Printf("[RAW TCP] Forwarding to %s:%d via tunnel (client: %s)", targetHost, targetPort, clientAddr)

	// Get tunnel and endpoint
	tunnelName, endpointName, err := s.getTunnelAndEndpoint(mapping)
	if err != nil {
		log.Printf("[RAW TCP] Failed to get tunnel/endpoint: %v", err)
		// Fallback to direct connection
		s.forwardDirect(clientConn, targetHost, targetPort)
		return
	}

	log.Printf("[RAW TCP] Using tunnel '%s' endpoint '%s'", tunnelName, endpointName)

	// Use TunnelManager to establish proxy connection
	// NOTE: SendProxyConnect starts proxyClientReadLoop which handles bidirectional data flow
	// We should NOT read from or modify clientConn after this call - the tunnel manager owns it now
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Pass client IP for security audit logging on endpoint
	log.Printf("[RAW TCP] Calling SendProxyConnect for %s:%d", targetHost, targetPort)
	done, err := s.tunnelManager.SendProxyConnect(ctx, tunnelName, endpointName, targetHost, targetPort, useTLS, clientConn, clientAddr)
	if err != nil {
		log.Printf("[RAW TCP] Tunnel proxy connect failed: %v", err)
		clientConn.Close()
		return
	}

	log.Printf("[RAW TCP] Tunnel proxy connection established, waiting for data flow completion")

	// Wait for the tunnel manager to signal that the connection is done
	// The done channel will be closed when:
	// 1. The client closes the connection
	// 2. The endpoint closes the connection
	// 3. An error occurs
	<-done
	log.Printf("[RAW TCP] Tunnel connection closed (client: %s)", clientAddr)
}

// getTunnelAndEndpoint gets the tunnel and endpoint names from mapping configuration
func (s *RawTCPServer) getTunnelAndEndpoint(mapping *Mapping) (tunnelName, endpointName string, err error) {
	// First try to get from tunnel manager using endpoint names
	if len(mapping.endpointNames) > 0 {
		// Pick a random endpoint name
		endpointName = mapping.endpointNames[0]
		if len(mapping.endpointNames) > 1 {
			endpointName = mapping.endpointNames[rand.Intn(len(mapping.endpointNames))]
		}

		// Find which tunnel this endpoint belongs to
		if tName, found := s.tunnelManager.FindTunnelForEndpoint(endpointName); found {
			return tName, endpointName, nil
		}
	}

	// Try to get from tunnel names
	if len(mapping.tunnelNames) > 0 {
		tunnelName = mapping.tunnelNames[0]
		if len(mapping.tunnelNames) > 1 {
			tunnelName = mapping.tunnelNames[rand.Intn(len(mapping.tunnelNames))]
		}

		// Get a random endpoint from this tunnel
		if _, epName, err := s.tunnelManager.GetRandomEndpointFromTunnels([]string{tunnelName}); err == nil {
			return tunnelName, epName, nil
		}

		return "", "", fmt.Errorf("no available endpoint in tunnel '%s'", tunnelName)
	}

	return "", "", fmt.Errorf("no tunnel or endpoint configured")
}

// bidirectionalCopy copies data between two connections bidirectionally
func (s *RawTCPServer) bidirectionalCopy(conn1, conn2 net.Conn) {
	var bytesSent, bytesRecv int64
	var wg sync.WaitGroup
	var once sync.Once

	// Close both connections when either direction finishes
	closeConns := func() {
		once.Do(func() {
			conn1.Close()
			conn2.Close()
		})
	}

	wg.Add(2)

	// conn1 -> conn2 (upload from client perspective)
	go func() {
		defer wg.Done()
		n, err := io.Copy(conn2, conn1)
		bytesRecv = n
		if err != nil && !isClosedConnError(err) {
			log.Printf("[RAW TCP] Copy conn1->conn2 error: %v", err)
		}
		closeConns() // Close both to unblock the other goroutine
	}()

	// conn2 -> conn1 (download from client perspective)
	go func() {
		defer wg.Done()
		n, err := io.Copy(conn1, conn2)
		bytesSent = n
		if err != nil && !isClosedConnError(err) {
			log.Printf("[RAW TCP] Copy conn2->conn1 error: %v", err)
		}
		closeConns() // Close both to unblock the other goroutine
	}()

	// Wait for both goroutines to complete
	wg.Wait()

	s.stats.AddBytesSent(uint64(bytesSent))
	s.stats.AddBytesRecv(uint64(bytesRecv))

	log.Printf("[RAW TCP] Transfer complete. Sent: %d bytes, Received: %d bytes", bytesSent, bytesRecv)
}

// isClosedConnError checks if the error is due to a closed connection
func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "broken pipe") ||
		err == io.EOF
}

// waitForClose waits for a connection to be closed
func waitForClose(conn net.Conn) {
	buf := make([]byte, 1)
	for {
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		_, err := conn.Read(buf)
		if err != nil {
			return
		}
	}
}

// encodeBase64 encodes a string to base64
func encodeBase64(s string) string {
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var result strings.Builder
	input := []byte(s)

	for i := 0; i < len(input); i += 3 {
		var b1, b2, b3 byte
		b1 = input[i]
		if i+1 < len(input) {
			b2 = input[i+1]
		}
		if i+2 < len(input) {
			b3 = input[i+2]
		}

		result.WriteByte(base64Chars[b1>>2])
		result.WriteByte(base64Chars[((b1&0x03)<<4)|(b2>>4)])

		if i+1 < len(input) {
			result.WriteByte(base64Chars[((b2&0x0f)<<2)|(b3>>6)])
		} else {
			result.WriteByte('=')
		}

		if i+2 < len(input) {
			result.WriteByte(base64Chars[b3&0x3f])
		} else {
			result.WriteByte('=')
		}
	}

	return result.String()
}
