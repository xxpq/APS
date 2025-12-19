package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RawUDPServer manages a raw UDP server for forwarding packets
type RawUDPServer struct {
	name          string
	config        *ListenConfig
	appConfig     *Config
	conn          *net.UDPConn
	tunnelManager TunnelManagerInterface
	trafficShaper *TrafficShaper
	stats         *StatsCollector
	loggingDB     *LoggingDB
	mappings      []*Mapping
	mu            sync.RWMutex
	sessions      map[string]*UDPSession // ClientAddr -> Session
	closed        bool
	ctx           context.Context
	cancel        context.CancelFunc
}

// UDPSession represents a UDP "session" from a specific client
type UDPSession struct {
	ClientAddr *net.UDPAddr
	TargetConn *net.UDPConn
	LastActive time.Time
	mu         sync.Mutex
}

// NewRawUDPServer creates a new raw UDP server
func NewRawUDPServer(name string, config *ListenConfig, appConfig *Config, mappings []*Mapping,
	tunnelManager TunnelManagerInterface, trafficShaper *TrafficShaper, stats *StatsCollector, loggingDB *LoggingDB) *RawUDPServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &RawUDPServer{
		name:          name,
		config:        config,
		appConfig:     appConfig,
		mappings:      mappings,
		tunnelManager: tunnelManager,
		trafficShaper: trafficShaper,
		stats:         stats,
		loggingDB:     loggingDB,
		sessions:      make(map[string]*UDPSession),
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Start starts the UDP server and begins accepting packets
func (s *RawUDPServer) Start() error {
	// Determine bind address
	host := "127.0.0.1"
	if s.config.Public == nil || *s.config.Public {
		host = "0.0.0.0"
	}
	addrStr := fmt.Sprintf("%s:%d", host, s.config.Port)
	addr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address %s: %w", addrStr, err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP %s: %w", addrStr, err)
	}
	s.conn = conn

	log.Printf("[RAW UDP] Server '%s' listening on %s", s.name, addrStr)

	go s.readLoop()
	go s.cleanupLoop()
	return nil
}

// Stop stops the UDP server
func (s *RawUDPServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	s.cancel()

	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// UpdateMappings updates the mappings for this server (for config hot reload)
func (s *RawUDPServer) UpdateMappings(mappings []*Mapping) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mappings = mappings
	log.Printf("[RAW UDP] Server '%s' mappings updated (%d mappings)", s.name, len(mappings))
}

// readLoop reads incoming UDP packets
func (s *RawUDPServer) readLoop() {
	buf := make([]byte, 65535) // Max UDP packet size
	for {
		n, clientAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if !s.closed {
				log.Printf("[RAW UDP] Read error on '%s': %v", s.name, err)
			}
			return
		}

		// Handle packet in a goroutine to avoid blocking read loop?
		// For UDP, handling per packet might be too heavy if we spawn a goroutine per packet.
		// But we need to look up session and possibly dial target.
		// Let's do it synchronously for now, or maybe dispatch to a worker pool if needed.
		// Given the session lookup is fast, we can try doing it here, but sending to target might block.
		// Better to copy data and handle async.
		data := make([]byte, n)
		copy(data, buf[:n])
		go s.handlePacket(clientAddr, data)
	}
}

// handlePacket handles a single UDP packet
func (s *RawUDPServer) handlePacket(clientAddr *net.UDPAddr, data []byte) {
	clientKey := clientAddr.String()

	s.mu.RLock()
	session, exists := s.sessions[clientKey]
	s.mu.RUnlock()

	if !exists {
		// Create new session
		var err error
		session, err = s.createSession(clientAddr)
		if err != nil {
			log.Printf("[RAW UDP] Failed to create session for %s: %v", clientKey, err)
			return
		}
		if session == nil {
			// No mapping found or blocked
			return
		}

		s.mu.Lock()
		s.sessions[clientKey] = session
		s.mu.Unlock()
	}

	// Update activity
	session.mu.Lock()
	session.LastActive = time.Now()
	targetConn := session.TargetConn
	session.mu.Unlock()

	if targetConn != nil {
		_, err := targetConn.Write(data)
		if err != nil {
			log.Printf("[RAW UDP] Failed to write to target for %s: %v", clientKey, err)
		} else {
			// Update stats
			s.stats.IncTotalRequests() // Count packets as requests? Or sessions?
			// Maybe count bytes
			// s.stats.AddBytesRecv(uint64(len(data)))
		}
	}
}

// createSession establishes a new UDP session
func (s *RawUDPServer) createSession(clientAddr *net.UDPAddr) (*UDPSession, error) {
	clientIP := clientAddr.IP.String()
	clientLocation := formatLocationTag(clientAddr.String())

	// Check firewall
	if s.config.Firewall != "" {
		firewallRule := GetFirewallRule(s.appConfig, s.config.Firewall)
		if firewallRule != nil {
			if !CheckFirewall(clientIP, firewallRule) {
				DebugLog("%s[RAW UDP] Packet from %s blocked by server firewall", clientLocation, clientIP)
				return nil, nil
			}
		}
	}

	// Find mapping
	mapping := s.findMapping()
	if mapping == nil {
		log.Printf("%s[RAW UDP] No mapping found for server '%s'", clientLocation, s.name)
		return nil, nil
	}

	// Check mapping firewall
	if mapping.Firewall != "" {
		firewallRule := GetFirewallRule(s.appConfig, mapping.Firewall)
		if firewallRule != nil {
			if !CheckFirewall(clientIP, firewallRule) {
				DebugLog("%s[RAW UDP] Packet from %s blocked by mapping firewall", clientLocation, clientIP)
				return nil, nil
			}
		}
	}

	log.Printf("%s[RAW UDP] New session from %s -> %s", clientLocation, clientAddr.String(), mapping.GetToURL())

	// Parse target
	toURL := mapping.GetToURL()
	targetHost, targetPort, err := parseUDPURL(toURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL %s: %v", toURL, err)
	}

	targetAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", targetHost, targetPort))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target %s:%d: %v", targetHost, targetPort, err)
	}

	// Dial target
	targetConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial target %s: %v", targetAddr, err)
	}

	session := &UDPSession{
		ClientAddr: clientAddr,
		TargetConn: targetConn,
		LastActive: time.Now(),
	}

	// Start reading from target
	go s.readFromTarget(session)

	return session, nil
}

// readFromTarget reads packets from the target and forwards them back to the client
func (s *RawUDPServer) readFromTarget(session *UDPSession) {
	buf := make([]byte, 65535)
	for {
		n, _, err := session.TargetConn.ReadFromUDP(buf)
		if err != nil {
			// Connection closed or error
			return
		}

		// Forward to client
		_, err = s.conn.WriteToUDP(buf[:n], session.ClientAddr)
		if err != nil {
			log.Printf("[RAW UDP] Failed to write back to client %s: %v", session.ClientAddr, err)
		} else {
			// Update activity
			session.mu.Lock()
			session.LastActive = time.Now()
			session.mu.Unlock()
			// Update stats
			// s.stats.AddBytesSent(uint64(n))
		}
	}
}

// cleanupLoop periodically removes idle sessions
func (s *RawUDPServer) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	timeout := 60 * time.Second // Idle timeout

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for key, session := range s.sessions {
				session.mu.Lock()
				if now.Sub(session.LastActive) > timeout {
					session.TargetConn.Close()
					delete(s.sessions, key)
					// log.Printf("[RAW UDP] Session %s timed out", key)
				}
				session.mu.Unlock()
			}
			s.mu.Unlock()
		}
	}
}

// findMapping finds a matching mapping for this UDP server
func (s *RawUDPServer) findMapping() *Mapping {
	// Similar to TCP, find mapping by server name or port
	for _, m := range s.mappings {
		for _, serverName := range m.serverNames {
			if serverName == s.name {
				fromURL := m.GetFromURL()
				if strings.HasPrefix(fromURL, "udp://") {
					return m
				}
			}
		}
	}

	serverPort := s.config.Port
	for _, m := range s.mappings {
		fromURL := m.GetFromURL()
		if !strings.HasPrefix(fromURL, "udp://") {
			continue
		}

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

		if mappingPort == serverPort {
			return m
		}
	}

	return nil
}

// parseUDPURL parses a udp:// URL
func parseUDPURL(rawURL string) (host string, port int, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", 0, err
	}

	if u.Scheme != "udp" {
		return "", 0, fmt.Errorf("unsupported scheme: %s, expected udp://", u.Scheme)
	}

	host = u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		return "", 0, fmt.Errorf("port is required in udp:// URL")
	}

	port, err = strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %s", portStr)
	}

	return host, port, nil
}
