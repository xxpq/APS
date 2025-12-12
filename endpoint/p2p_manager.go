package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// P2PConnectionType represents the type of P2P connection
type P2PConnectionType int

const (
	ConnectionTypeNone P2PConnectionType = iota
	ConnectionTypeP2P                    // Direct P2P hole-punched connection
	ConnectionTypePE2P                   // Peer-enhanced P2P (via another endpoint)
	ConnectionTypeP2SP                   // Peer to server to peer (via APS)
)

func (t P2PConnectionType) String() string {
	switch t {
	case ConnectionTypeP2P:
		return "P2P"
	case ConnectionTypePE2P:
		return "PE2P"
	case ConnectionTypeP2SP:
		return "P2SP"
	default:
		return "None"
	}
}

// P2PConnection represents an active P2P connection to another endpoint
type P2PConnection struct {
	TargetEndpoint string
	ConnectionType P2PConnectionType
	Conn           net.Conn
	NATInfo        *NATInfo
	CreatedAt      time.Time
	LastActivity   time.Time
	mu             sync.Mutex
}

// P2PManager manages P2P connections with other endpoints
type P2PManager struct {
	stunClient   *STUNClient
	natInfo      *NATInfo
	connections  map[string]*P2PConnection // endpointName -> connection
	tunnelConn   *TunnelConn               // Connection to APS for fallback
	endpointName string
	tunnelName   string
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewP2PManager creates a new P2P manager
func NewP2PManager(stunServers []string, endpointName, tunnelName string) *P2PManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &P2PManager{
		stunClient:   NewSTUNClient(stunServers),
		connections:  make(map[string]*P2PConnection),
		endpointName: endpointName,
		tunnelName:   tunnelName,
		ctx:          ctx,
		cancel:       cancel,
	}
}

// SetTunnelConn sets the tunnel connection for P2SP fallback
func (pm *P2PManager) SetTunnelConn(tc *TunnelConn) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.tunnelConn = tc
}

// Start starts the P2P manager and performs initial STUN discovery
func (pm *P2PManager) Start() error {
	log.Println("[P2P] Starting P2P manager...")

	// Perform initial STUN discovery
	natInfo, err := pm.stunClient.Discover()
	if err != nil {
		log.Printf("[P2P] STUN discovery failed: %v (P2P may be limited)", err)
		// Continue without NAT info - will fall back to P2SP
	} else {
		pm.mu.Lock()
		pm.natInfo = natInfo
		pm.mu.Unlock()
		log.Printf("[P2P] NAT info: external=%s:%d, local=%s:%d",
			natInfo.ExternalIP, natInfo.ExternalPort,
			natInfo.LocalIP, natInfo.LocalPort)
	}

	return nil
}

// Stop stops the P2P manager
func (pm *P2PManager) Stop() {
	pm.cancel()

	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Close all P2P connections
	for _, conn := range pm.connections {
		conn.mu.Lock()
		if conn.Conn != nil {
			conn.Conn.Close()
		}
		conn.mu.Unlock()
	}
	pm.connections = make(map[string]*P2PConnection)

	log.Println("[P2P] P2P manager stopped")
}

// GetNATInfo returns the current NAT information
func (pm *P2PManager) GetNATInfo() *NATInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.natInfo
}

// RefreshNATInfo performs a new STUN discovery
func (pm *P2PManager) RefreshNATInfo() (*NATInfo, error) {
	natInfo, err := pm.stunClient.Discover()
	if err != nil {
		return nil, err
	}

	pm.mu.Lock()
	pm.natInfo = natInfo
	pm.mu.Unlock()

	return natInfo, nil
}

// GetConnection gets an existing P2P connection to an endpoint
func (pm *P2PManager) GetConnection(targetEndpoint string) (*P2PConnection, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	conn, ok := pm.connections[targetEndpoint]
	return conn, ok
}

// ConnectToPeer attempts to establish a P2P connection to another endpoint
// Returns the connection type achieved and any error
func (pm *P2PManager) ConnectToPeer(targetEndpoint string, targetNATInfo *NATInfo) (P2PConnectionType, error) {
	// Check if we already have a connection
	if conn, ok := pm.GetConnection(targetEndpoint); ok {
		return conn.ConnectionType, nil
	}

	// Try connection methods in order of preference: P2P > PE2P > P2SP

	// 1. Try direct P2P hole punching
	if pm.natInfo != nil && targetNATInfo != nil {
		log.Printf("[P2P] Attempting P2P hole punch to %s (%s:%d)",
			targetEndpoint, targetNATInfo.ExternalIP, targetNATInfo.ExternalPort)

		conn, err := pm.attemptHolePunch(targetNATInfo)
		if err == nil {
			pm.registerConnection(targetEndpoint, conn, ConnectionTypeP2P, targetNATInfo)
			return ConnectionTypeP2P, nil
		}
		log.Printf("[P2P] P2P hole punch failed: %v", err)
	}

	// 2. PE2P via another endpoint (future implementation)
	// For now, skip directly to P2SP

	// 3. Fall back to P2SP (via APS tunnel)
	log.Printf("[P2P] Falling back to P2SP for %s", targetEndpoint)
	pm.registerConnection(targetEndpoint, nil, ConnectionTypeP2SP, targetNATInfo)
	return ConnectionTypeP2SP, nil
}

// attemptHolePunch attempts UDP hole punching to the target
func (pm *P2PManager) attemptHolePunch(targetNATInfo *NATInfo) (net.Conn, error) {
	// Create UDP socket
	localAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	conn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP socket: %w", err)
	}

	// Target address
	targetAddr := &net.UDPAddr{
		IP:   net.ParseIP(targetNATInfo.ExternalIP),
		Port: targetNATInfo.ExternalPort,
	}

	// Send punch packets
	punch := []byte("PUNCH")
	for i := 0; i < 5; i++ {
		_, err := conn.WriteToUDP(punch, targetAddr)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to send punch packet: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Wait for response with timeout
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, remoteAddr, err := conn.ReadFromUDP(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("no response: %w", err)
	}

	log.Printf("[P2P] Hole punch successful! Received %d bytes from %s", n, remoteAddr)

	// Reset deadline and return the connected socket
	conn.SetReadDeadline(time.Time{})

	// Convert to net.Conn
	return &udpConnWrapper{
		UDPConn:    conn,
		remoteAddr: remoteAddr,
	}, nil
}

// registerConnection registers a new P2P connection
func (pm *P2PManager) registerConnection(targetEndpoint string, conn net.Conn, connType P2PConnectionType, natInfo *NATInfo) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.connections[targetEndpoint] = &P2PConnection{
		TargetEndpoint: targetEndpoint,
		ConnectionType: connType,
		Conn:           conn,
		NATInfo:        natInfo,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
	}

	log.Printf("[P2P] Registered %s connection to %s", connType, targetEndpoint)
}

// CloseConnection closes a P2P connection
func (pm *P2PManager) CloseConnection(targetEndpoint string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if conn, ok := pm.connections[targetEndpoint]; ok {
		conn.mu.Lock()
		if conn.Conn != nil {
			conn.Conn.Close()
		}
		conn.mu.Unlock()
		delete(pm.connections, targetEndpoint)
		log.Printf("[P2P] Closed connection to %s", targetEndpoint)
	}
}

// udpConnWrapper wraps UDPConn to implement net.Conn for a specific remote address
type udpConnWrapper struct {
	*net.UDPConn
	remoteAddr *net.UDPAddr
}

func (w *udpConnWrapper) Read(b []byte) (int, error) {
	n, addr, err := w.UDPConn.ReadFromUDP(b)
	if err != nil {
		return n, err
	}
	// Only accept packets from the expected remote address
	if addr.String() != w.remoteAddr.String() {
		return 0, nil // Ignore packets from other addresses
	}
	return n, nil
}

func (w *udpConnWrapper) Write(b []byte) (int, error) {
	return w.UDPConn.WriteToUDP(b, w.remoteAddr)
}

func (w *udpConnWrapper) RemoteAddr() net.Addr {
	return w.remoteAddr
}
