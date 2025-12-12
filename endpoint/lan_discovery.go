package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

const (
	lanDiscoveryPort        = 19823 // UDP port for LAN discovery broadcast
	lanBroadcastAddr        = "255.255.255.255:19823"
	discoveryInterval       = 30 * time.Second
	connectionRetryCount    = 5
	connectionRetryInterval = 10 * time.Second
)

// LANDiscoveryMessage is broadcast over UDP to discover other endpoints
type LANDiscoveryMessage struct {
	Type         string `json:"type"` // "announce" or "respond"
	TunnelName   string `json:"tunnel_name"`
	EndpointName string `json:"endpoint_name"`
	ListenIP     string `json:"listen_ip"`
	ListenPort   int    `json:"listen_port"`
	Timestamp    int64  `json:"timestamp"`
}

// LANPeer represents a discovered LAN peer
type LANPeer struct {
	TunnelName   string
	EndpointName string
	IP           string
	Port         int
	LastSeen     time.Time
	Connected    bool
	Conn         net.Conn
}

// LANDiscovery handles LAN-based endpoint discovery and tunneling
type LANDiscovery struct {
	tunnelName   string
	endpointName string
	listenPort   int
	listener     net.Listener
	udpConn      *net.UDPConn
	peers        map[string]*LANPeer // key: "tunnelName/endpointName"
	tunnelConn   *TunnelConn         // Connection to APS
	mu           sync.RWMutex
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

// NewLANDiscovery creates a new LAN discovery instance
func NewLANDiscovery(tunnelName, endpointName string) *LANDiscovery {
	return &LANDiscovery{
		tunnelName:   tunnelName,
		endpointName: endpointName,
		peers:        make(map[string]*LANPeer),
		stopCh:       make(chan struct{}),
	}
}

// SetTunnelConn sets the APS tunnel connection
func (ld *LANDiscovery) SetTunnelConn(tc *TunnelConn) {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	ld.tunnelConn = tc
}

// Start starts LAN discovery and listening
func (ld *LANDiscovery) Start() error {
	// Start TCP listener on random port
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("failed to start TCP listener: %w", err)
	}
	ld.listener = listener
	ld.listenPort = listener.Addr().(*net.TCPAddr).Port
	log.Printf("[LAN] TCP listener started on port %d", ld.listenPort)

	// Start UDP listener for discovery
	udpAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("0.0.0.0:%d", lanDiscoveryPort))
	if err != nil {
		ld.listener.Close()
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	ld.udpConn, err = net.ListenUDP("udp4", udpAddr)
	if err != nil {
		// Port might be in use, try without specific port
		ld.udpConn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			ld.listener.Close()
			return fmt.Errorf("failed to start UDP listener: %w", err)
		}
		log.Printf("[LAN] UDP listener on dynamic port (broadcast limited)")
	} else {
		log.Printf("[LAN] UDP discovery listener on port %d", lanDiscoveryPort)
	}

	// Start goroutines
	ld.wg.Add(3)
	go ld.acceptLoop()
	go ld.discoveryListener()
	go ld.broadcastLoop()

	return nil
}

// Stop stops LAN discovery
func (ld *LANDiscovery) Stop() {
	close(ld.stopCh)

	if ld.listener != nil {
		ld.listener.Close()
	}
	if ld.udpConn != nil {
		ld.udpConn.Close()
	}

	// Close all peer connections
	ld.mu.Lock()
	for _, peer := range ld.peers {
		if peer.Conn != nil {
			peer.Conn.Close()
		}
	}
	ld.peers = make(map[string]*LANPeer)
	ld.mu.Unlock()

	ld.wg.Wait()
	log.Println("[LAN] LAN discovery stopped")
}

// acceptLoop accepts incoming TCP connections from LAN peers
func (ld *LANDiscovery) acceptLoop() {
	defer ld.wg.Done()

	for {
		select {
		case <-ld.stopCh:
			return
		default:
		}

		// Set accept deadline
		if tcpListener, ok := ld.listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := ld.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-ld.stopCh:
				return
			default:
				log.Printf("[LAN] Accept error: %v", err)
				continue
			}
		}

		go ld.handlePeerConnection(conn)
	}
}

// handlePeerConnection handles an incoming peer connection
func (ld *LANDiscovery) handlePeerConnection(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[LAN] Peer connection from %s", remoteAddr)

	// Read peer announcement
	decoder := json.NewDecoder(conn)
	var msg LANDiscoveryMessage
	if err := decoder.Decode(&msg); err != nil {
		log.Printf("[LAN] Failed to read peer announcement from %s: %v", remoteAddr, err)
		conn.Close()
		return
	}

	// Verify same tunnel
	if msg.TunnelName != ld.tunnelName {
		log.Printf("[LAN] Peer %s is in different tunnel: %s", msg.EndpointName, msg.TunnelName)
		conn.Close()
		return
	}

	// Register peer
	peerKey := fmt.Sprintf("%s/%s", msg.TunnelName, msg.EndpointName)
	ld.mu.Lock()
	ld.peers[peerKey] = &LANPeer{
		TunnelName:   msg.TunnelName,
		EndpointName: msg.EndpointName,
		IP:           msg.ListenIP,
		Port:         msg.ListenPort,
		LastSeen:     time.Now(),
		Connected:    true,
		Conn:         conn,
	}
	ld.mu.Unlock()

	log.Printf("[LAN] Peer registered: %s at %s:%d", msg.EndpointName, msg.ListenIP, msg.ListenPort)

	// Handle peer communication
	ld.peerCommLoop(conn, msg.EndpointName)
}

// peerCommLoop handles communication with a connected peer
func (ld *LANDiscovery) peerCommLoop(conn net.Conn, peerName string) {
	defer func() {
		peerKey := fmt.Sprintf("%s/%s", ld.tunnelName, peerName)
		ld.mu.Lock()
		if peer, ok := ld.peers[peerKey]; ok {
			peer.Connected = false
			peer.Conn = nil
		}
		ld.mu.Unlock()
		conn.Close()
		log.Printf("[LAN] Peer disconnected: %s", peerName)
	}()

	buf := make([]byte, 64*1024)
	for {
		select {
		case <-ld.stopCh:
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		// Handle peer message (future: relay data through peer)
		_ = n // Will be used for message handling
	}
}

// discoveryListener listens for UDP discovery broadcasts
func (ld *LANDiscovery) discoveryListener() {
	defer ld.wg.Done()

	buf := make([]byte, 4096)
	for {
		select {
		case <-ld.stopCh:
			return
		default:
		}

		ld.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := ld.udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-ld.stopCh:
				return
			default:
				continue
			}
		}

		var msg LANDiscoveryMessage
		if err := json.Unmarshal(buf[:n], &msg); err != nil {
			continue
		}

		// Ignore our own broadcasts
		if msg.EndpointName == ld.endpointName && msg.TunnelName == ld.tunnelName {
			continue
		}

		// Only process messages from same tunnel
		if msg.TunnelName != ld.tunnelName {
			continue
		}

		ld.handleDiscoveryMessage(&msg, remoteAddr)
	}
}

// handleDiscoveryMessage handles a received discovery message
func (ld *LANDiscovery) handleDiscoveryMessage(msg *LANDiscoveryMessage, remoteAddr *net.UDPAddr) {
	peerKey := fmt.Sprintf("%s/%s", msg.TunnelName, msg.EndpointName)

	ld.mu.Lock()
	peer, exists := ld.peers[peerKey]
	if !exists {
		peer = &LANPeer{
			TunnelName:   msg.TunnelName,
			EndpointName: msg.EndpointName,
			IP:           msg.ListenIP,
			Port:         msg.ListenPort,
			LastSeen:     time.Now(),
		}
		ld.peers[peerKey] = peer
		log.Printf("[LAN] Discovered peer: %s at %s:%d", msg.EndpointName, msg.ListenIP, msg.ListenPort)
	} else {
		peer.LastSeen = time.Now()
		peer.IP = msg.ListenIP
		peer.Port = msg.ListenPort
	}
	needConnect := !peer.Connected
	ld.mu.Unlock()

	// If announcement and not connected, respond and try to connect
	if msg.Type == "announce" {
		ld.sendResponse(remoteAddr)
		if needConnect {
			go ld.connectToPeer(peer)
		}
	}
}

// sendResponse sends a discovery response
func (ld *LANDiscovery) sendResponse(addr *net.UDPAddr) {
	msg := LANDiscoveryMessage{
		Type:         "respond",
		TunnelName:   ld.tunnelName,
		EndpointName: ld.endpointName,
		ListenIP:     getLocalIP(),
		ListenPort:   ld.listenPort,
		Timestamp:    time.Now().UnixNano(),
	}

	data, _ := json.Marshal(msg)
	ld.udpConn.WriteToUDP(data, addr)
}

// broadcastLoop periodically broadcasts discovery announcements
func (ld *LANDiscovery) broadcastLoop() {
	defer ld.wg.Done()

	ticker := time.NewTicker(discoveryInterval)
	defer ticker.Stop()

	// Initial broadcast
	ld.broadcast()

	for {
		select {
		case <-ld.stopCh:
			return
		case <-ticker.C:
			ld.broadcast()
		}
	}
}

// broadcast sends a discovery broadcast
func (ld *LANDiscovery) broadcast() {
	msg := LANDiscoveryMessage{
		Type:         "announce",
		TunnelName:   ld.tunnelName,
		EndpointName: ld.endpointName,
		ListenIP:     getLocalIP(),
		ListenPort:   ld.listenPort,
		Timestamp:    time.Now().UnixNano(),
	}

	data, _ := json.Marshal(msg)

	// Broadcast to 255.255.255.255
	broadcastAddr, err := net.ResolveUDPAddr("udp4", lanBroadcastAddr)
	if err != nil {
		return
	}

	conn, err := net.DialUDP("udp4", nil, broadcastAddr)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.Write(data)
}

// connectToPeer attempts to connect to a discovered peer
func (ld *LANDiscovery) connectToPeer(peer *LANPeer) {
	for i := 0; i < connectionRetryCount; i++ {
		addr := net.JoinHostPort(peer.IP, fmt.Sprintf("%d", peer.Port))
		log.Printf("[LAN] Connecting to peer %s at %s (attempt %d/%d)",
			peer.EndpointName, addr, i+1, connectionRetryCount)

		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			log.Printf("[LAN] Failed to connect to %s: %v", peer.EndpointName, err)
			time.Sleep(connectionRetryInterval)
			continue
		}

		// Send our announcement
		msg := LANDiscoveryMessage{
			Type:         "announce",
			TunnelName:   ld.tunnelName,
			EndpointName: ld.endpointName,
			ListenIP:     getLocalIP(),
			ListenPort:   ld.listenPort,
			Timestamp:    time.Now().UnixNano(),
		}
		encoder := json.NewEncoder(conn)
		if err := encoder.Encode(msg); err != nil {
			conn.Close()
			time.Sleep(connectionRetryInterval)
			continue
		}

		// Update peer
		peerKey := fmt.Sprintf("%s/%s", peer.TunnelName, peer.EndpointName)
		ld.mu.Lock()
		peer.Connected = true
		peer.Conn = conn
		ld.peers[peerKey] = peer
		ld.mu.Unlock()

		log.Printf("[LAN] Connected to peer %s", peer.EndpointName)
		ld.peerCommLoop(conn, peer.EndpointName)
		return
	}

	log.Printf("[LAN] Failed to connect to peer %s after %d attempts",
		peer.EndpointName, connectionRetryCount)
}

// GetConnectedPeers returns a list of connected peers
func (ld *LANDiscovery) GetConnectedPeers() []*LANPeer {
	ld.mu.RLock()
	defer ld.mu.RUnlock()

	var peers []*LANPeer
	for _, p := range ld.peers {
		if p.Connected {
			peers = append(peers, p)
		}
	}
	return peers
}

// GetListenerPort returns the TCP listener port used for peer connections
func (ld *LANDiscovery) GetListenerPort() int {
	ld.mu.RLock()
	defer ld.mu.RUnlock()
	return ld.listenPort
}

// getLocalIP returns the local IP address
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}
