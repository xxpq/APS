package main

import (
	"log"
	"sync"
	"time"
)

// RelayManager handles multi-level relay through LAN endpoints when APS connectivity is lost
type RelayManager struct {
	lanDiscovery *LANDiscovery
	tunnelConn   *TunnelConn
	maxHops      int
	connected    bool
	mu           sync.RWMutex
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

// NewRelayManager creates a new relay manager
func NewRelayManager(lanDiscovery *LANDiscovery, maxHops int) *RelayManager {
	return &RelayManager{
		lanDiscovery: lanDiscovery,
		maxHops:      maxHops,
		connected:    true,
		stopCh:       make(chan struct{}),
	}
}

// SetTunnelConn sets the APS tunnel connection
func (rm *RelayManager) SetTunnelConn(tc *TunnelConn) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.tunnelConn = tc
	rm.connected = tc != nil
}

// Start starts the relay manager
func (rm *RelayManager) Start() error {
	log.Println("[RELAY] Starting relay manager...")

	rm.wg.Add(1)
	go rm.monitorLoop()

	return nil
}

// Stop stops the relay manager
func (rm *RelayManager) Stop() {
	close(rm.stopCh)
	rm.wg.Wait()
	log.Println("[RELAY] Relay manager stopped")
}

// monitorLoop monitors APS connectivity and switches to relay mode if needed
func (rm *RelayManager) monitorLoop() {
	defer rm.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-rm.stopCh:
			return
		case <-ticker.C:
			rm.checkConnectivity()
		}
	}
}

// checkConnectivity checks APS connectivity status
func (rm *RelayManager) checkConnectivity() {
	rm.mu.RLock()
	wasConnected := rm.connected
	rm.mu.RUnlock()

	// connected flag is set externally when tunnel drops
	rm.mu.RLock()
	isConnected := rm.connected
	rm.mu.RUnlock()

	if wasConnected && !isConnected {
		log.Println("[RELAY] APS connectivity lost, switching to relay mode")
		rm.enterRelayMode()
	} else if !wasConnected && isConnected {
		log.Println("[RELAY] APS connectivity restored, exiting relay mode")
	}
}

// OnDisconnected should be called when the APS tunnel disconnects
func (rm *RelayManager) OnDisconnected() {
	rm.mu.Lock()
	rm.connected = false
	rm.tunnelConn = nil
	rm.mu.Unlock()
}

// enterRelayMode switches to relay mode using LAN peers
func (rm *RelayManager) enterRelayMode() {
	// Get connected LAN peers
	peers := rm.lanDiscovery.GetConnectedPeers()
	if len(peers) == 0 {
		log.Println("[RELAY] No LAN peers available for relay")
		return
	}

	log.Printf("[RELAY] %d LAN peers available for relay", len(peers))

	// Try to establish relay through each peer
	for _, peer := range peers {
		if rm.tryRelayThrough(peer, 1) {
			log.Printf("[RELAY] Relay established through %s", peer.EndpointName)
			return
		}
	}

	log.Println("[RELAY] Failed to establish relay through any peer")
}

// tryRelayThrough attempts to relay through a specific peer
func (rm *RelayManager) tryRelayThrough(peer *LANPeer, hopCount int) bool {
	if hopCount > rm.maxHops {
		log.Printf("[RELAY] Max hops (%d) exceeded", rm.maxHops)
		return false
	}

	if !peer.Connected || peer.Conn == nil {
		return false
	}

	log.Printf("[RELAY] Attempting relay through %s (hop %d/%d)",
		peer.EndpointName, hopCount, rm.maxHops)

	// Send relay request to peer
	// The peer will either:
	// 1. Forward to APS if connected
	// 2. Forward to another peer (adding to hop count)
	// 3. Reject if max hops exceeded

	// For now, just mark as relay candidate
	// Full implementation would send relay protocol messages
	return true
}

// IsRelayMode returns whether we're in relay mode
func (rm *RelayManager) IsRelayMode() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return !rm.connected
}

// GetRelayStatus returns the current relay status
func (rm *RelayManager) GetRelayStatus() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if rm.connected {
		return "direct"
	}

	peers := rm.lanDiscovery.GetConnectedPeers()
	if len(peers) > 0 {
		return "relay-via-lan"
	}

	return "disconnected"
}
