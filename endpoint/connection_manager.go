package main

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
)

// ServerConfig represents a single server connection configuration
type ServerConfig struct {
	Address    string
	ConfigID   string // empty means use global -cid
	IsSeed     bool   // true if from -server flag (infinite retry)
	RetryCount int    // current retry count (max 5 for dynamic)
}

// ConnectionManager manages multiple APS server connections
type ConnectionManager struct {
	servers   map[string]*ServerConfig      // address -> config
	active    map[string]context.CancelFunc // address -> cancel function
	mu        sync.RWMutex
	globalCID string // global config ID from -cid flag
}

// NewConnectionManager creates a new connection manager
func NewConnectionManager(globalCID string) *ConnectionManager {
	return &ConnectionManager{
		servers:   make(map[string]*ServerConfig),
		active:    make(map[string]context.CancelFunc),
		globalCID: globalCID,
	}
}

// ParseServerAddress parses address in format "addr:port" or "cid@addr:port"
func (cm *ConnectionManager) ParseServerAddress(addr string, isSeed bool) *ServerConfig {
	addr = strings.TrimSpace(addr)

	var configID string
	var address string

	if strings.Contains(addr, "@") {
		parts := strings.SplitN(addr, "@", 2)
		configID = parts[0]
		address = parts[1]
	} else {
		configID = cm.globalCID
		address = addr
	}

	// Check if address has port, default to 80 if missing
	if _, _, err := net.SplitHostPort(address); err != nil {
		if strings.Contains(err.Error(), "missing port") {
			address = address + ":80"
		} else if strings.Contains(err.Error(), "too many colons") {
			// Likely IPv6 literal without brackets/port, e.g. ::1
			address = net.JoinHostPort(address, "80")
		}
	}

	return &ServerConfig{
		Address:    address,
		ConfigID:   configID,
		IsSeed:     isSeed,
		RetryCount: 0,
	}
}

// AddSeedServer adds a seed server (from -server flag)
func (cm *ConnectionManager) AddSeedServer(cfg *ServerConfig) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cfg.IsSeed = true
	cfg.RetryCount = 0
	cm.servers[cfg.Address] = cfg
	log.Printf("[CONN-MGR] Added seed server: %s (cid: %s)", cfg.Address, cfg.ConfigID)
}

// AddDynamicServer adds a dynamic server (from mirror update)
func (cm *ConnectionManager) AddDynamicServer(cfg *ServerConfig) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Don't add if already exists
	if _, exists := cm.servers[cfg.Address]; exists {
		return false
	}

	cfg.IsSeed = false
	cfg.RetryCount = 0
	cm.servers[cfg.Address] = cfg
	log.Printf("[CONN-MGR] Added dynamic server: %s (cid: %s)", cfg.Address, cfg.ConfigID)
	return true
}

// HasConnection checks if a connection to this address exists
func (cm *ConnectionManager) HasConnection(address string) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	_, exists := cm.servers[address]
	return exists
}

// ShouldRetry checks if we should retry connecting to this server
func (cm *ConnectionManager) ShouldRetry(address string) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	cfg, exists := cm.servers[address]
	if !exists {
		return false
	}

	// Seed servers always retry
	if cfg.IsSeed {
		return true
	}

	// Dynamic servers retry max 5 times
	return cfg.RetryCount < 5
}

// IncrementRetry increments the retry counter for a server
func (cm *ConnectionManager) IncrementRetry(address string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cfg, exists := cm.servers[address]; exists {
		cfg.RetryCount++
		if !cfg.IsSeed && cfg.RetryCount >= 5 {
			log.Printf("[CONN-MGR] Dynamic server %s reached max retries (5), will be removed", address)
		}
	}
}

// RemoveServer removes a server (for dynamic servers that exceeded retry limit)
func (cm *ConnectionManager) RemoveServer(address string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cfg, exists := cm.servers[address]; exists {
		if !cfg.IsSeed {
			delete(cm.servers, address)
			log.Printf("[CONN-MGR] Removed dynamic server: %s", address)
		}
	}
}

// SetActive marks a connection as active with its cancel function
func (cm *ConnectionManager) SetActive(address string, cancel context.CancelFunc) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.active[address] = cancel
}

// CloseConnection closes an active connection
func (cm *ConnectionManager) CloseConnection(address string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cancel, exists := cm.active[address]; exists {
		cancel()
		delete(cm.active, address)
	}
}

// GetServerConfig returns the configuration for a server
func (cm *ConnectionManager) GetServerConfig(address string) *ServerConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.servers[address]
}

// GetAllServers returns all server addresses
func (cm *ConnectionManager) GetAllServers() []string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	addrs := make([]string, 0, len(cm.servers))
	for addr := range cm.servers {
		addrs = append(addrs, addr)
	}
	return addrs
}

// CloseAll closes all active connections
func (cm *ConnectionManager) CloseAll() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for addr, cancel := range cm.active {
		cancel()
		log.Printf("[CONN-MGR] Closed connection to %s", addr)
	}
	cm.active = make(map[string]context.CancelFunc)
}
