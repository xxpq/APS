package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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

const (
	endpointInboundRateWindow           = time.Minute
	endpointInboundMaxPerIPPerWindow    = 60
	endpointInboundMaxConcurrentPerIP   = 16
	endpointInboundMaxPendingTLSPerIP   = 8
	endpointInboundAuthCooldown         = 500 * time.Millisecond
	endpointInboundSessionCacheMaxItems = 4096
	endpointInboundSessionCacheTTL      = 24 * time.Hour
	endpointInboundSessionCacheEnv      = "APS_ENDPOINT_SESSION_CACHE_FILE"
)

var (
	errInboundSessionRateLimited = errors.New("inbound connection rate limited")
	errInboundSessionBlocked     = errors.New("inbound connection temporarily blocked")
)

type inboundConnectionSession struct {
	SessionID       string
	RemoteIP        string
	RemoteAddr      string
	OpenedAt        time.Time
	LastSeenAt      time.Time
	TLSEstablished  bool
	RateLimitExempt bool
}

type inboundConnectionRecord struct {
	SessionID      string `json:"session_id"`
	RemoteIP       string `json:"remote_ip"`
	RemoteAddr     string `json:"remote_addr"`
	OpenedAt       int64  `json:"opened_at"`
	ClosedAt       int64  `json:"closed_at"`
	TLSEstablished bool   `json:"tls_established"`
	Authenticated  bool   `json:"authenticated"`
}

type inboundConnectionCache struct {
	Version int                       `json:"version"`
	SavedAt int64                     `json:"saved_at"`
	History []inboundConnectionRecord `json:"history,omitempty"`
}

type inboundIPState struct {
	Attempts     []time.Time
	Active       int
	PendingTLS   int
	BlockedUntil time.Time
}

type inboundConnectionGuard struct {
	mu        sync.Mutex
	loaded    bool
	cachePath string
	sessions  map[string]inboundConnectionSession
	history   []inboundConnectionRecord
	ipState   map[string]*inboundIPState
}

var endpointInboundGuard = &inboundConnectionGuard{
	cachePath: resolveInboundSessionCachePath(),
	sessions:  make(map[string]inboundConnectionSession),
	history:   make([]inboundConnectionRecord, 0, 256),
	ipState:   make(map[string]*inboundIPState),
}

var endpointInboundSessionSeq uint64

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

	// Check if address has port, default to 443 for secure tunnel transport
	if _, _, err := net.SplitHostPort(address); err != nil {
		if strings.Contains(err.Error(), "missing port") {
			address = address + ":443"
		} else if strings.Contains(err.Error(), "too many colons") {
			// Likely IPv6 literal without brackets/port, e.g. ::1
			address = net.JoinHostPort(address, "443")
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
	DebugLog("[CONN-MGR] Added seed server: %s (cid: %s)", cfg.Address, cfg.ConfigID)
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
	DebugLog("[CONN-MGR] Added dynamic server: %s (cid: %s)", cfg.Address, cfg.ConfigID)
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
			DebugLog("[CONN-MGR] Removed dynamic server: %s", address)
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
		DebugLog("[CONN-MGR] Closed connection to %s", addr)
	}
	cm.active = make(map[string]context.CancelFunc)
}

func acquireInboundConnectionSession(remoteAddr net.Addr) (inboundConnectionSession, error) {
	return endpointInboundGuard.acquire(remoteAddr, false)
}

func acquireInboundConnectionSessionWithExemption(remoteAddr net.Addr, exempt bool) (inboundConnectionSession, error) {
	return endpointInboundGuard.acquire(remoteAddr, exempt)
}

func markInboundConnectionTLSEstablished(sessionID string) {
	endpointInboundGuard.markTLS(sessionID)
}

func releaseInboundConnectionSession(sessionID string, authenticated bool) {
	endpointInboundGuard.release(sessionID, authenticated)
}

func inboundConnectionSessionCountByIP(ip string) int {
	return endpointInboundGuard.activeSessionsByIP(ip)
}

func resolveInboundSessionCachePath() string {
	if path := strings.TrimSpace(os.Getenv(endpointInboundSessionCacheEnv)); path != "" {
		return path
	}
	return filepath.Join(".cache", "endpoint_inbound_session_cache.json")
}

func parseRemoteIP(remoteAddr net.Addr) string {
	if remoteAddr == nil {
		return ""
	}
	raw := strings.TrimSpace(remoteAddr.String())
	if raw == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(raw)
	if err != nil {
		host = raw
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

func generateInboundSessionID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err == nil {
		return hex.EncodeToString(buf)
	}
	seq := atomic.AddUint64(&endpointInboundSessionSeq, 1)
	return strconv.FormatInt(time.Now().UTC().UnixNano(), 16) + "-" + strconv.FormatUint(seq, 16)
}

func (g *inboundConnectionGuard) acquire(remoteAddr net.Addr, rateLimitExempt bool) (inboundConnectionSession, error) {
	ip := parseRemoteIP(remoteAddr)
	if ip == "" {
		return inboundConnectionSession{}, errors.New("missing remote ip")
	}

	now := time.Now().UTC()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.loadCacheLocked()

	state := g.ensureIPStateLocked(ip)
	g.pruneIPStateLocked(state, now)

	if !rateLimitExempt {
		if !state.BlockedUntil.IsZero() && now.Before(state.BlockedUntil) {
			return inboundConnectionSession{}, errInboundSessionBlocked
		}
		if len(state.Attempts) >= endpointInboundMaxPerIPPerWindow {
			state.BlockedUntil = now.Add(endpointInboundAuthCooldown)
			return inboundConnectionSession{}, errInboundSessionRateLimited
		}
		if state.Active >= endpointInboundMaxConcurrentPerIP {
			return inboundConnectionSession{}, errInboundSessionRateLimited
		}
		if state.PendingTLS >= endpointInboundMaxPendingTLSPerIP {
			return inboundConnectionSession{}, errInboundSessionRateLimited
		}
	}

	sessionID := generateInboundSessionID()
	session := inboundConnectionSession{
		SessionID:       sessionID,
		RemoteIP:        ip,
		RemoteAddr:      strings.TrimSpace(remoteAddr.String()),
		OpenedAt:        now,
		LastSeenAt:      now,
		RateLimitExempt: rateLimitExempt,
	}

	if !rateLimitExempt {
		state.Attempts = append(state.Attempts, now)
	}
	state.Active++
	state.PendingTLS++
	g.sessions[sessionID] = session
	return session, nil
}

func (g *inboundConnectionGuard) markTLS(sessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return
	}
	now := time.Now().UTC()

	g.mu.Lock()
	defer g.mu.Unlock()
	session, exists := g.sessions[sessionID]
	if !exists {
		return
	}
	session.LastSeenAt = now
	if !session.TLSEstablished {
		session.TLSEstablished = true
		if state, ok := g.ipState[session.RemoteIP]; ok && state.PendingTLS > 0 {
			state.PendingTLS--
		}
	}
	g.sessions[sessionID] = session
}

func (g *inboundConnectionGuard) release(sessionID string, authenticated bool) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return
	}
	now := time.Now().UTC()

	g.mu.Lock()
	defer g.mu.Unlock()
	g.loadCacheLocked()

	session, exists := g.sessions[sessionID]
	if !exists {
		return
	}
	delete(g.sessions, sessionID)

	state := g.ensureIPStateLocked(session.RemoteIP)
	g.pruneIPStateLocked(state, now)
	if state.Active > 0 {
		state.Active--
	}
	if !session.TLSEstablished && state.PendingTLS > 0 {
		state.PendingTLS--
	}
	if !authenticated {
		state.BlockedUntil = now.Add(endpointInboundAuthCooldown)
	}

	g.history = append(g.history, inboundConnectionRecord{
		SessionID:      session.SessionID,
		RemoteIP:       session.RemoteIP,
		RemoteAddr:     session.RemoteAddr,
		OpenedAt:       session.OpenedAt.Unix(),
		ClosedAt:       now.Unix(),
		TLSEstablished: session.TLSEstablished,
		Authenticated:  authenticated,
	})
	g.pruneHistoryLocked(now)
	g.persistCacheLocked()
}

func (g *inboundConnectionGuard) activeSessionsByIP(ip string) int {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	state := g.ipState[ip]
	if state == nil {
		return 0
	}
	return state.Active
}

func (g *inboundConnectionGuard) ensureIPStateLocked(ip string) *inboundIPState {
	state := g.ipState[ip]
	if state != nil {
		return state
	}
	state = &inboundIPState{}
	g.ipState[ip] = state
	return state
}

func (g *inboundConnectionGuard) pruneIPStateLocked(state *inboundIPState, now time.Time) {
	if state == nil {
		return
	}
	filtered := state.Attempts[:0]
	for _, attempt := range state.Attempts {
		if now.Sub(attempt) <= endpointInboundRateWindow {
			filtered = append(filtered, attempt)
		}
	}
	state.Attempts = filtered
	if !state.BlockedUntil.IsZero() && now.After(state.BlockedUntil) {
		state.BlockedUntil = time.Time{}
	}
}

func (g *inboundConnectionGuard) pruneHistoryLocked(now time.Time) {
	filtered := g.history[:0]
	for _, item := range g.history {
		closedAt := time.Unix(item.ClosedAt, 0)
		if now.Sub(closedAt) <= endpointInboundSessionCacheTTL {
			filtered = append(filtered, item)
		}
	}
	g.history = filtered
	if len(g.history) > endpointInboundSessionCacheMaxItems {
		g.history = g.history[len(g.history)-endpointInboundSessionCacheMaxItems:]
	}
}

func (g *inboundConnectionGuard) loadCacheLocked() {
	if g.loaded {
		return
	}
	g.loaded = true
	cachePath := strings.TrimSpace(g.cachePath)
	if cachePath == "" {
		return
	}
	data, err := os.ReadFile(cachePath)
	if err != nil || len(data) == 0 {
		return
	}
	var cache inboundConnectionCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return
	}
	now := time.Now().UTC()
	for _, item := range cache.History {
		closedAt := time.Unix(item.ClosedAt, 0)
		if now.Sub(closedAt) > endpointInboundSessionCacheTTL {
			continue
		}
		g.history = append(g.history, item)
		if item.RemoteIP == "" {
			continue
		}
		state := g.ensureIPStateLocked(item.RemoteIP)
		state.Attempts = append(state.Attempts, closedAt)
	}
	g.pruneHistoryLocked(now)
	for _, state := range g.ipState {
		g.pruneIPStateLocked(state, now)
	}
}

func (g *inboundConnectionGuard) persistCacheLocked() {
	cachePath := strings.TrimSpace(g.cachePath)
	if cachePath == "" {
		return
	}
	dir := filepath.Dir(cachePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return
		}
	}
	cache := inboundConnectionCache{
		Version: 1,
		SavedAt: time.Now().UTC().Unix(),
		History: append([]inboundConnectionRecord(nil), g.history...),
	}
	data, err := json.Marshal(cache)
	if err != nil {
		return
	}
	_ = os.WriteFile(cachePath, data, 0600)
}
