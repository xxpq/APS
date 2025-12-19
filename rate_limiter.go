package main

import (
	"net"
	"sync"
	"time"
)

const (
	maxRequestsPerMinute = 500
	banDuration          = 30 * time.Minute
	cleanupInterval      = 1 * time.Minute
)

// RequestTracker tracks request count in a sliding window
type RequestTracker struct {
	count       int
	windowStart time.Time
}

// IPRateLimiter manages rate limiting and banning for IPs
type IPRateLimiter struct {
	requests map[string]*RequestTracker // IP -> request tracker
	banned   map[string]time.Time       // IP -> ban expiry time
	conns    map[string][]net.Conn      // IP -> active connections
	mu       sync.RWMutex
}

// NewIPRateLimiter creates a new rate limiter
func NewIPRateLimiter() *IPRateLimiter {
	return &IPRateLimiter{
		requests: make(map[string]*RequestTracker),
		banned:   make(map[string]time.Time),
		conns:    make(map[string][]net.Conn),
	}
}

// IsBanned checks if an IP is currently banned
func (r *IPRateLimiter) IsBanned(ip string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if banExpiry, exists := r.banned[ip]; exists {
		if time.Now().Before(banExpiry) {
			return true
		}
		// Ban expired, will be cleaned up later
	}
	return false
}

// CheckAndIncrement checks rate limit and increments counter
// Returns (allowed, banned) where:
//   - allowed: true if request is allowed
//   - banned: true if IP is currently banned
func (r *IPRateLimiter) CheckAndIncrement(ip string) (allowed bool, banned bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()

	// Check if banned
	if banExpiry, exists := r.banned[ip]; exists {
		if now.Before(banExpiry) {
			return false, true
		}
		// Ban expired, remove it
		delete(r.banned, ip)
	}

	// Get or create tracker
	tracker, exists := r.requests[ip]
	if !exists {
		tracker = &RequestTracker{
			count:       0,
			windowStart: now,
		}
		r.requests[ip] = tracker
	}

	// Check if window expired (1 minute)
	if now.Sub(tracker.windowStart) > time.Minute {
		// Reset window
		tracker.count = 0
		tracker.windowStart = now
	}

	// Increment counter
	tracker.count++

	// Check if limit exceeded
	if tracker.count > maxRequestsPerMinute {
		// Ban this IP
		r.banIPLocked(ip, now)
		return false, true // Not allowed, and now banned
	}

	return true, false
}

// BanIP bans an IP for the configured duration and terminates all connections
func (r *IPRateLimiter) BanIP(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.banIPLocked(ip, time.Now())
}

// banIPLocked internal method that must be called with lock held
func (r *IPRateLimiter) banIPLocked(ip string, now time.Time) {
	// Set ban expiry
	r.banned[ip] = now.Add(banDuration)

	// Close all active connections for this IP
	if conns, exists := r.conns[ip]; exists {
		for _, conn := range conns {
			if conn != nil {
				conn.Close()
			}
		}
		// Clear connection list
		delete(r.conns, ip)
	}

	DebugLog("[RATE LIMIT] IP %s banned for %v (exceeded %d requests/minute)",
		ip, banDuration, maxRequestsPerMinute)
}

// RegisterConnection tracks an active connection for an IP
func (r *IPRateLimiter) RegisterConnection(ip string, conn net.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.conns[ip] = append(r.conns[ip], conn)
}

// UnregisterConnection removes a connection from tracking
func (r *IPRateLimiter) UnregisterConnection(ip string, conn net.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()

	conns, exists := r.conns[ip]
	if !exists {
		return
	}

	// Find and remove the connection
	for i, c := range conns {
		if c == conn {
			// Remove from slice
			r.conns[ip] = append(conns[:i], conns[i+1:]...)
			break
		}
	}

	// Clean up empty slices
	if len(r.conns[ip]) == 0 {
		delete(r.conns, ip)
	}
}

// CleanupExpired removes expired bans and old request trackers
// Should be run in a background goroutine
func (r *IPRateLimiter) CleanupExpired() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		r.mu.Lock()

		now := time.Now()

		// Clean up expired bans
		for ip, expiry := range r.banned {
			if now.After(expiry) {
				delete(r.banned, ip)
				DebugLog("[RATE LIMIT] Ban expired for IP %s", ip)
			}
		}

		// Clean up old request trackers (older than 2 minutes)
		for ip, tracker := range r.requests {
			if now.Sub(tracker.windowStart) > 2*time.Minute {
				delete(r.requests, ip)
			}
		}

		r.mu.Unlock()
	}
}

// GetStats returns current rate limiter statistics
func (r *IPRateLimiter) GetStats() (activeTrackers, bannedIPs, activeConns int) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.requests), len(r.banned), len(r.conns)
}
