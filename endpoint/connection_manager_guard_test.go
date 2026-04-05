package main

import (
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func resetInboundGuardForTest(t *testing.T) {
	t.Helper()
	cachePath := filepath.Join(t.TempDir(), "session_cache.json")
	endpointInboundGuard.mu.Lock()
	endpointInboundGuard.loaded = true
	endpointInboundGuard.cachePath = cachePath
	endpointInboundGuard.sessions = make(map[string]inboundConnectionSession)
	endpointInboundGuard.history = nil
	endpointInboundGuard.ipState = make(map[string]*inboundIPState)
	endpointInboundGuard.mu.Unlock()
}

func TestInboundConnectionGuardAcquireMarkRelease(t *testing.T) {
	resetInboundGuardForTest(t)

	remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 50000}
	session, err := acquireInboundConnectionSession(remote)
	if err != nil {
		t.Fatalf("acquireInboundConnectionSession failed: %v", err)
	}
	if session.SessionID == "" {
		t.Fatal("session id should not be empty")
	}
	if inboundConnectionSessionCountByIP("203.0.113.10") != 1 {
		t.Fatal("expected one active inbound session")
	}

	markInboundConnectionTLSEstablished(session.SessionID)
	releaseInboundConnectionSession(session.SessionID, true)

	if inboundConnectionSessionCountByIP("203.0.113.10") != 0 {
		t.Fatal("expected zero active inbound sessions after release")
	}
}

func TestInboundConnectionGuardRateLimitPerIP(t *testing.T) {
	resetInboundGuardForTest(t)

	remote := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 41000}
	for i := 0; i < endpointInboundMaxPerIPPerWindow; i++ {
		session, err := acquireInboundConnectionSession(remote)
		if err != nil {
			t.Fatalf("acquire attempt %d failed early: %v", i, err)
		}
		releaseInboundConnectionSession(session.SessionID, true)
	}

	_, err := acquireInboundConnectionSession(remote)
	if !errors.Is(err, errInboundSessionRateLimited) {
		t.Fatalf("expected errInboundSessionRateLimited, got %v", err)
	}
}

func TestInboundConnectionGuardCooldownAfterAuthFailure(t *testing.T) {
	resetInboundGuardForTest(t)

	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.44"), Port: 42000}
	session, err := acquireInboundConnectionSession(remote)
	if err != nil {
		t.Fatalf("acquire failed: %v", err)
	}
	releaseInboundConnectionSession(session.SessionID, false)

	_, err = acquireInboundConnectionSession(remote)
	if !errors.Is(err, errInboundSessionBlocked) {
		t.Fatalf("expected errInboundSessionBlocked during cooldown, got %v", err)
	}

	time.Sleep(endpointInboundAuthCooldown + 50*time.Millisecond)
	recovered, err := acquireInboundConnectionSession(remote)
	if err != nil {
		t.Fatalf("acquire after cooldown failed: %v", err)
	}
	releaseInboundConnectionSession(recovered.SessionID, true)
}
