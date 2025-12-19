package main

import (
	"net"
	"testing"
	"time"
)

// MockConnection implements net.Conn for testing
type MockConnection struct {
	closed bool
}

func (m *MockConnection) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *MockConnection) Write(b []byte) (n int, err error)  { return 0, nil }
func (m *MockConnection) Close() error                       { m.closed = true; return nil }
func (m *MockConnection) LocalAddr() net.Addr                { return nil }
func (m *MockConnection) RemoteAddr() net.Addr               { return nil }
func (m *MockConnection) SetDeadline(t time.Time) error      { return nil }
func (m *MockConnection) SetReadDeadline(t time.Time) error  { return nil }
func (m *MockConnection) SetWriteDeadline(t time.Time) error { return nil }

func TestIPRateLimiter(t *testing.T) {
	limiter := NewIPRateLimiter()
	ip := "192.168.1.100"

	// Test 1: Under limit
	for i := 0; i < 500; i++ {
		allowed, banned := limiter.CheckAndIncrement(ip)
		if !allowed || banned {
			t.Fatalf("Request %d should be allowed", i)
		}
	}

	// Test 2: Exceed limit -> Ban
	allowed, banned := limiter.CheckAndIncrement(ip)
	if allowed {
		t.Fatal("Request 501 should be denied")
	}
	if !banned {
		t.Fatal("Should return banned=true")
	}
	if !limiter.IsBanned(ip) {
		t.Fatal("IP should be banned after exceeding limit")
	}

	// Test 3: Connection Termination
	limiter = NewIPRateLimiter() // Reset
	conn1 := &MockConnection{}
	conn2 := &MockConnection{}

	limiter.RegisterConnection(ip, conn1)
	limiter.RegisterConnection(ip, conn2)

	limiter.BanIP(ip)

	if !conn1.closed || !conn2.closed {
		t.Fatal("Active connections should be closed upon ban")
	}
	if !limiter.IsBanned(ip) {
		t.Fatal("IP should be banned")
	}
}
