package main

import (
	"net"
	"sync"
	"testing"
)

// Mock connection to simulate client
type mockConn struct {
	net.Conn
	closed bool
	mu     sync.Mutex
}

func (m *mockConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP("192.168.1.100"),
		Port: 12345,
	}
}

func TestRawTCPServer_FirewallBlock(t *testing.T) {
	// Setup config with firewall rule
	appConfig := &Config{
		Firewalls: map[string]*FirewallRule{
			"block_rule": {
				Block: &FilterRules{
					Networks: []string{"192.168.1.100"},
				},
			},
		},
		mu: sync.RWMutex{},
	}
	// Parse the rule
	ParseFirewallRule(appConfig.Firewalls["block_rule"])

	serverConfig := &ListenConfig{
		Firewall: "block_rule",
		Port:     8080,
	}

	server := &RawTCPServer{
		name:      "test_server",
		config:    serverConfig,
		appConfig: appConfig,
		stats:     NewStatsCollector(appConfig),
	}

	// Add a mapping that would match if firewall didn't block
	server.mappings = []*Mapping{
		{
			serverNames: []string{"test_server"},
			From:        "tcp://:8080",
			To:          "tcp://127.0.0.1:9090",
		},
	}

	conn := &mockConn{}
	server.handleConnection(conn)

	conn.mu.Lock()
	closed := conn.closed
	conn.mu.Unlock()

	if !closed {
		t.Error("Connection should have been closed by firewall")
	}
}
