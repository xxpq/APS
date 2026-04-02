package main

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// HybridTunnelManager 绠＄悊TCP闅ч亾鐨勭鐞嗗櫒
type HybridTunnelManager struct {
	mu             sync.RWMutex
	tcpManager     *TCPTunnelManager
	tcpServer      *TCPTunnelServer
	config         *Config
	statsCollector *StatsCollector
	statsDB        *StatsDB
}

// NewHybridTunnelManager creates a hybrid tunnel manager.
func NewHybridTunnelManager(config *Config, statsCollector *StatsCollector, statsDB *StatsDB) *HybridTunnelManager {
	htm := &HybridTunnelManager{
		config:         config,
		statsCollector: statsCollector,
		statsDB:        statsDB,
	}

	// Initialize TCP tunnel server and manager.
	htm.tcpServer = NewTCPTunnelServer(config, statsDB)
	htm.tcpManager = NewTCPTunnelManager(config, htm.tcpServer)

	return htm
}

// StartTCPServer 鍚姩TCP闅ч亾鏈嶅姟鍣紙鍙寚瀹氱鍙ｆ垨浣跨敤杩炴帴澶嶇敤鍣級
func (htm *HybridTunnelManager) StartTCPServer(addr string) error {
	if htm.tcpServer == nil {
		return errors.New("TCP tunnel server not initialized")
	}
	return htm.tcpServer.Start(addr)
}

// HandleTunnelConnection 澶勭悊鏉ヨ嚜杩炴帴澶嶇敤鍣ㄧ殑闅ч亾杩炴帴
func (htm *HybridTunnelManager) HandleTunnelConnection(conn net.Conn) {
	if htm.tcpServer != nil {
		htm.tcpServer.handleConnection(conn)
	}
}

// SetStatsCollector sets stats collector.
func (htm *HybridTunnelManager) SetStatsCollector(statsCollector *StatsCollector) {
	htm.mu.Lock()
	defer htm.mu.Unlock()
	htm.statsCollector = statsCollector
}

// UpdateTunnels updates tunnel config reference.
func (htm *HybridTunnelManager) UpdateTunnels(newConfig *Config) {
	htm.mu.Lock()
	defer htm.mu.Unlock()

	DebugLog("[TUNNEL] Updating tunnels...")
	htm.config = newConfig
}

// SendRequestStream sends a request and returns a stream for the response.
func (htm *HybridTunnelManager) SendRequestStream(ctx context.Context, tunnelName, endpointName string, reqPayload *RequestPayload) (io.ReadCloser, []byte, error) {
	if htm.tcpManager != nil {
		return htm.tcpManager.SendRequestStream(ctx, tunnelName, endpointName, reqPayload)
	}
	return nil, nil, errors.New("no available tunnel manager")
}

// SendProxyConnect establishes a TCP proxy connection through the tunnel.
func (htm *HybridTunnelManager) SendProxyConnect(ctx context.Context, tunnelName, endpointName string, host string, port int, useTLS bool, clientConn net.Conn, clientIP string) (<-chan struct{}, error) {
	if htm.tcpManager != nil {
		return htm.tcpManager.SendProxyConnect(ctx, tunnelName, endpointName, host, port, useTLS, clientConn, clientIP)
	}
	return nil, errors.New("no available tunnel manager for proxy connection")
}

// GetRandomEndpointFromTunnels 浠庨毀閬撲腑鑾峰彇闅忔満绔偣
func (htm *HybridTunnelManager) GetRandomEndpointFromTunnels(tunnelNames []string) (string, string, error) {
	if htm.tcpManager != nil {
		return htm.tcpManager.GetRandomEndpointFromTunnels(tunnelNames)
	}
	return "", "", errors.New("no available endpoints found")
}

// FindTunnelForEndpoint 鏌ユ壘绔偣鎵€鍦ㄧ殑闅ч亾
func (htm *HybridTunnelManager) FindTunnelForEndpoint(endpointName string) (string, bool) {
	if htm.tcpManager != nil {
		return htm.tcpManager.FindTunnelForEndpoint(endpointName)
	}
	return "", false
}

// GetEndpointsInfo 鑾峰彇绔偣淇℃伅
func (htm *HybridTunnelManager) GetEndpointsInfo(tunnelName string, stats *StatsCollector) map[string]*EndpointInfo {
	if htm.tcpManager == nil {
		return nil
	}

	// Get endpoint info with per-endpoint statistics from TCP manager
	info := htm.tcpManager.GetEndpointsInfo(tunnelName, stats)
	return info
}

// MeasureEndpointLatency 娴嬮噺绔偣寤惰繜
func (htm *HybridTunnelManager) MeasureEndpointLatency(tunnelName, endpointName string) (time.Duration, error) {
	if htm.tcpManager == nil {
		return 0, errors.New("TCP tunnel manager not initialized")
	}
	return htm.tcpManager.MeasureEndpointLatency(tunnelName, endpointName)
}

// GetPoolStats returns tunnel manager pool stats.
func (htm *HybridTunnelManager) GetPoolStats() map[string]interface{} {
	htm.mu.RLock()
	defer htm.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["protocol"] = "tcp"

	return stats
}

// Cleanup 娓呯悊璧勬簮
func (htm *HybridTunnelManager) Cleanup() {
	DebugLog("[TUNNEL] Cleaning up tunnel manager")

	if htm.tcpManager != nil {
		htm.tcpManager.Stop()
	}
}

// SendConfigUpdate sends a config update message to a connected endpoint
func (htm *HybridTunnelManager) SendConfigUpdate(tunnelName, endpointName string, payload []byte) error {
	if htm.tcpManager == nil {
		return errors.New("TCP tunnel manager not initialized")
	}
	return htm.tcpManager.SendConfigUpdate(tunnelName, endpointName, payload)
}

// GetAllOnlineEndpoints returns all online endpoints
func (htm *HybridTunnelManager) GetAllOnlineEndpoints() []EndpointInfo {
	if htm.tcpManager != nil {
		return htm.tcpManager.GetAllOnlineEndpoints()
	}
	return nil
}
