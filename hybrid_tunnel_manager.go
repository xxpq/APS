package main

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// HybridTunnelManager 管理TCP隧道的管理器
type HybridTunnelManager struct {
	mu             sync.RWMutex
	tcpManager     *TCPTunnelManager
	tcpServer      *TCPTunnelServer
	config         *Config
	statsCollector *StatsCollector
}

// NewHybridTunnelManager 创建隧道管理器
func NewHybridTunnelManager(config *Config, statsCollector *StatsCollector) *HybridTunnelManager {
	htm := &HybridTunnelManager{
		config:         config,
		statsCollector: statsCollector,
	}

	// 初始化TCP隧道服务器和管理器
	htm.tcpServer = NewTCPTunnelServer(config)
	htm.tcpManager = NewTCPTunnelManager(config, htm.tcpServer)

	return htm
}

// StartTCPServer 启动TCP隧道服务器（可指定端口或使用连接复用器）
func (htm *HybridTunnelManager) StartTCPServer(addr string) error {
	if htm.tcpServer == nil {
		return errors.New("TCP tunnel server not initialized")
	}
	return htm.tcpServer.Start(addr)
}

// HandleTunnelConnection 处理来自连接复用器的隧道连接
func (htm *HybridTunnelManager) HandleTunnelConnection(conn net.Conn) {
	if htm.tcpServer != nil {
		htm.tcpServer.handleConnection(conn)
	}
}

// SetStatsCollector 设置统计收集器
func (htm *HybridTunnelManager) SetStatsCollector(statsCollector *StatsCollector) {
	htm.mu.Lock()
	defer htm.mu.Unlock()
	htm.statsCollector = statsCollector
}

// UpdateTunnels 动态更新隧道配置
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

// GetRandomEndpointFromTunnels 从隧道中获取随机端点
func (htm *HybridTunnelManager) GetRandomEndpointFromTunnels(tunnelNames []string) (string, string, error) {
	if htm.tcpManager != nil {
		return htm.tcpManager.GetRandomEndpointFromTunnels(tunnelNames)
	}
	return "", "", errors.New("no available endpoints found")
}

// FindTunnelForEndpoint 查找端点所在的隧道
func (htm *HybridTunnelManager) FindTunnelForEndpoint(endpointName string) (string, bool) {
	if htm.tcpManager != nil {
		return htm.tcpManager.FindTunnelForEndpoint(endpointName)
	}
	return "", false
}

// GetEndpointsInfo 获取端点信息
func (htm *HybridTunnelManager) GetEndpointsInfo(tunnelName string) map[string]*EndpointInfo {
	if htm.tcpManager != nil {
		return htm.tcpManager.GetEndpointsInfo(tunnelName)
	}
	return nil
}

// MeasureEndpointLatency 测量端点延迟
func (htm *HybridTunnelManager) MeasureEndpointLatency(tunnelName, endpointName string) (time.Duration, error) {
	// TODO: Implement latency measurement for TCP tunnel
	return 0, errors.New("latency measurement not implemented for TCP tunnel")
}

// GetPoolStats 获取连接池统计信息
func (htm *HybridTunnelManager) GetPoolStats() map[string]interface{} {
	htm.mu.RLock()
	defer htm.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["protocol"] = "tcp"

	return stats
}

// Cleanup 清理资源
func (htm *HybridTunnelManager) Cleanup() {
	DebugLog("[TUNNEL] Cleaning up tunnel manager")

	if htm.tcpManager != nil {
		htm.tcpManager.Stop()
	}
}
