package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	pb "aps/tunnelpb"
)

// HybridTunnelManager 管理gRPC隧道的管理器（WebSocket已移除）
type HybridTunnelManager struct {
	mu             sync.RWMutex
	grpcManager    *TunnelManager
	config         *Config
	statsCollector *StatsCollector
}

// NewHybridTunnelManager 创建隧道管理器
func NewHybridTunnelManager(config *Config, statsCollector *StatsCollector) *HybridTunnelManager {
	htm := &HybridTunnelManager{
		config:         config,
		statsCollector: statsCollector,
	}

	// 初始化gRPC隧道管理器
	htm.grpcManager = NewTunnelManager(config, statsCollector)

	return htm
}

// SetStatsCollector 设置统计收集器
func (htm *HybridTunnelManager) SetStatsCollector(statsCollector *StatsCollector) {
	htm.mu.Lock()
	defer htm.mu.Unlock()

	htm.statsCollector = statsCollector
	if htm.grpcManager != nil {
		htm.grpcManager.SetStatsCollector(statsCollector)
	}
}

// UpdateTunnels 动态更新隧道配置
func (htm *HybridTunnelManager) UpdateTunnels(newConfig *Config) {
	htm.mu.Lock()
	defer htm.mu.Unlock()

	log.Println("[TUNNEL] Updating tunnels...")
	htm.config = newConfig

	if htm.grpcManager != nil {
		htm.grpcManager.UpdateTunnels(newConfig)
	}
}

// RegisterEndpointStream 注册gRPC端点流
func (htm *HybridTunnelManager) RegisterEndpointStream(tunnelName, endpointName, password string, stream pb.TunnelService_EstablishServer, remoteAddr string) (*EndpointStream, error) {
	return htm.grpcManager.RegisterEndpointStream(tunnelName, endpointName, password, stream, remoteAddr)
}

// UnregisterEndpointStream 注销gRPC端点流
func (htm *HybridTunnelManager) UnregisterEndpointStream(tunnelName, endpointName, streamID string) {
	htm.grpcManager.UnregisterEndpointStream(tunnelName, endpointName, streamID)
}

// HandleIncomingMessage 处理gRPC传入消息
func (htm *HybridTunnelManager) HandleIncomingMessage(msg *pb.EndpointToServer) {
	htm.grpcManager.HandleIncomingMessage(msg)
}

// SendRequestStream sends a request and returns a stream for the response.
func (htm *HybridTunnelManager) SendRequestStream(ctx context.Context, tunnelName, endpointName string, reqPayload *RequestPayload) (io.ReadCloser, []byte, error) {
	if htm.grpcManager != nil {
		return htm.grpcManager.SendRequestStream(ctx, tunnelName, endpointName, reqPayload)
	}

	return nil, nil, errors.New("no available tunnel manager")
}

// SendProxyConnect establishes a TCP proxy connection through the tunnel.
func (htm *HybridTunnelManager) SendProxyConnect(ctx context.Context, tunnelName, endpointName string, host string, port int, useTLS bool, clientConn net.Conn) error {
	if htm.grpcManager != nil {
		return htm.grpcManager.SendProxyConnect(ctx, tunnelName, endpointName, host, port, useTLS, clientConn)
	}

	return errors.New("no available tunnel manager for proxy connection")
}

// GetRandomEndpointFromTunnels 从隧道中获取随机端点
func (htm *HybridTunnelManager) GetRandomEndpointFromTunnels(tunnelNames []string) (string, string, error) {
	if htm.grpcManager != nil {
		return htm.grpcManager.GetRandomEndpointFromTunnels(tunnelNames)
	}

	return "", "", errors.New("no available endpoints found")
}

// FindTunnelForEndpoint 查找端点所在的隧道
func (htm *HybridTunnelManager) FindTunnelForEndpoint(endpointName string) (string, bool) {
	if htm.grpcManager != nil {
		return htm.grpcManager.FindTunnelForEndpoint(endpointName)
	}

	return "", false
}

// GetEndpointsInfo 获取端点信息
func (htm *HybridTunnelManager) GetEndpointsInfo(tunnelName string) map[string]*EndpointInfo {
	if htm.grpcManager != nil {
		return htm.grpcManager.GetEndpointsInfo(tunnelName)
	}

	return nil
}

// MeasureEndpointLatency 测量端点延迟
func (htm *HybridTunnelManager) MeasureEndpointLatency(tunnelName, endpointName string) (time.Duration, error) {
	if htm.grpcManager != nil {
		return htm.grpcManager.MeasureEndpointLatency(tunnelName, endpointName)
	}

	return 0, errors.New("no available tunnel manager for latency measurement")
}

// GetPoolStats 获取连接池统计信息
func (htm *HybridTunnelManager) GetPoolStats() map[string]interface{} {
	htm.mu.RLock()
	defer htm.mu.RUnlock()

	stats := make(map[string]interface{})

	if htm.grpcManager != nil {
		grpcStats := htm.grpcManager.GetPoolStats()
		stats["grpc"] = grpcStats
	}

	return stats
}

// Cleanup 清理资源
func (htm *HybridTunnelManager) Cleanup() {
	log.Println("[TUNNEL] Cleaning up tunnel manager")

	if htm.grpcManager != nil {
		htm.grpcManager.Cleanup()
	}
}
