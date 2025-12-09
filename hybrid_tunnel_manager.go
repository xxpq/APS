package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	pb "aps/tunnelpb"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// HybridTunnelManager 管理gRPC和WebSocket隧道的混合管理器
type HybridTunnelManager struct {
	mu                sync.RWMutex
	grpcManager       *TunnelManager
	wsManager         *WebSocketPoolManager
	config            *Config
	statsCollector    *StatsCollector
	fallbackEnabled   bool
	fallbackThreshold int // gRPC失败多少次后启用fallback
}

// NewHybridTunnelManager 创建混合隧道管理器
func NewHybridTunnelManager(config *Config, statsCollector *StatsCollector) *HybridTunnelManager {
	htm := &HybridTunnelManager{
		config:            config,
		statsCollector:    statsCollector,
		fallbackEnabled:   true,
		fallbackThreshold: 3,
	}

	// 初始化gRPC隧道管理器
	htm.grpcManager = NewTunnelManager(config, statsCollector)

	// 初始化WebSocket连接池管理器
	htm.wsManager = NewWebSocketPoolManager(config, statsCollector)

	// 根据配置调整参数
	htm.updateConfigFromTunnels()

	return htm
}

// updateConfigFromTunnels 根据隧道配置更新混合管理器参数
func (htm *HybridTunnelManager) updateConfigFromTunnels() {
	if htm.config == nil || htm.config.Tunnels == nil {
		return
	}

	for _, tunnelConfig := range htm.config.Tunnels {
		if tunnelConfig.WebSocketPool != nil {
			wsConfig := tunnelConfig.WebSocketPool

			// 更新fallback配置
			htm.fallbackEnabled = wsConfig.FallbackEnabled
			if wsConfig.FallbackThreshold > 0 {
				htm.fallbackThreshold = wsConfig.FallbackThreshold
			}

			log.Printf("[HYBRID] Updated WebSocket pool config - FallbackEnabled: %v, FallbackThreshold: %d",
				htm.fallbackEnabled, htm.fallbackThreshold)
			break // 使用第一个找到的配置
		}
	}
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

// UpdateTunnels 动态更新所有底层管理器的隧道配置
func (htm *HybridTunnelManager) UpdateTunnels(newConfig *Config) {
	htm.mu.Lock()
	defer htm.mu.Unlock()

	log.Println("[HYBRID] Updating tunnels for all managers...")
	htm.config = newConfig // 更新混合管理器持有的配置引用

	if htm.grpcManager != nil {
		htm.grpcManager.UpdateTunnels(newConfig)
	}
	if htm.wsManager != nil {
		htm.wsManager.UpdateTunnels(newConfig)
	}

	// 更新混合管理器本身的配置
	htm.updateConfigFromTunnels()
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
	htm.mu.RLock()
	fallbackEnabled := htm.fallbackEnabled
	htm.mu.RUnlock()

	// First, try gRPC
	if htm.grpcManager != nil {
		bodyStream, header, err := htm.grpcManager.SendRequestStream(ctx, tunnelName, endpointName, reqPayload)
		if err == nil {
			return bodyStream, header, nil
		}

		// If gRPC fails and fallback is enabled, try WebSocket
		if fallbackEnabled && htm.shouldFallback(err) {
			log.Printf("[HYBRID] gRPC request failed for tunnel %s.%s, trying WebSocket fallback: %v",
				tunnelName, endpointName, err)
			// Note: WebSocket implementation does not support streaming yet.
			// This will read the entire body into memory.
			data, err := htm.sendWebSocketRequest(ctx, tunnelName, endpointName, reqPayload)
			if err != nil {
				return nil, nil, err
			}
			// To match the stream interface, we wrap the data in a ReadCloser.
			// This is not true streaming.
			return io.NopCloser(bytes.NewReader(data)), nil, nil
		}

		return nil, nil, err
	}

	// If gRPC manager is not available, try WebSocket directly
	if fallbackEnabled {
		data, err := htm.sendWebSocketRequest(ctx, tunnelName, endpointName, reqPayload)
		if err != nil {
			return nil, nil, err
		}
		return io.NopCloser(bytes.NewReader(data)), nil, nil
	}

	return nil, nil, errors.New("no available tunnel managers")
}

// shouldFallback 判断是否应该fallback到WebSocket
func (htm *HybridTunnelManager) shouldFallback(err error) bool {
	// 检查是否是gRPC特定的错误
	if statusErr, ok := status.FromError(err); ok {
		switch statusErr.Code() {
		case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted:
			return true
		}
	}

	// 检查错误消息中是否包含网络相关的关键词
	errMsg := err.Error()
	networkErrors := []string{
		"connection refused",
		"connection reset",
		"timeout",
		"unavailable",
		"deadline exceeded",
		"no available stream",
		"endpoint is not connected",
	}

	for _, networkErr := range networkErrors {
		if contains(errMsg, networkErr) {
			return true
		}
	}

	return false
}

// sendWebSocketRequest 通过WebSocket发送请求
func (htm *HybridTunnelManager) sendWebSocketRequest(ctx context.Context, tunnelName, endpointName string, reqPayload *RequestPayload) ([]byte, error) {
	if htm.wsManager == nil {
		return nil, errors.New("WebSocket manager not available")
	}

	// 获取隧道配置
	htm.mu.RLock()
	tunnelConfig, exists := htm.config.Tunnels[tunnelName]
	htm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("tunnel '%s' not found", tunnelName)
	}

	// 获取或创建WebSocket连接池
	pool := htm.wsManager.GetOrCreatePool(tunnelName, endpointName, tunnelConfig.Password, "")

	// 通过WebSocket发送请求
	respData, err := pool.SendRequest(ctx, reqPayload)
	if err != nil {
		return nil, fmt.Errorf("WebSocket request failed: %v", err)
	}

	// WebSocket pool returns raw data directly, not JSON
	return respData, nil
}

// GetRandomEndpointFromTunnels 从隧道中获取随机端点
func (htm *HybridTunnelManager) GetRandomEndpointFromTunnels(tunnelNames []string) (string, string, error) {
	// 首先尝试gRPC
	if htm.grpcManager != nil {
		tunnelName, endpointName, err := htm.grpcManager.GetRandomEndpointFromTunnels(tunnelNames)
		if err == nil {
			return tunnelName, endpointName, nil
		}
	}

	// 如果gRPC没有可用端点，尝试WebSocket
	// 这里可以实现WebSocket端点发现逻辑
	return "", "", errors.New("no available endpoints found")
}

// FindTunnelForEndpoint 查找端点所在的隧道
func (htm *HybridTunnelManager) FindTunnelForEndpoint(endpointName string) (string, bool) {
	// 首先尝试gRPC
	if htm.grpcManager != nil {
		if tunnelName, exists := htm.grpcManager.FindTunnelForEndpoint(endpointName); exists {
			return tunnelName, true
		}
	}

	// 尝试WebSocket
	if htm.wsManager != nil {
		if tunnelName, exists := htm.wsManager.FindTunnelForEndpoint(endpointName); exists {
			return tunnelName, true
		}
	}

	return "", false
}

// GetEndpointsInfo 获取端点信息
func (htm *HybridTunnelManager) GetEndpointsInfo(tunnelName string) map[string]*EndpointInfo {
	var grpcInfo, wsInfo map[string]*EndpointInfo

	// 获取gRPC信息
	if htm.grpcManager != nil {
		grpcInfo = htm.grpcManager.GetEndpointsInfo(tunnelName)
	}

	// 获取WebSocket信息
	if htm.wsManager != nil {
		wsInfo = htm.wsManager.GetEndpointsInfo(tunnelName)
	}

	// 合并结果
	if grpcInfo == nil && wsInfo == nil {
		return nil
	}

	result := make(map[string]*EndpointInfo)
	if grpcInfo != nil {
		for k, v := range grpcInfo {
			result[k] = v
		}
	}
	if wsInfo != nil {
		for k, v := range wsInfo {
			// 如果重名，gRPC优先
			if _, exists := result[k]; !exists {
				result[k] = v
			}
		}
	}

	return result
}

// MeasureEndpointLatency 测量端点延迟
func (htm *HybridTunnelManager) MeasureEndpointLatency(tunnelName, endpointName string) (time.Duration, error) {
	// 首先尝试gRPC
	if htm.grpcManager != nil {
		if latency, err := htm.grpcManager.MeasureEndpointLatency(tunnelName, endpointName); err == nil {
			return latency, nil
		}
	}

	// 如果gRPC失败，尝试WebSocket
	if htm.wsManager != nil {
		pool := htm.wsManager.GetOrCreatePool(tunnelName, endpointName, "", "")

		// 使用轻量级ping请求测量延迟
		pingPayload := &RequestPayload{
			URL:  "aps://ping",
			Data: []byte("ping"),
		}

		start := time.Now()
		_, err := pool.SendRequest(context.Background(), pingPayload)
		if err != nil {
			return 0, err
		}

		return time.Since(start), nil
	}

	return 0, errors.New("no available tunnel managers for latency measurement")
}

// EnableFallback 启用或禁用fallback机制
func (htm *HybridTunnelManager) EnableFallback(enabled bool) {
	htm.mu.Lock()
	defer htm.mu.Unlock()

	htm.fallbackEnabled = enabled
	log.Printf("[HYBRID] Fallback mechanism %s", map[bool]string{true: "enabled", false: "disabled"}[enabled])
}

// GetPoolStats 获取连接池统计信息
func (htm *HybridTunnelManager) GetPoolStats() map[string]interface{} {
	htm.mu.RLock()
	defer htm.mu.RUnlock()

	stats := make(map[string]interface{})

	// gRPC统计
	if htm.grpcManager != nil {
		grpcStats := make(map[string]interface{})
		// 这里可以添加gRPC统计信息
		stats["grpc"] = grpcStats
	}

	// WebSocket统计
	if htm.wsManager != nil {
		wsStats := make(map[string]interface{})
		// 这里可以添加WebSocket连接池统计信息
		stats["websocket"] = wsStats
	}

	stats["fallback_enabled"] = htm.fallbackEnabled
	return stats
}

// Cleanup 清理资源
func (htm *HybridTunnelManager) Cleanup() {
	log.Println("[HYBRID] Cleaning up hybrid tunnel manager")

	// 这里可以添加清理逻辑
	if htm.grpcManager != nil {
		// 清理gRPC管理器
	}

	if htm.wsManager != nil {
		// 清理WebSocket管理器
	}
}
