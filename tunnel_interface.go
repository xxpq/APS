package main

import (
	"context"
	"io"
	"net"
	"time"
)

// RequestPayload represents an HTTP request payload
type RequestPayload struct {
	ID      string
	Method  string
	URL     string
	Header  map[string][]string
	Data    []byte
	Timeout time.Duration
}

// EndpointInfo contains information about a connected endpoint
type EndpointInfo struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	TunnelName       string         `json:"tunnel_name"`
	RemoteAddr       string         `json:"remote_addr"`
	OnlineTime       time.Time      `json:"online_time"`
	LastActivityTime time.Time      `json:"last_activity_time"`
	Status           string         `json:"status"`
	Stats            *PublicMetrics `json:"stats,omitempty"` // Statistics for this endpoint (tunnel-level)
}

// TunnelManagerInterface 定义隧道管理器的统一接口
type TunnelManagerInterface interface {
	// TCP隧道服务控制
	StartTCPServer(addr string) error
	HandleTunnelConnection(conn net.Conn)

	// 通用隧道操作方法
	SendRequestStream(ctx context.Context, tunnelName, endpointName string, reqPayload *RequestPayload) (io.ReadCloser, []byte, error)
	SendProxyConnect(ctx context.Context, tunnelName, endpointName string, host string, port int, useTLS bool, clientConn net.Conn, clientIP string) (<-chan struct{}, error)
	GetRandomEndpointFromTunnels(tunnelNames []string) (string, string, error)
	FindTunnelForEndpoint(endpointName string) (string, bool)
	GetEndpointsInfo(tunnelName string, stats *StatsCollector) map[string]*EndpointInfo
	MeasureEndpointLatency(tunnelName, endpointName string) (time.Duration, error)

	// 统计和管理方法
	SetStatsCollector(statsCollector *StatsCollector)
	GetPoolStats() map[string]interface{}
	Cleanup()
	UpdateTunnels(newConfig *Config)
}

// 确保HybridTunnelManager实现这个接口
var _ TunnelManagerInterface = (*HybridTunnelManager)(nil)
