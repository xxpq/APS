package tcptunnel

import (
	"context"
	"io"
	"net"
	"time"

	"aps/stats"
)

// RequestPayload represents an HTTP request payload sent through the tunnel.
type RequestPayload struct {
	ID         string
	Method     string
	URL        string
	SourceIP   string
	Header     map[string][]string
	Data       []byte
	HeaderData []byte
	Body       io.ReadCloser
	Timeout    time.Duration
}

// EndpointInfo contains information about a connected endpoint.
type EndpointInfo struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	TunnelName       string      `json:"tunnel_name"`
	RemoteAddr       string      `json:"remote_addr"`
	OnlineTime       time.Time   `json:"online_time"`
	LastActivityTime time.Time   `json:"last_activity_time"`
	Status           string      `json:"status"`
	Stats            interface{} `json:"stats,omitempty"` // Statistics for this endpoint (tunnel-level)
}

// TunnelManagerInterface 定义隧道管理器的统一接口 (unified tunnel manager
// interface). It is satisfied by the higher-level aps/tunnel package via its
// HybridTunnelManager; declared here so that code in this package can refer to
// it without an import cycle.
type TunnelManagerInterface interface {
	// TCP tunnel service control
	StartTCPServer(addr string) error
	HandleTunnelConnection(conn net.Conn)

	// Common tunnel operations
	SendRequestStream(ctx context.Context, tunnelName, endpointName string, reqPayload *RequestPayload) (io.ReadCloser, []byte, error)
	SendProxyConnect(ctx context.Context, tunnelName, endpointName string, host string, port int, useTLS bool, clientConn net.Conn, clientIP string) (<-chan struct{}, error)
	GetRandomEndpointFromTunnels(tunnelNames []string) (string, string, error)
	FindTunnelForEndpoint(endpointName string) (string, bool)
	GetEndpointsInfo(tunnelName string, stats *stats.StatsCollector) map[string]*EndpointInfo
	MeasureEndpointLatency(tunnelName, endpointName string) (time.Duration, error)

	// Stats and management
	SetStatsCollector(statsCollector *stats.StatsCollector)
	GetPoolStats() map[string]interface{}
	Cleanup()
	UpdateTunnels(newConfig *Config)

	// Config hot reload
	SendConfigUpdate(tunnelName, endpointName string, payload []byte) error

	// Online endpoints
	GetAllOnlineEndpoints() []EndpointInfo
}
