package tunnel

import (
	"context"
	"io"
	"net"
	"time"

	"aps/stats"
	"aps/tcptunnel"
)

// RequestPayload is re-exported for callers that want to use the tunnel
// manager interface without importing aps/tcptunnel directly.
type RequestPayload = tcptunnel.RequestPayload

// EndpointInfo is re-exported for the same reason.
type EndpointInfo = tcptunnel.EndpointInfo

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
	GetEndpointsInfo(tunnelName string, stats *stats.StatsCollector) map[string]*EndpointInfo
	MeasureEndpointLatency(tunnelName, endpointName string) (time.Duration, error)

	// 统计和管理方法
	SetStatsCollector(statsCollector *stats.StatsCollector)
	GetPoolStats() map[string]interface{}
	Cleanup()
	UpdateTunnels(newConfig *tcptunnel.Config)

	// Config hot reload
	SendConfigUpdate(tunnelName, endpointName string, payload []byte) error

	// Online endpoints
	GetAllOnlineEndpoints() []EndpointInfo
}

// 确保HybridTunnelManager实现这个接口
var _ TunnelManagerInterface = (*HybridTunnelManager)(nil)
