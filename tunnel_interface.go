package main

import (
	"context"
	"io"
	"time"

	pb "aps/tunnelpb"
)

// TunnelManagerInterface 定义隧道管理器的统一接口
type TunnelManagerInterface interface {
	// gRPC相关方法
	RegisterEndpointStream(tunnelName, endpointName, password string, stream pb.TunnelService_EstablishServer, remoteAddr string) (*EndpointStream, error)
	UnregisterEndpointStream(tunnelName, endpointName, streamID string)
	HandleIncomingMessage(msg *pb.EndpointToServer)

	// 通用隧道操作方法
	SendRequestStream(ctx context.Context, tunnelName, endpointName string, reqPayload *RequestPayload) (io.ReadCloser, []byte, error)
	GetRandomEndpointFromTunnels(tunnelNames []string) (string, string, error)
	FindTunnelForEndpoint(endpointName string) (string, bool)
	GetEndpointsInfo(tunnelName string) map[string]*EndpointInfo
	MeasureEndpointLatency(tunnelName, endpointName string) (time.Duration, error)

	// 统计和管理方法
	SetStatsCollector(statsCollector *StatsCollector)
	GetPoolStats() map[string]interface{}
	Cleanup()
	UpdateTunnels(newConfig *Config)
}

// 确保HybridTunnelManager和TunnelManager都实现这个接口
var _ TunnelManagerInterface = (*HybridTunnelManager)(nil)
var _ TunnelManagerInterface = (*TunnelManager)(nil)