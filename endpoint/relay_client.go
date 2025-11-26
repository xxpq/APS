package main

import (
	"context"
	"fmt"
	"log"
	"sync"

	pb "aps/tunnelpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// RelayClient 中继客户端
type RelayClient struct {
	name           string
	conn           *grpc.ClientConn
	client         pb.TunnelServiceClient
	stream         pb.TunnelService_EstablishClient
	relayEndpoints map[string]*RelayEndpoint
	mu             sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	isConnected    bool
}

// NewRelayClient 创建中继客户端
func NewRelayClient(name string) *RelayClient {
	ctx, cancel := context.WithCancel(context.Background())
	return &RelayClient{
		name:           name,
		relayEndpoints: make(map[string]*RelayEndpoint),
		ctx:            ctx,
		cancel:         cancel,
	}
}

// ConnectToRelay 连接到中继
func (rc *RelayClient) ConnectToRelay(ctx context.Context, endpoint *RelayEndpoint) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if rc.isConnected {
		return fmt.Errorf("already connected to relay")
	}

	log.Printf("[RelayClient] Connecting to relay: %s at %s", endpoint.Name, endpoint.Address)

	// 建立gRPC连接
	conn, err := grpc.Dial(endpoint.Address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect to relay %s: %v", endpoint.Name, err)
	}

	rc.conn = conn
	rc.client = pb.NewTunnelServiceClient(conn)

	// 建立隧道流
	md := metadata.New(map[string]string{
		"tunnel-name":   *tunnelName,
		"endpoint-name": rc.name,
		"password":      *tunnelPassword,
		"x-aps-tunnel":  endpointVersion,
		"relay-mode":    "true",
	})

	streamCtx := metadata.NewOutgoingContext(ctx, md)
	stream, err := rc.client.Establish(streamCtx)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to establish relay stream: %v", err)
	}

	rc.stream = stream
	rc.isConnected = true

	log.Printf("[RelayClient] Successfully connected to relay: %s", endpoint.Name)
	return nil
}

// Disconnect 断开连接
func (rc *RelayClient) Disconnect() {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if !rc.isConnected {
		return
	}

	log.Printf("[RelayClient] Disconnecting from relay")
	
	rc.cancel()
	
	if rc.stream != nil {
		rc.stream.CloseSend()
	}
	
	if rc.conn != nil {
		rc.conn.Close()
	}

	rc.isConnected = false
	log.Printf("[RelayClient] Disconnected from relay")
}

// IsConnected 返回连接状态
func (rc *RelayClient) IsConnected() bool {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.isConnected
}

// GetStream 获取流
func (rc *RelayClient) GetStream() pb.TunnelService_EstablishClient {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.stream
}