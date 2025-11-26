package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	pb "aps/tunnelpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// RelayClient 中继客户端
type RelayClient struct {
	name           string
	conn           *grpc.ClientConn
	client         pb.RelayServiceClient
	stream         pb.RelayService_EstablishRelayClient
	relayEndpoints map[string]*RelayEndpoint
	mu             sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	messageChan    chan *pb.RelayMessage
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
		messageChan:    make(chan *pb.RelayMessage, 100),
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
	rc.client = pb.NewRelayServiceClient(conn)

	// 建立中继流
	md := metadata.New(map[string]string{
		"client-name": rc.name,
	})

	streamCtx := metadata.NewOutgoingContext(ctx, md)
	stream, err := rc.client.EstablishRelay(streamCtx)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to establish relay stream: %v", err)
	}

	rc.stream = stream
	rc.isConnected = true

	// 启动消息处理协程
	go rc.handleIncomingMessages()
	go rc.handleOutgoingMessages()

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
	close(rc.messageChan)
	
	if rc.stream != nil {
		rc.stream.CloseSend()
	}
	
	if rc.conn != nil {
		rc.conn.Close()
	}

	rc.isConnected = false
	log.Printf("[RelayClient] Disconnected from relay")
}

// handleIncomingMessages 处理传入消息
func (rc *RelayClient) handleIncomingMessages() {
	for {
		select {
		case <-rc.ctx.Done():
			return
		default:
			message, err := rc.stream.Recv()
			if err == io.EOF {
				log.Printf("[RelayClient] Relay stream closed by server")
				return
			}
			if err != nil {
				log.Printf("[RelayClient] Error receiving message: %v", err)
				return
			}

			if err := rc.processIncomingMessage(message); err != nil {
				log.Printf("[RelayClient] Error processing message: %v", err)
			}
		}
	}
}

// handleOutgoingMessages 处理传出消息
func (rc *RelayClient) handleOutgoingMessages() {
	for {
		select {
		case <-rc.ctx.Done():
			return
		case message := <-rc.messageChan:
			if err := rc.stream.Send(message); err != nil {
				log.Printf("[RelayClient] Error sending message: %v", err)
				return
			}
		}
	}
}

// processIncomingMessage 处理传入消息
func (rc *RelayClient) processIncomingMessage(message *pb.RelayMessage) error {
	switch message.Type {
	case pb.RelayMessageType_RELAY_DATA:
		return rc.handleRelayData(message)
	case pb.RelayMessageType_RELAY_CONTROL:
		return rc.handleRelayControl(message)
	case pb.RelayMessageType_ROUTE_RESPONSE:
		return rc.handleRouteResponse(message)
	case pb.RelayMessageType_HEARTBEAT:
		return rc.handleHeartbeat(message)
	default:
		log.Printf("[RelayClient] Unknown message type: %v", message.Type)
		return nil
	}
}

// handleRelayData 处理中继数据
func (rc *RelayClient) handleRelayData(message *pb.RelayMessage) error {
	log.Printf("[RelayClient] Received relay data from %s (size: %d bytes)", 
		message.SourceClient, len(message.Data))

	// 如果目标是本客户端，处理数据
	if message.TargetClient == rc.name {
		return rc.processDataForSelf(message.Data)
	}

	// 否则转发给下一个中继节点
	return rc.forwardToNextHop(message)
}

// handleRelayControl 处理中继控制消息
func (rc *RelayClient) handleRelayControl(message *pb.RelayMessage) error {
	log.Printf("[RelayClient] Received control message from %s: %s", 
		message.SourceClient, string(message.Data))
	
	// 处理控制逻辑
	return nil
}

// handleRouteResponse 处理路由响应
func (rc *RelayClient) handleRouteResponse(message *pb.RelayMessage) error {
	var routeResponse RelayRouteResponse
	if err := json.Unmarshal(message.Data, &routeResponse); err != nil {
		return fmt.Errorf("failed to unmarshal route response: %v", err)
	}

	log.Printf("[RelayClient] Received route response: path=%v, latency=%dms",
		routeResponse.Path, routeResponse.Latency)

	// 更新路由信息
	rc.updateRouteInfo(&routeResponse)
	return nil
}

// handleHeartbeat 处理心跳
func (rc *RelayClient) handleHeartbeat(message *pb.RelayMessage) error {
	// 回复心跳
	response := &pb.RelayMessage{
		Type:         pb.RelayMessageType_HEARTBEAT,
		SourceClient: rc.name,
		TargetClient: message.SourceClient,
		Data:         message.Data,
		Timestamp:    time.Now().Unix(),
	}

	return rc.SendMessage(response)
}

// processDataForSelf 处理给自己的数据
func (rc *RelayClient) processDataForSelf(data []byte) error {
	// 这里应该处理实际的数据
	// 暂时只是记录日志
	log.Printf("[RelayClient] Processing data for self (size: %d bytes)", len(data))
	return nil
}

// forwardToNextHop 转发到下一跳
func (rc *RelayClient) forwardToNextHop(message *pb.RelayMessage) error {
	// 这里应该实现转发逻辑
	// 暂时只是记录日志
	log.Printf("[RelayClient] Forwarding message to next hop: %s", message.TargetClient)
	return nil
}

// SendMessage 发送消息
func (rc *RelayClient) SendMessage(message *pb.RelayMessage) error {
	if !rc.isConnected {
		return fmt.Errorf("not connected to relay")
	}

	select {
	case rc.messageChan <- message:
		return nil
	case <-rc.ctx.Done():
		return fmt.Errorf("context cancelled")
	default:
		return fmt.Errorf("message channel full")
	}
}

// SendData 发送数据
func (rc *RelayClient) SendData(targetClient string, data []byte) error {
	message := &pb.RelayMessage{
		Type:         pb.RelayMessageType_RELAY_DATA,
		SourceClient: rc.name,
		TargetClient: targetClient,
		Data:         data,
		Timestamp:    time.Now().Unix(),
	}

	return rc.SendMessage(message)
}

// RequestRoute 请求路由
func (rc *RelayClient) RequestRoute(target string) error {
	routeRequest := RelayRouteRequest{
		Source: rc.name,
		Target: target,
	}

	data, err := json.Marshal(routeRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal route request: %v", err)
	}

	message := &pb.RelayMessage{
		Type:         pb.RelayMessageType_ROUTE_REQUEST,
		SourceClient: rc.name,
		TargetClient: "SERVER",
		Data:         data,
		Timestamp:    time.Now().Unix(),
	}

	return rc.SendMessage(message)
}

// ConnectToReverseRelay 连接到反向中继（E1主动连接E2）
func (rc *RelayClient) ConnectToReverseRelay(ctx context.Context, endpoint *RelayEndpoint) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if rc.isConnected {
		return fmt.Errorf("already connected to relay")
	}

	log.Printf("[RelayClient] Connecting to reverse relay: %s at %s", endpoint.Name, endpoint.Address)

	// 建立gRPC连接
	conn, err := grpc.Dial(endpoint.Address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect to reverse relay %s: %v", endpoint.Name, err)
	}

	rc.conn = conn
	rc.client = pb.NewRelayServiceClient(conn)

	// 建立反向中继流（使用特殊的metadata标识这是反向连接）
	md := metadata.New(map[string]string{
		"client-name": rc.name,
		"connection-type": "reverse", // 标识这是反向连接
	})

	streamCtx := metadata.NewOutgoingContext(ctx, md)
	stream, err := rc.client.EstablishRelay(streamCtx)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to establish reverse relay stream: %v", err)
	}

	rc.stream = stream
	rc.isConnected = true

	// 启动消息处理协程
	go rc.handleIncomingMessages()
	go rc.handleOutgoingMessages()

	log.Printf("[RelayClient] Successfully connected to reverse relay: %s", endpoint.Name)
	return nil
}

// updateRouteInfo 更新路由信息
func (rc *RelayClient) updateRouteInfo(routeResponse *RelayRouteResponse) {
	// 这里可以实现路由信息的存储和更新逻辑
	log.Printf("[RelayClient] Updated route info: %v", routeResponse)
}

// IsConnected 返回连接状态
func (rc *RelayClient) IsConnected() bool {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.isConnected
}

// GetConnectedRelays 获取已连接的中继列表
func (rc *RelayClient) GetConnectedRelays() []string {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	relays := make([]string, 0)
	for name := range rc.relayEndpoints {
		relays = append(relays, name)
	}
	return relays
}