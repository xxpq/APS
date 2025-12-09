package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"sync"
	"time"

	pb "aps/tunnelpb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

// RelayServer 中继服务器
type RelayServer struct {
	pb.UnimplementedRelayServiceServer
	name              string
	address           string
	listener          net.Listener
	grpcServer        *grpc.Server
	clients           map[string]*RelayClientConnection
	reverseClients    map[string]*RelayClientConnection // 反向连接客户端
	mu                sync.RWMutex
	ctx               context.Context
	cancel            context.CancelFunc
	isReverseMode     bool
	reverseConnection chan *RelayClientConnection // 反向连接通知通道
}

// RelayClientConnection 中继客户端连接
type RelayClientConnection struct {
	Name       string
	Stream     pb.RelayService_EstablishRelayServer
	Conn       net.Conn // 用于反向连接的原始连接
	EndpointID string   // 端点ID
	Type       string   // 连接类型: "normal" 或 "reverse"
	LastActive time.Time
	mu         sync.Mutex
}

// NewRelayServer 创建中继服务器
func NewRelayServer(name string) *RelayServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &RelayServer{
		name:              name,
		address:           fmt.Sprintf("0.0.0.0:%d", 18081), // 默认中继端口
		clients:           make(map[string]*RelayClientConnection),
		reverseClients:    make(map[string]*RelayClientConnection),
		ctx:               ctx,
		cancel:            cancel,
		reverseConnection: make(chan *RelayClientConnection, 1),
	}
}

// Start 启动中继服务器
func (rs *RelayServer) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", rs.address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", rs.address, err)
	}

	rs.listener = listener
	rs.grpcServer = grpc.NewServer(
		grpc.MaxRecvMsgSize(math.MaxInt64),
		grpc.MaxSendMsgSize(math.MaxInt64),
		grpc.NumStreamWorkers(uint32(100)), // 并发流处理worker数
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     5 * time.Minute,  // 空闲连接超时
			MaxConnectionAge:      30 * time.Minute, // 连接最大生命周期
			MaxConnectionAgeGrace: 10 * time.Second, // 优雅关闭等待时间
			Time:                  30 * time.Second, // keepalive ping间隔
			Timeout:               10 * time.Second, // keepalive ping超时
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second, // 客户端ping最小间隔
			PermitWithoutStream: true,            // 允许无流时ping
		}),
	)
	pb.RegisterRelayServiceServer(rs.grpcServer, rs)

	log.Printf("[RelayServer] Starting relay server on %s", rs.address)

	go func() {
		if err := rs.grpcServer.Serve(listener); err != nil {
			log.Printf("[RelayServer] Failed to serve: %v", err)
		}
	}()

	return nil
}

// Stop 停止中继服务器
func (rs *RelayServer) Stop() {
	log.Printf("[RelayServer] Stopping relay server")

	rs.cancel()

	if rs.grpcServer != nil {
		rs.grpcServer.GracefulStop()
	}

	if rs.listener != nil {
		rs.listener.Close()
	}
}

// WaitForReverseConnection 等待反向连接
func (rs *RelayServer) WaitForReverseConnection(ctx context.Context, endpointID string) (*RelayClientConnection, error) {
	rs.mu.Lock()
	if client, exists := rs.reverseClients[endpointID]; exists {
		rs.mu.Unlock()
		return client, nil
	}
	rs.mu.Unlock()

	select {
	case client := <-rs.reverseConnection:
		if client != nil && client.EndpointID == endpointID {
			return client, nil
		}
		// 如果不是目标端点，放回通道
		select {
		case rs.reverseConnection <- client:
		default:
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-rs.ctx.Done():
		return nil, errors.New("server stopped")
	}

	// 再次检查
	rs.mu.Lock()
	if client, exists := rs.reverseClients[endpointID]; exists {
		rs.mu.Unlock()
		return client, nil
	}
	rs.mu.Unlock()

	return nil, errors.New("connection not found")
}

// handleReverseConnection 处理反向连接
func (rs *RelayServer) handleReverseConnection(conn net.Conn, endpointID string) {
	client := &RelayClientConnection{
		Conn:       conn,
		EndpointID: endpointID,
		Type:       "reverse",
		Name:       endpointID,
	}

	rs.mu.Lock()
	rs.reverseClients[endpointID] = client
	rs.mu.Unlock()

	// 通知等待的客户端
	select {
	case rs.reverseConnection <- client:
	default:
		// 通道已满，丢弃最旧的连接
		select {
		case <-rs.reverseConnection:
			rs.reverseConnection <- client
		default:
		}
	}

	log.Printf("反向连接已建立: %s", endpointID)

	// 保持连接直到断开
	buffer := make([]byte, 4096)
	for {
		select {
		case <-rs.ctx.Done():
			return
		default:
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := conn.Read(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("反向连接断开: %s, 错误: %v", endpointID, err)
				rs.mu.Lock()
				delete(rs.reverseClients, endpointID)
				rs.mu.Unlock()
				return
			}
			if n > 0 {
				// 处理心跳或其他数据
				log.Printf("收到反向连接数据: %s, 长度: %d", endpointID, n)
			}
		}
	}
}

// EstablishRelay 建立中继连接
func (rs *RelayServer) EstablishRelay(stream pb.RelayService_EstablishRelayServer) error {
	// 获取客户端信息
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		return fmt.Errorf("failed to get metadata")
	}

	clientName := getMetadataValue(md, "client-name")
	if clientName == "" {
		return fmt.Errorf("client name not provided")
	}

	log.Printf("[RelayServer] New relay connection from client: %s", clientName)

	// 创建客户端连接
	clientConn := &RelayClientConnection{
		Name:       clientName,
		Stream:     stream,
		LastActive: time.Now(),
	}

	// 注册客户端
	rs.registerClient(clientName, clientConn)
	defer rs.unregisterClient(clientName)

	// 处理中继消息
	return rs.handleRelayMessages(clientConn)
}

// handleRelayMessages 处理中继消息
func (rs *RelayServer) handleRelayMessages(clientConn *RelayClientConnection) error {
	for {
		select {
		case <-rs.ctx.Done():
			return fmt.Errorf("relay server shutting down")
		default:
			// 设置读取超时
			message, err := clientConn.receiveWithTimeout(30 * time.Second)
			if err != nil {
				if err == io.EOF {
					log.Printf("[RelayServer] Client %s disconnected", clientConn.Name)
					return nil
				}
				log.Printf("[RelayServer] Error receiving from client %s: %v", clientConn.Name, err)
				return err
			}

			// 更新最后活跃时间
			clientConn.updateLastActive()

			// 处理中继消息
			if err := rs.processRelayMessage(clientConn, message); err != nil {
				log.Printf("[RelayServer] Error processing message from %s: %v", clientConn.Name, err)
				return err
			}
		}
	}
}

// processRelayMessage 处理中继消息
func (rs *RelayServer) processRelayMessage(fromClient *RelayClientConnection, message *pb.RelayMessage) error {
	switch message.Type {
	case pb.RelayMessageType_RELAY_DATA:
		return rs.handleRelayData(fromClient, message)
	case pb.RelayMessageType_RELAY_CONTROL:
		return rs.handleRelayControl(fromClient, message)
	case pb.RelayMessageType_ROUTE_REQUEST:
		return rs.handleRouteRequest(fromClient, message)
	default:
		return fmt.Errorf("unknown relay message type: %v", message.Type)
	}
}

// handleRelayData 处理中继数据
func (rs *RelayServer) handleRelayData(fromClient *RelayClientConnection, message *pb.RelayMessage) error {
	targetClient := message.TargetClient
	if targetClient == "" {
		return fmt.Errorf("target client not specified")
	}

	// 查找目标客户端
	targetConn, exists := rs.getClient(targetClient)
	if !exists {
		// 如果目标客户端不存在，可能是要转发到服务器
		if targetClient == "SERVER" {
			return rs.forwardToServer(fromClient, message)
		}
		return fmt.Errorf("target client %s not found", targetClient)
	}

	// 转发给目标客户端
	log.Printf("[RelayServer] Relaying data from %s to %s (size: %d bytes)",
		fromClient.Name, targetClient, len(message.Data))

	return targetConn.sendMessage(message)
}

// handleRelayControl 处理中继控制消息
func (rs *RelayServer) handleRelayControl(fromClient *RelayClientConnection, message *pb.RelayMessage) error {
	// 处理控制消息，如心跳、状态更新等
	log.Printf("[RelayServer] Received control message from %s: %s",
		fromClient.Name, string(message.Data))

	// 可以在这里添加具体的控制逻辑
	return nil
}

// handleRouteRequest 处理路由请求
func (rs *RelayServer) handleRouteRequest(fromClient *RelayClientConnection, message *pb.RelayMessage) error {
	// 解析路由请求
	var routeRequest RelayRouteRequest
	if err := json.Unmarshal(message.Data, &routeRequest); err != nil {
		return fmt.Errorf("failed to unmarshal route request: %v", err)
	}

	log.Printf("[RelayServer] Received route request from %s to %s",
		fromClient.Name, routeRequest.Target)

	// 构建路由响应
	routeResponse := RelayRouteResponse{
		Source:   fromClient.Name,
		Target:   routeRequest.Target,
		Path:     []string{fromClient.Name, rs.name, "SERVER"},
		HopCount: 2,
		Latency:  50, // 模拟延迟
	}

	responseData, err := json.Marshal(routeResponse)
	if err != nil {
		return fmt.Errorf("failed to marshal route response: %v", err)
	}

	response := &pb.RelayMessage{
		Type:         pb.RelayMessageType_ROUTE_RESPONSE,
		SourceClient: rs.name,
		TargetClient: fromClient.Name,
		Data:         responseData,
	}

	return fromClient.sendMessage(response)
}

// forwardToServer 转发到服务器
func (rs *RelayServer) forwardToServer(fromClient *RelayClientConnection, message *pb.RelayMessage) error {
	// 这里需要实现转发到APS服务器的逻辑
	log.Printf("[RelayServer] Forwarding message from %s to APS server", fromClient.Name)

	// 可以建立到APS服务器的连接，或者通过现有的隧道连接
	// 暂时返回成功，后续实现具体逻辑
	return nil
}

// registerClient 注册客户端
func (rs *RelayServer) registerClient(name string, client *RelayClientConnection) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rs.clients[name] = client
	log.Printf("[RelayServer] Registered client: %s", name)
}

// unregisterClient 注销客户端
func (rs *RelayServer) unregisterClient(name string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	delete(rs.clients, name)
	log.Printf("[RelayServer] Unregistered client: %s", name)
}

// getClient 获取客户端连接
func (rs *RelayServer) getClient(name string) (*RelayClientConnection, bool) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	client, exists := rs.clients[name]
	return client, exists
}

// GetConnectedClients 获取已连接的客户端列表
func (rs *RelayServer) GetConnectedClients() []string {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	clients := make([]string, 0, len(rs.clients))
	for name := range rs.clients {
		clients = append(clients, name)
	}
	return clients
}

// RelayClientConnection 的方法

// receiveWithTimeout 带超时接收消息
func (c *RelayClientConnection) receiveWithTimeout(timeout time.Duration) (*pb.RelayMessage, error) {
	// 这里应该实现带超时的接收逻辑
	// 暂时使用简单的接收
	return c.Stream.Recv()
}

// sendMessage 发送消息
func (c *RelayClientConnection) sendMessage(message *pb.RelayMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.Stream.Send(message); err != nil {
		return err
	}

	c.LastActive = time.Now()
	return nil
}

// updateLastActive 更新最后活跃时间
func (c *RelayClientConnection) updateLastActive() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.LastActive = time.Now()
}

// getMetadataValue 获取metadata值
func getMetadataValue(md metadata.MD, key string) string {
	values := md.Get(key)
	if len(values) > 0 {
		return values[0]
	}
	return ""
}
