package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	pb "aps/tunnelpb"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
)

const (
	// WebSocket连接池配置
	DefaultPoolSize    = 10               // 默认连接池大小（增大以支持高并发）
	MaxPoolSize        = 50               // 最大连接池大小（增大以支持高并发）
	DefaultIdleTimeout = 5 * time.Minute  // 默认连接闲置超时时间
	DefaultMaxLifetime = 30 * time.Minute // 默认连接最大生命周期
	PingPeriod         = 30 * time.Second // ping周期
	PongWait           = 60 * time.Second // pong等待时间
)

// WebSocketConnection 表示一个WebSocket连接
type WebSocketConnection struct {
	ID              string
	Conn            *websocket.Conn
	TunnelName      string
	EndpointName    string
	Status          ConnectionStatus
	LastUsedTime    time.Time
	CreatedTime     time.Time
	mu              sync.Mutex
	inUse           bool
	sendCh          chan []byte
	pendingRequests map[string]chan *pb.Response
}

type ConnectionStatus int

const (
	StatusIdle ConnectionStatus = iota
	StatusInUse
	StatusClosed
)

// WebSocketPool 管理WebSocket连接池
type WebSocketPool struct {
	mu           sync.RWMutex
	connections  []*WebSocketConnection
	tunnelName   string
	endpointName string
	password     string
	serverAddr   string
	maxSize      int
	activeCount  int
	idleTimeout  time.Duration
	maxLifetime  time.Duration
}

// WebSocketPoolManager 管理所有的WebSocket连接池
type WebSocketPoolManager struct {
	mu             sync.RWMutex
	pools          map[string]*WebSocketPool // key: tunnelName.endpointName
	config         *Config
	statsCollector *StatsCollector
	upgrader       websocket.Upgrader
}

// NewWebSocketPoolManager 创建WebSocket连接池管理器
func NewWebSocketPoolManager(config *Config, statsCollector *StatsCollector) *WebSocketPoolManager {
	return &WebSocketPoolManager{
		pools:          make(map[string]*WebSocketPool),
		config:         config,
		statsCollector: statsCollector,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // 允许所有来源
			},
		},
	}
}

// UpdateTunnels dynamically updates the tunnel list from a new configuration.
func (wspm *WebSocketPoolManager) UpdateTunnels(newConfig *Config) {
	wspm.mu.Lock()
	defer wspm.mu.Unlock()

	log.Println("[WS-POOL] Updating pools based on new configuration...")
	wspm.config = newConfig // 更新配置引用

	newTunnelsMap := make(map[string]bool)
	if newConfig.Tunnels != nil {
		for name := range newConfig.Tunnels {
			newTunnelsMap[name] = true
		}
	}

	// 遍历所有连接池，移除属于已删除隧道的池
	for key, pool := range wspm.pools {
		if !newTunnelsMap[pool.tunnelName] {
			log.Printf("[WS-POOL] Removing pool for tunnel '%s' as it is no longer in the configuration.", pool.tunnelName)
			pool.closeAllConnections()
			delete(wspm.pools, key)
		}
	}
	log.Printf("[WS-POOL] Pools updated. Total pools now: %d", len(wspm.pools))
}

// GetOrCreatePool 获取或创建连接池
func (wspm *WebSocketPoolManager) GetOrCreatePool(tunnelName, endpointName, password, serverAddr string) *WebSocketPool {
	key := fmt.Sprintf("%s.%s", tunnelName, endpointName)

	wspm.mu.RLock()
	if pool, exists := wspm.pools[key]; exists {
		wspm.mu.RUnlock()
		return pool
	}
	wspm.mu.RUnlock()

	wspm.mu.Lock()
	defer wspm.mu.Unlock()

	// 双重检查
	if pool, exists := wspm.pools[key]; exists {
		return pool
	}

	// 获取隧道配置来确定连接池参数
	poolSize := DefaultPoolSize
	idleTimeout := DefaultIdleTimeout
	maxLifetime := DefaultMaxLifetime

	if wspm.config != nil && wspm.config.Tunnels != nil {
		if tunnelConfig, exists := wspm.config.Tunnels[tunnelName]; exists {
			if tunnelConfig.WebSocketPool != nil {
				wsConfig := tunnelConfig.WebSocketPool
				if wsConfig.PoolSize > 0 {
					poolSize = wsConfig.PoolSize
				}
				if wsConfig.IdleTimeout > 0 {
					idleTimeout = time.Duration(wsConfig.IdleTimeout) * time.Second
				}
				if wsConfig.MaxLifetime > 0 {
					maxLifetime = time.Duration(wsConfig.MaxLifetime) * time.Second
				}
			}
		}
	}

	// 创建新连接池
	pool := &WebSocketPool{
		connections:  make([]*WebSocketConnection, 0),
		tunnelName:   tunnelName,
		endpointName: endpointName,
		password:     password,
		serverAddr:   serverAddr,
		maxSize:      poolSize,
		idleTimeout:  idleTimeout,
		maxLifetime:  maxLifetime,
	}

	wspm.pools[key] = pool

	// 启动连接池维护goroutine
	go pool.maintainPool()

	log.Printf("[WS-POOL] Created new pool for %s.%s with size %d, idle timeout %v, max lifetime %v",
		tunnelName, endpointName, poolSize, idleTimeout, maxLifetime)

	return pool
}

// GetConnection 从连接池获取一个可用连接
func (pool *WebSocketPool) GetConnection() (*WebSocketConnection, error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// 查找空闲连接
	for _, conn := range pool.connections {
		conn.mu.Lock()
		if conn.Status == StatusIdle && !conn.inUse {
			conn.inUse = true
			conn.Status = StatusInUse
			conn.LastUsedTime = time.Now()
			conn.mu.Unlock()

			pool.activeCount++
			log.Printf("[WS-POOL] Connection %s acquired from pool %s.%s (active: %d)",
				conn.ID, pool.tunnelName, pool.endpointName, pool.activeCount)
			return conn, nil
		}
		conn.mu.Unlock()
	}

	// 如果没有空闲连接且未达到最大数量，创建新连接
	// 注意：服务端是被动连接，无法主动创建连接
	// 这里只能等待客户端连接，或者返回错误
	// 为了简化，如果没有空闲连接，我们返回错误，让上层重试或等待
	// 实际场景中，客户端应该已经建立了足够的连接

	return nil, fmt.Errorf("no available connections in pool (max: %d, active: %d)", pool.maxSize, pool.activeCount)
}

// ReturnConnection 归还连接到连接池
func (pool *WebSocketPool) ReturnConnection(conn *WebSocketConnection) {
	conn.mu.Lock()
	if conn.Status != StatusInUse {
		conn.mu.Unlock()
		return
	}

	conn.inUse = false
	conn.Status = StatusIdle
	conn.LastUsedTime = time.Now()
	conn.mu.Unlock()

	pool.mu.Lock()
	pool.activeCount--
	log.Printf("[WS-POOL] Connection %s returned to pool %s.%s (active: %d)",
		conn.ID, pool.tunnelName, pool.endpointName, pool.activeCount)
	pool.mu.Unlock()
}

// createConnection 仅作为接口占位，实际连接由客户端发起
func (pool *WebSocketPool) createConnection() (*WebSocketConnection, error) {
	return nil, errors.New("server cannot initiate websocket connections")
}

// closeAllConnections 关闭并清理池中所有连接
func (pool *WebSocketPool) closeAllConnections() {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	log.Printf("[WS-POOL] Closing all connections in pool for %s.%s", pool.tunnelName, pool.endpointName)
	for _, conn := range pool.connections {
		conn.close()
	}
	pool.connections = nil
}

// close 关闭连接
func (conn *WebSocketConnection) close() {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.Status == StatusClosed {
		return
	}

	conn.Status = StatusClosed
	if conn.Conn != nil {
		conn.Conn.Close()
	}
	close(conn.sendCh)
}

// maintainPool 维护连接池，清理过期连接
func (pool *WebSocketPool) maintainPool() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		pool.cleanupExpiredConnections()
	}
}

// cleanupExpiredConnections 清理过期连接
func (pool *WebSocketPool) cleanupExpiredConnections() {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	now := time.Now()
	activeConnections := make([]*WebSocketConnection, 0)

	for _, conn := range pool.connections {
		conn.mu.Lock()
		shouldClose := false

		// 检查是否闲置超时
		if conn.Status == StatusIdle && now.Sub(conn.LastUsedTime) > pool.idleTimeout {
			shouldClose = true
		}

		// 检查是否达到最大生命周期
		if now.Sub(conn.CreatedTime) > pool.maxLifetime {
			shouldClose = true
		}

		// 检查连接是否已关闭
		if conn.Status == StatusClosed {
			shouldClose = true
		}

		if shouldClose {
			log.Printf("[WS-POOL] Closing expired connection %s in pool %s.%s",
				conn.ID, pool.tunnelName, pool.endpointName)
			conn.mu.Unlock()
			conn.close()
		} else {
			activeConnections = append(activeConnections, conn)
			conn.mu.Unlock()
		}
	}

	pool.connections = activeConnections
}

// SendRequest 通过WebSocket连接发送请求
func (pool *WebSocketPool) SendRequest(ctx context.Context, reqPayload *RequestPayload) ([]byte, error) {
	conn, err := pool.GetConnection()
	if err != nil {
		return nil, err
	}
	defer pool.ReturnConnection(conn)

	return conn.SendRequest(ctx, reqPayload, pool.password)
}

// SendRequest 通过单个WebSocket连接发送请求
func (conn *WebSocketConnection) SendRequest(ctx context.Context, reqPayload *RequestPayload, password string) ([]byte, error) {
	if conn.Conn == nil {
		return nil, errors.New("websocket connection not established")
	}

	requestID := generateRequestID()
	respCh := make(chan *pb.Response, 10) // Increased buffer for streaming responses

	conn.mu.Lock()
	conn.pendingRequests[requestID] = respCh
	conn.mu.Unlock()

	defer func() {
		conn.mu.Lock()
		delete(conn.pendingRequests, requestID)
		conn.mu.Unlock()
	}()

	// 加密数据
	encryptedData, err := encrypt(reqPayload.Data, password)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt request: %v", err)
	}

	// 创建Protobuf消息
	msg := &pb.ServerToEndpoint{
		Id: requestID,
		Payload: &pb.ServerToEndpoint_Request{
			Request: &pb.Request{
				Url:  reqPayload.URL,
				Data: encryptedData,
			},
		},
	}

	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		return nil, err
	}

	// 发送二进制消息
	if err := conn.Conn.WriteMessage(websocket.BinaryMessage, msgBytes); err != nil {
		return nil, err
	}

	// 等待流式响应并组装完整数据
	var headerBytes []byte
	var bodyChunks [][]byte

	timeout := time.After(60 * time.Second)
	for {
		select {
		case resp := <-respCh:
			// 检查错误字段（向后兼容）
			if resp.GetError() != "" {
				return nil, errors.New(resp.GetError())
			}

			// 处理流式响应内容
			switch content := resp.Content.(type) {
			case *pb.Response_Header:
				// 解密响应头
				decryptedHeader, err := decrypt(content.Header.GetHeader(), password)
				if err != nil {
					return nil, fmt.Errorf("failed to decrypt response header: %v", err)
				}
				headerBytes = decryptedHeader

			case *pb.Response_Chunk:
				// 解密数据块
				decryptedChunk, err := decrypt(content.Chunk.GetData(), password)
				if err != nil {
					return nil, fmt.Errorf("failed to decrypt response chunk: %v", err)
				}
				bodyChunks = append(bodyChunks, decryptedChunk)

			case *pb.Response_End:
				// 流结束，检查是否有错误
				if content.End.GetError() != "" {
					return nil, errors.New(content.End.GetError())
				}
				// 组装完整响应
				var fullResponse []byte
				fullResponse = append(fullResponse, headerBytes...)
				for _, chunk := range bodyChunks {
					fullResponse = append(fullResponse, chunk...)
				}
				return fullResponse, nil

			case *pb.Response_Error:
				// 直接错误响应
				return nil, errors.New(content.Error)
			}

		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout:
			return nil, errors.New("request timeout")
		}
	}
}

// HandleWebSocketUpgrade 处理WebSocket升级请求
func (wspm *WebSocketPoolManager) HandleWebSocketUpgrade(w http.ResponseWriter, r *http.Request) {
	tunnelName := r.Header.Get("X-Tunnel-Name")
	endpointName := r.Header.Get("X-Endpoint-Name")
	password := r.Header.Get("X-Tunnel-Password")

	if tunnelName == "" || endpointName == "" {
		http.Error(w, "Missing required headers", http.StatusBadRequest)
		return
	}

	// 验证隧道配置
	wspm.mu.RLock()
	config, exists := wspm.config.Tunnels[tunnelName]
	wspm.mu.RUnlock()

	if !exists {
		http.Error(w, "Tunnel not found", http.StatusNotFound)
		return
	}

	if config.Password != "" && config.Password != password {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// 升级连接
	conn, err := wspm.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WS] Failed to upgrade connection: %v", err)
		return
	}

	// 移除WebSocket消息大小限制以支持大文件传输
	conn.SetReadLimit(0)

	// 创建连接对象
	wsConn := &WebSocketConnection{
		ID:              generateRequestID(),
		Conn:            conn,
		TunnelName:      tunnelName,
		EndpointName:    endpointName,
		Status:          StatusIdle,
		CreatedTime:     time.Now(),
		LastUsedTime:    time.Now(),
		sendCh:          make(chan []byte, 256),
		pendingRequests: make(map[string]chan *pb.Response),
	}

	// 获取或创建连接池
	pool := wspm.GetOrCreatePool(tunnelName, endpointName, password, r.Host)

	pool.mu.Lock()
	if len(pool.connections) < pool.maxSize {
		pool.connections = append(pool.connections, wsConn)
		log.Printf("[WS] New WebSocket connection %s added to pool %s.%s",
			wsConn.ID, tunnelName, endpointName)
	} else {
		log.Printf("[WS] Pool %s.%s is full, rejecting connection", tunnelName, endpointName)
		conn.Close()
		pool.mu.Unlock()
		return
	}
	pool.mu.Unlock()

	// 启动连接处理
	go wsConn.handleWebSocketConnection(pool)
}

// handleWebSocketConnection 处理WebSocket连接的消息收发
func (conn *WebSocketConnection) handleWebSocketConnection(pool *WebSocketPool) {
	defer func() {
		conn.close()
		// 从池中移除
		pool.mu.Lock()
		for i, c := range pool.connections {
			if c.ID == conn.ID {
				pool.connections = append(pool.connections[:i], pool.connections[i+1:]...)
				break
			}
		}
		pool.mu.Unlock()
	}()

	conn.Conn.SetReadDeadline(time.Now().Add(PongWait))
	conn.Conn.SetPongHandler(func(string) error {
		conn.Conn.SetReadDeadline(time.Now().Add(PongWait))
		return nil
	})

	for {
		_, message, err := conn.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[WS] Connection %s read error: %v", conn.ID, err)
			}
			break
		}

		// 处理Protobuf消息
		var msg pb.EndpointToServer
		if err := proto.Unmarshal(message, &msg); err != nil {
			log.Printf("[WS] Error unmarshalling protobuf message from connection %s: %v", conn.ID, err)
			continue
		}

		switch payload := msg.Payload.(type) {
		case *pb.EndpointToServer_Response:
			// 处理响应
			resp := payload.Response
			conn.mu.Lock()
			if ch, ok := conn.pendingRequests[resp.Id]; ok {
				ch <- resp
				delete(conn.pendingRequests, resp.Id)
			}
			conn.mu.Unlock()

		case *pb.EndpointToServer_Heartbeat:
			// 处理心跳
			log.Printf("[WS] Received heartbeat from %s", conn.EndpointName)

		case *pb.EndpointToServer_Registration:
			// 处理注册信息（可选，目前已在握手头中处理）
		}
	}
}

// FindTunnelForEndpoint 查找端点所在的隧道
func (wspm *WebSocketPoolManager) FindTunnelForEndpoint(endpointName string) (string, bool) {
	wspm.mu.RLock()
	defer wspm.mu.RUnlock()

	for _, pool := range wspm.pools {
		if pool.endpointName == endpointName {
			pool.mu.RLock()
			hasConnections := len(pool.connections) > 0
			pool.mu.RUnlock()

			if hasConnections {
				return pool.tunnelName, true
			}
		}
	}
	return "", false
}

// GetEndpointsInfo 获取指定隧道的所有端点信息
func (wspm *WebSocketPoolManager) GetEndpointsInfo(tunnelName string) map[string]*EndpointInfo {
	wspm.mu.RLock()
	defer wspm.mu.RUnlock()

	info := make(map[string]*EndpointInfo)

	for _, pool := range wspm.pools {
		if pool.tunnelName == tunnelName {
			pool.mu.RLock()
			if len(pool.connections) > 0 {
				// 使用第一个连接作为代表
				conn := pool.connections[0]
				conn.mu.Lock()

				// 简单的统计信息
				// 注意：目前WebSocket连接没有详细的Metrics统计，这里先传nil
				info[pool.endpointName] = &EndpointInfo{
					Name:             pool.endpointName,
					RemoteAddr:       conn.Conn.RemoteAddr().String(),
					OnlineTime:       conn.CreatedTime,
					LastActivityTime: conn.LastUsedTime,
					Stats:            nil,
				}
				conn.mu.Unlock()
			}
			pool.mu.RUnlock()
		}
	}
	return info
}
