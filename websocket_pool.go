package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// WebSocket连接池配置
	DefaultPoolSize        = 3          // 默认连接池大小
	MaxPoolSize           = 10         // 最大连接池大小
	DefaultIdleTimeout    = 5 * time.Minute // 默认连接闲置超时时间
	DefaultMaxLifetime    = 30 * time.Minute // 默认连接最大生命周期
	PingPeriod            = 30 * time.Second // ping周期
	PongWait              = 60 * time.Second // pong等待时间
)

// WebSocketConnection 表示一个WebSocket连接
type WebSocketConnection struct {
	ID               string
	Conn             *websocket.Conn
	TunnelName       string
	EndpointName     string
	Status           ConnectionStatus
	LastUsedTime     time.Time
	CreatedTime      time.Time
	mu               sync.Mutex
	inUse            bool
	sendCh           chan []byte
	pendingRequests  map[string]chan *WebSocketResponse
}

type ConnectionStatus int

const (
	StatusIdle ConnectionStatus = iota
	StatusInUse
	StatusClosed
)

type WebSocketResponse struct {
	Data  []byte
	Error string
}

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
	mu              sync.RWMutex
	pools           map[string]*WebSocketPool // key: tunnelName.endpointName
	config          *Config
	statsCollector  *StatsCollector
	upgrader        websocket.Upgrader
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
	if len(pool.connections) < pool.maxSize {
		conn, err := pool.createConnection()
		if err != nil {
			return nil, err
		}
		
		conn.inUse = true
		conn.Status = StatusInUse
		conn.LastUsedTime = time.Now()
		pool.activeCount++
		
		log.Printf("[WS-POOL] New connection %s created for pool %s.%s (active: %d)", 
			conn.ID, pool.tunnelName, pool.endpointName, pool.activeCount)
		return conn, nil
	}

	return nil, fmt.Errorf("no available connections in pool")
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

// createConnection 创建新的WebSocket连接
func (pool *WebSocketPool) createConnection() (*WebSocketConnection, error) {
	// 这里应该实现实际的WebSocket连接逻辑
	// 暂时返回一个模拟连接
	conn := &WebSocketConnection{
		ID:              generateWSRequestID(),
		TunnelName:      pool.tunnelName,
		EndpointName:    pool.endpointName,
		Status:          StatusIdle,
		CreatedTime:     time.Now(),
		LastUsedTime:    time.Now(),
		sendCh:          make(chan []byte, 256),
		pendingRequests: make(map[string]chan *WebSocketResponse),
	}

	// 启动连接处理goroutine
	go conn.handleConnection(pool)
	
	return conn, nil
}

// handleConnection 处理WebSocket连接
func (conn *WebSocketConnection) handleConnection(pool *WebSocketPool) {
	// 这里应该实现实际的WebSocket消息处理逻辑
	// 包括ping/pong、消息收发等
	ticker := time.NewTicker(PingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 发送ping
			if conn.Conn != nil {
				conn.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := conn.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					log.Printf("[WS-CONN] Failed to send ping for connection %s: %v", conn.ID, err)
					conn.close()
					return
				}
			}
		}
	}
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
	log.Printf("[WS-POOL] Pool %s.%s cleanup completed, active connections: %d", 
		pool.tunnelName, pool.endpointName, len(pool.connections))
}

// SendRequest 通过WebSocket连接发送请求
func (pool *WebSocketPool) SendRequest(ctx context.Context, data []byte) ([]byte, error) {
	conn, err := pool.GetConnection()
	if err != nil {
		return nil, err
	}
	defer pool.ReturnConnection(conn)

	return conn.SendRequest(ctx, data)
}

// SendRequest 通过单个WebSocket连接发送请求
func (conn *WebSocketConnection) SendRequest(ctx context.Context, data []byte) ([]byte, error) {
	if conn.Conn == nil {
		return nil, errors.New("websocket connection not established")
	}

	requestID := generateWSRequestID()
	respCh := make(chan *WebSocketResponse, 1)

	conn.mu.Lock()
	conn.pendingRequests[requestID] = respCh
	conn.mu.Unlock()

	defer func() {
		conn.mu.Lock()
		delete(conn.pendingRequests, requestID)
		conn.mu.Unlock()
	}()

	// 创建消息 - 使用与现有代码兼容的消息格式
	msg := map[string]interface{}{
		"id":      requestID,
		"type":    "request",
		"payload": data,
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	// 发送消息
	if err := conn.Conn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		return nil, err
	}

	// 等待响应
	select {
	case resp := <-respCh:
		if resp.Error != "" {
			return nil, errors.New(resp.Error)
		}
		return resp.Data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(30 * time.Second):
		return nil, errors.New("request timeout")
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

	// 创建连接对象
	wsConn := &WebSocketConnection{
		ID:              generateWSRequestID(),
		Conn:            conn,
		TunnelName:      tunnelName,
		EndpointName:    endpointName,
		Status:          StatusIdle,
		CreatedTime:     time.Now(),
		LastUsedTime:    time.Now(),
		sendCh:          make(chan []byte, 256),
		pendingRequests: make(map[string]chan *WebSocketResponse),
	}

	// 获取或创建连接池
	pool := wspm.GetOrCreatePool(tunnelName, endpointName, password, r.Host)
	
	pool.mu.Lock()
	if len(pool.connections) < pool.maxSize {
		pool.connections = append(pool.connections, wsConn)
		log.Printf("[WS] New WebSocket connection %s added to pool %s.%s", 
			wsConn.ID, tunnelName, endpointName)
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

		// 处理消息
		var msg map[string]interface{}
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("[WS] Error unmarshalling message from connection %s: %v", conn.ID, err)
			continue
		}

		msgType, ok := msg["type"].(string)
		if !ok {
			continue
		}

		switch msgType {
		case "response":
			// 处理响应
			msgID, _ := msg["id"].(string)
			payload, _ := msg["payload"].(map[string]interface{})
			
			data, _ := payload["data"].([]byte)
			errorStr, _ := payload["error"].(string)

			conn.mu.Lock()
			if ch, ok := conn.pendingRequests[msgID]; ok {
				ch <- &WebSocketResponse{
					Data:  data,
					Error: errorStr,
				}
				delete(conn.pendingRequests, msgID)
			}
			conn.mu.Unlock()
		}
	}
}

// generateWSRequestID 生成WebSocket请求ID
func generateWSRequestID() string {
	b := make([]byte, 16)
	// 使用crypto/rand生成随机数
	if _, err := rand.Read(b); err != nil {
		// 如果随机数生成失败，使用时间戳
		return fmt.Sprintf("ws-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("ws-%x", b)
}