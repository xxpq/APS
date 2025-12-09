package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketClient 管理WebSocket连接
type WebSocketClient struct {
	serverURL      string
	tunnelName     string
	endpointName   string
	tunnelPassword string
	debug          bool
	conn           *websocket.Conn
	sendChan       chan []byte
	receiveChan    chan []byte
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	isConnected    bool
	mu             sync.Mutex
}

// NewWebSocketClient 创建新的WebSocket客户端
func NewWebSocketClient(serverURL, tunnelName, endpointName, tunnelPassword string, debug bool) *WebSocketClient {
	ctx, cancel := context.WithCancel(context.Background())
	return &WebSocketClient{
		serverURL:      serverURL,
		tunnelName:     tunnelName,
		endpointName:   endpointName,
		tunnelPassword: tunnelPassword,
		debug:          debug,
		sendChan:       make(chan []byte, 1000), // 增大缓冲区提高吞吐量
		receiveChan:    make(chan []byte, 1000), // 增大缓冲区提高吞吐量
		ctx:            ctx,
		cancel:         cancel,
	}
}

// Connect 建立WebSocket连接
func (c *WebSocketClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isConnected {
		return nil
	}

	// 构建WebSocket URL
	path := "/.tunnel"
	wsURL := fmt.Sprintf("ws://%s%s", c.serverURL, path)
	if strings.HasPrefix(c.serverURL, "https://") {
		wsURL = fmt.Sprintf("wss://%s%s", strings.TrimPrefix(c.serverURL, "https://"), path)
	} else if strings.HasPrefix(c.serverURL, "http://") {
		wsURL = fmt.Sprintf("ws://%s%s", strings.TrimPrefix(c.serverURL, "http://"), path)
	}

	// 设置请求头
	headers := http.Header{}
	headers.Set("X-Tunnel-Name", c.tunnelName)
	headers.Set("X-Endpoint-Name", c.endpointName)
	headers.Set("X-Tunnel-Password", c.tunnelPassword)
	headers.Set("X-Aps-Tunnel", endpointVersion)

	// 创建WebSocket连接，增大缓冲区以支持大消息
	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		HandshakeTimeout: 10 * time.Second,
		ReadBufferSize:   1024 * 1024, // 1MB
		WriteBufferSize:  1024 * 1024, // 1MB
	}

	conn, _, err := dialer.Dial(wsURL, headers)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket: %v", err)
	}

	// 移除WebSocket消息大小限制以支持大文件传输
	conn.SetReadLimit(0)

	c.conn = conn
	c.isConnected = true

	// 启动读写协程
	c.wg.Add(2)
	go c.readLoop()
	go c.writeLoop()

	if c.debug {
		log.Printf("[DEBUG] WebSocket connection established to %s", wsURL)
	}

	return nil
}

// Disconnect 断开WebSocket连接
func (c *WebSocketClient) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isConnected {
		return
	}

	c.cancel()
	close(c.sendChan)

	if c.conn != nil {
		c.conn.Close()
	}

	c.wg.Wait()
	c.isConnected = false

	if c.debug {
		log.Printf("[DEBUG] WebSocket connection closed")
	}
}

// readLoop 读取WebSocket消息
func (c *WebSocketClient) readLoop() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			_, message, err := c.conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("WebSocket read error: %v", err)
				}
				// Mark connection as disconnected
				c.mu.Lock()
				c.isConnected = false
				c.mu.Unlock()
				return
			}

			if c.debug {
				log.Printf("[DEBUG] Received WebSocket message, length: %d", len(message))
			}

			select {
			case c.receiveChan <- message:
			case <-c.ctx.Done():
				return
			default:
				// 通道满，丢弃消息
				log.Printf("Warning: receive channel full, dropping message")
			}
		}
	}
}

// writeLoop 写入WebSocket消息
func (c *WebSocketClient) writeLoop() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		case message, ok := <-c.sendChan:
			if !ok {
				return
			}

			if err := c.conn.WriteMessage(websocket.BinaryMessage, message); err != nil {
				log.Printf("WebSocket write error: %v", err)
				// Mark connection as disconnected
				c.mu.Lock()
				c.isConnected = false
				c.mu.Unlock()
				return
			}

			if c.debug {
				log.Printf("[DEBUG] Sent WebSocket message, length: %d", len(message))
			}
		}
	}
}

// Send 发送消息
func (c *WebSocketClient) Send(data []byte) error {
	if !c.isConnected {
		return fmt.Errorf("WebSocket not connected")
	}

	select {
	case c.sendChan <- data:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("context cancelled")
	default:
		return fmt.Errorf("send channel full")
	}
}

// Receive 接收消息
func (c *WebSocketClient) Receive() ([]byte, error) {
	select {
	case data := <-c.receiveChan:
		return data, nil
	case <-c.ctx.Done():
		return nil, fmt.Errorf("context cancelled")
	}
}

// IsConnected 返回连接状态
func (c *WebSocketClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isConnected
}
