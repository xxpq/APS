package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Maximum message size allowed from peer.
	maxMessageSize = 8192

	// Endpoint is considered dead if no ping is received for this duration.
	heartbeatTimeout = 30 * time.Second

	// How often to check for dead endpoints.
	heartbeatCheckInterval = 10 * time.Second
)

// TunnelManager manages all active tunnel connections from endpoints
type TunnelManager struct {
	mu      sync.RWMutex
	tunnels map[string]*Tunnel // tunnelName -> Tunnel
	config  *Config
}

// Tunnel represents a named tunnel with multiple endpoint connections
type Tunnel struct {
	mu        sync.RWMutex
	name      string
	endpoints map[string]*EndpointConn // endpointName -> EndpointConn
	password  string                   // AES key
}

// EndpointConn represents a single WebSocket connection from an endpoint client
type EndpointConn struct {
	ws              *websocket.Conn
	sendCh          chan []byte
	name            string
	mu              sync.Mutex
	pendingRequests map[string]chan *ResponsePayload
	lastPingTime    atomic.Value // Stores time.Time
	latency         time.Duration
}

func NewTunnelManager(config *Config) *TunnelManager {
	tm := &TunnelManager{
		tunnels: make(map[string]*Tunnel),
		config:  config,
	}
	// Initialize tunnels from config
	if config.Tunnels != nil {
		for name, tConfig := range config.Tunnels {
			tm.tunnels[name] = &Tunnel{
				name:      name,
				endpoints: make(map[string]*EndpointConn),
				password:  tConfig.Password,
			}
		}
	}
	return tm
}

// GetTunnelForServer checks if a server is configured as a tunnel endpoint
func (tm *TunnelManager) GetTunnelForServer(serverName string) *Tunnel {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	for tunnelName, tConfig := range tm.config.Tunnels {
		for _, sName := range tConfig.Servers {
			if sName == serverName {
				return tm.tunnels[tunnelName]
			}
		}
	}
	return nil
}

// RegisterEndpoint adds a new endpoint connection to a tunnel
func (t *Tunnel) RegisterEndpoint(endpointName string, conn *EndpointConn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// TODO: Handle existing connection with the same name
	t.endpoints[endpointName] = conn
	log.Printf("[TUNNEL] Endpoint '%s' registered to tunnel '%s'", endpointName, t.name)
}

// UnregisterEndpoint removes an endpoint connection
func (t *Tunnel) UnregisterEndpoint(endpointName string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.endpoints, endpointName)
	log.Printf("[TUNNEL] Endpoint '%s' unregistered from tunnel '%s'", endpointName, t.name)
}

// GetRandomEndpoint selects a random online endpoint from the tunnel
func (t *Tunnel) GetRandomEndpoint() *EndpointConn {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if len(t.endpoints) == 0 {
		return nil
	}

	// Convert map to slice for random selection
	endpoints := make([]*EndpointConn, 0, len(t.endpoints))
	for _, ep := range t.endpoints {
		endpoints = append(endpoints, ep)
	}
	return endpoints[mrand.Intn(len(endpoints))]
}

// FindEndpoint searches for a specific endpoint by name across all tunnels.
func (tm *TunnelManager) FindEndpoint(endpointName string) (*EndpointConn, *Tunnel) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	for _, tunnel := range tm.tunnels {
		tunnel.mu.RLock()
		if ep, exists := tunnel.endpoints[endpointName]; exists {
			tunnel.mu.RUnlock()
			return ep, tunnel
		}
		tunnel.mu.RUnlock()
	}
	return nil, nil
}

// GetRandomEndpointFromTunnel finds a tunnel by name and returns a random endpoint from it.
func (tm *TunnelManager) GetRandomEndpointFromTunnel(tunnelName string) (*EndpointConn, *Tunnel) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	tunnel, exists := tm.tunnels[tunnelName]
	if !exists {
		return nil, nil
	}

	endpoint := tunnel.GetRandomEndpoint()
	if endpoint == nil {
		return nil, nil
	}
	return endpoint, tunnel
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all connections
	},
}

// ServeWs handles websocket requests from the peer.
func (tm *TunnelManager) ServeWs(tunnel *Tunnel, w http.ResponseWriter, r *http.Request) {
	endpointName := r.Header.Get("X-Endpoint-Name")
	if endpointName == "" {
		http.Error(w, "X-Endpoint-Name header is required", http.StatusBadRequest)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[TUNNEL] Upgrade error: %v", err)
		return
	}

	conn := &EndpointConn{
		ws:              ws,
		sendCh:          make(chan []byte, 256),
		name:            endpointName,
		pendingRequests: make(map[string]chan *ResponsePayload),
	}
	conn.lastPingTime.Store(time.Now())

	tunnel.RegisterEndpoint(endpointName, conn)

	go conn.writePump()
	go conn.readPump(tunnel)
	go conn.monitorHeartbeat(tunnel)
}

func (c *EndpointConn) monitorHeartbeat(tunnel *Tunnel) {
	ticker := time.NewTicker(heartbeatCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			lastPing := c.lastPingTime.Load().(time.Time)
			if time.Since(lastPing) > heartbeatTimeout {
				log.Printf("[TUNNEL] Heartbeat timeout for endpoint '%s'. Disconnecting.", c.name)
				c.ws.Close() // This will trigger the readPump to exit and unregister
				return
			}
		// A way to stop this goroutine if the connection is closed from another place
		case <-c.sendCh: // Assuming sendCh is closed when the connection is terminated
			return
		}
	}
}

func (c *EndpointConn) readPump(tunnel *Tunnel) {
	defer func() {
		tunnel.UnregisterEndpoint(c.name)
		close(c.sendCh) // Signal other goroutines to stop
		c.ws.Close()
	}()
	c.ws.SetReadLimit(maxMessageSize)

	for {
		_, message, err := c.ws.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[TUNNEL] Endpoint '%s' read error: %v", c.name, err)
			}
			break
		}

		var msg TunnelMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("[TUNNEL] Error unmarshalling message from '%s': %v", c.name, err)
			continue
		}

		switch msg.Type {
		case MessageTypePing:
			var pingPayload PingPayload
			if err := json.Unmarshal(msg.Payload, &pingPayload); err == nil {
				c.lastPingTime.Store(time.Now())
				c.latency = time.Since(time.Unix(0, pingPayload.Timestamp))

				// Respond with a pong
				pongPayload := PongPayload{Timestamp: pingPayload.Timestamp}
				payloadBytes, _ := json.Marshal(pongPayload)
				pongMsg := TunnelMessage{Type: MessageTypePong, Payload: payloadBytes}
				msgBytes, _ := json.Marshal(pongMsg)
				c.sendCh <- msgBytes
			}

		case MessageTypeResponse:
			var payload ResponsePayload
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				log.Printf("[TUNNEL] Error unmarshalling response payload from '%s': %v", c.name, err)
				c.mu.Lock()
				if ch, ok := c.pendingRequests[msg.ID]; ok {
					ch <- &ResponsePayload{Error: "payload unmarshal error"}
					delete(c.pendingRequests, msg.ID)
				}
				c.mu.Unlock()
				continue
			}

			decryptedData, err := decrypt(payload.Data, tunnel.password)
			if err != nil {
				log.Printf("[TUNNEL] Error decrypting response from '%s': %v", c.name, err)
				payload.Error = "decryption failed"
				payload.Data = nil
			} else {
				payload.Data = decryptedData
			}

			c.mu.Lock()
			if ch, ok := c.pendingRequests[msg.ID]; ok {
				ch <- &payload
				delete(c.pendingRequests, msg.ID)
			}
			c.mu.Unlock()
		}
	}
}

func (c *EndpointConn) writePump() {
	defer func() {
		c.ws.Close()
	}()
	for {
		select {
		case message, ok := <-c.sendCh:
			c.ws.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.ws.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.ws.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			if err := w.Close(); err != nil {
				return
			}
		}
	}
}

// SendRequest sends a request to the endpoint and waits for a response
func (c *EndpointConn) SendRequest(ctx context.Context, reqData []byte, tunnel *Tunnel) ([]byte, error) {
	requestID := generateRequestID()

	encryptedData, err := encrypt(reqData, tunnel.password)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt request: %w", err)
	}

	payload, _ := json.Marshal(RequestPayload{Data: encryptedData})
	msg, _ := json.Marshal(TunnelMessage{
		ID:      requestID,
		Type:    MessageTypeRequest,
		Payload: payload,
	})

	respCh := make(chan *ResponsePayload, 1)
	c.mu.Lock()
	c.pendingRequests[requestID] = respCh
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.pendingRequests, requestID)
		c.mu.Unlock()
	}()

	// Send the request message
	select {
	case c.sendCh <- msg:
		// Successfully sent, now wait for response or cancellation
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(5 * time.Second): // Timeout for sending the message itself
		return nil, errors.New("failed to send request to endpoint channel")
	}

	// Wait for the response
	select {
	case resp := <-respCh:
		if resp.Error != "" {
			return nil, errors.New(resp.Error)
		}
		return resp.Data, nil
	case <-ctx.Done():
		// Context was cancelled (e.g., client timeout), notify the endpoint
		log.Printf("[TUNNEL] Request %s cancelled by client, notifying endpoint '%s'", requestID, c.name)
		cancelMsg, _ := json.Marshal(TunnelMessage{ID: requestID, Type: MessageTypeCancel})
		// Use a select with a short timeout to avoid blocking if the send channel is full
		select {
		case c.sendCh <- cancelMsg:
		case <-time.After(1 * time.Second):
			log.Printf("[TUNNEL] Failed to send cancellation for request %s to endpoint '%s'", requestID, c.name)
		}
		return nil, ctx.Err()
	}
}

func generateRequestID() string {
	b := make([]byte, 16)
	crand.Read(b)
	return fmt.Sprintf("%x", b)
}

// createKey generates a 32-byte key from a password string
func createKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

// encrypt encrypts data using AES-GCM
func encrypt(data []byte, password string) ([]byte, error) {
	if password == "" {
		return data, nil
	}
	key := createKey(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(crand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

// decrypt decrypts data using AES-GCM
func decrypt(data []byte, password string) ([]byte, error) {
	if password == "" {
		return data, nil
	}
	key := createKey(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}