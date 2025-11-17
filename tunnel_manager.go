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
	"time"

	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 30 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 8192
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

	tunnel.RegisterEndpoint(endpointName, conn)

	go conn.writePump()
	go conn.readPump(tunnel)
}

func (c *EndpointConn) readPump(tunnel *Tunnel) {
	defer func() {
		tunnel.UnregisterEndpoint(c.name)
		c.ws.Close()
	}()
	c.ws.SetReadLimit(maxMessageSize)
	c.ws.SetReadDeadline(time.Now().Add(pongWait))
	c.ws.SetPongHandler(func(string) error {
		c.ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

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

			// Only decrypt when data is present and no error is reported
			if len(payload.Data) > 0 && payload.Error == "" {
				decryptedData, err := decrypt(payload.Data, tunnel.password)
				if err != nil {
					log.Printf("[TUNNEL] Error decrypting response from '%s': %v", c.name, err)
					payload.Error = "decryption failed"
					payload.Data = nil
				} else {
					payload.Data = decryptedData
				}
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
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.ws.Close()
	}()
	for {
		select {
		case message, ok := <-c.sendCh:
			c.ws.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The sendCh channel was closed.
				c.ws.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.ws.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued chat messages to the current websocket message.
			n := len(c.sendCh)
			for i := 0; i < n; i++ {
				w.Write(<-c.sendCh)
			}

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// SendRequest sends a request to the endpoint and waits for a response
func (c *EndpointConn) SendRequest(ctx context.Context, reqPayload *RequestPayload, tunnel *Tunnel) ([]byte, error) {
	requestID := generateRequestID()

	// Encrypt the inner data of the payload
	encryptedData, err := encrypt(reqPayload.Data, tunnel.password)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt request: %w", err)
	}

	// Create a new payload for sending, with the original URL and encrypted data
	payloadToSend := RequestPayload{
		URL:  reqPayload.URL,
		Data: encryptedData,
	}

	payloadBytes, _ := json.Marshal(payloadToSend)
	msg, _ := json.Marshal(TunnelMessage{
		ID:      requestID,
		Type:    MessageTypeRequest,
		Payload: payloadBytes,
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
		// Use a non-blocking send to avoid panic on closed channel
		select {
		case c.sendCh <- cancelMsg:
			// Sent successfully
		default:
			log.Printf("[TUNNEL] Failed to send cancellation for request %s to endpoint '%s' (channel closed or full)", requestID, c.name)
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
