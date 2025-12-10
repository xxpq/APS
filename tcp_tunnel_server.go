package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// TCPTunnelServer handles TCP connections from endpoints
type TCPTunnelServer struct {
	mu            sync.RWMutex
	listener      net.Listener
	tunnelManager *TCPTunnelManager
	endpoints     map[string]*TCPEndpoint // endpointID -> endpoint
	config        *Config
	running       bool
}

// TCPEndpoint represents an endpoint connected via TCP
type TCPEndpoint struct {
	ID               string
	TunnelName       string
	EndpointName     string
	Conn             *TunnelConn
	RemoteAddr       string
	OnlineTime       time.Time
	LastActivityTime time.Time

	// Pending requests and proxy connections
	mu              sync.Mutex
	pendingRequests map[string]*tcpPendingRequest  // requestID -> pending
	proxyConns      map[string]*tcpProxyConnection // connectionID -> proxy

	// Control channels
	sendChan chan *TunnelMessage
	done     chan struct{}
}

// tcpPendingRequest represents a pending HTTP request
type tcpPendingRequest struct {
	responseChan chan *TunnelMessage
	pipeWriter   *io.PipeWriter
}

// tcpProxyConnection represents an active TCP proxy connection
type tcpProxyConnection struct {
	connectionID string
	clientConn   net.Conn      // Connection from client to APS
	endpoint     *TCPEndpoint  // The endpoint handling this connection
	connectAck   chan error    // Channel to signal connection result
	done         chan struct{} // Channel to signal connection closed
	closed       bool
	mu           sync.Mutex
}

// NewTCPTunnelServer creates a new TCP tunnel server
func NewTCPTunnelServer(config *Config) *TCPTunnelServer {
	return &TCPTunnelServer{
		config:    config,
		endpoints: make(map[string]*TCPEndpoint),
	}
}

// SetTunnelManager sets the tunnel manager (called after manager is created)
func (s *TCPTunnelServer) SetTunnelManager(tm *TCPTunnelManager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tunnelManager = tm
}

// Start starts the TCP tunnel server
func (s *TCPTunnelServer) Start(addr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return errors.New("TCP tunnel server is already running")
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	s.listener = listener
	s.running = true

	log.Printf("[TCP TUNNEL] Server listening on %s", addr)

	go s.acceptLoop()

	return nil
}

// Stop stops the TCP tunnel server
func (s *TCPTunnelServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	s.running = false
	if s.listener != nil {
		s.listener.Close()
	}

	// Close all endpoints
	for _, ep := range s.endpoints {
		ep.Close()
	}
	s.endpoints = make(map[string]*TCPEndpoint)

	log.Println("[TCP TUNNEL] Server stopped")
}

// acceptLoop accepts new connections
func (s *TCPTunnelServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.RLock()
			running := s.running
			s.mu.RUnlock()

			if !running {
				return
			}
			log.Printf("[TCP TUNNEL] Accept error: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

// handleConnection handles a new endpoint connection
func (s *TCPTunnelServer) handleConnection(conn net.Conn) {
	tc := NewTunnelConn(conn)
	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[TCP TUNNEL] New connection from %s", remoteAddr)

	// Set read deadline for registration
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Read first message - must be registration
	msg, err := tc.ReadMessage()
	if err != nil {
		log.Printf("[TCP TUNNEL] Failed to read registration from %s: %v", remoteAddr, err)
		tc.Close()
		return
	}

	if msg.Type != MsgTypeRegister {
		log.Printf("[TCP TUNNEL] Expected registration message, got type %d from %s", msg.Type, remoteAddr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "first message must be registration",
		})
		tc.Close()
		return
	}

	// Parse registration
	var reg RegisterPayload
	if err := msg.ParseJSON(&reg); err != nil {
		log.Printf("[TCP TUNNEL] Invalid registration payload from %s: %v", remoteAddr, err)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "invalid registration payload",
		})
		tc.Close()
		return
	}

	// Validate tunnel and password
	s.mu.RLock()
	tunnelConfig, exists := s.config.Tunnels[reg.TunnelName]
	s.mu.RUnlock()

	if !exists {
		log.Printf("[TCP TUNNEL] Tunnel '%s' not found from %s", reg.TunnelName, remoteAddr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "tunnel not found",
		})
		tc.Close()
		return
	}

	if tunnelConfig.Password != "" && tunnelConfig.Password != reg.Password {
		log.Printf("[TCP TUNNEL] Invalid password for tunnel '%s' from %s", reg.TunnelName, remoteAddr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "invalid password",
		})
		tc.Close()
		return
	}

	// Clear read deadline after successful registration
	conn.SetReadDeadline(time.Time{})

	// Create endpoint
	endpoint := &TCPEndpoint{
		ID:               generateRequestID(),
		TunnelName:       reg.TunnelName,
		EndpointName:     reg.EndpointName,
		Conn:             tc,
		RemoteAddr:       remoteAddr,
		OnlineTime:       time.Now(),
		LastActivityTime: time.Now(),
		pendingRequests:  make(map[string]*tcpPendingRequest),
		proxyConns:       make(map[string]*tcpProxyConnection),
		sendChan:         make(chan *TunnelMessage, 100),
		done:             make(chan struct{}),
	}

	// Register endpoint
	s.mu.Lock()
	s.endpoints[endpoint.ID] = endpoint
	s.mu.Unlock()

	// Send registration acknowledgement
	if err := tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{Success: true}); err != nil {
		log.Printf("[TCP TUNNEL] Failed to send registration ack to %s: %v", remoteAddr, err)
		tc.Close()
		s.unregisterEndpoint(endpoint.ID)
		return
	}

	log.Printf("[TCP TUNNEL] Endpoint '%s' connected to tunnel '%s' (ID: %s)",
		reg.EndpointName, reg.TunnelName, endpoint.ID)

	// Notify tunnel manager
	if s.tunnelManager != nil {
		s.tunnelManager.RegisterEndpoint(endpoint)
	}

	// Start goroutines for read/write
	go endpoint.writeLoop()
	go endpoint.readLoop(s)

	// Wait for endpoint to disconnect
	<-endpoint.done

	log.Printf("[TCP TUNNEL] Endpoint '%s' disconnected (ID: %s)", reg.EndpointName, endpoint.ID)
	s.unregisterEndpoint(endpoint.ID)
}

// unregisterEndpoint removes an endpoint
func (s *TCPTunnelServer) unregisterEndpoint(endpointID string) {
	s.mu.Lock()
	endpoint, exists := s.endpoints[endpointID]
	if exists {
		delete(s.endpoints, endpointID)
	}
	s.mu.Unlock()

	if exists && s.tunnelManager != nil {
		s.tunnelManager.UnregisterEndpoint(endpoint)
	}
}

// GetEndpoint returns an endpoint by ID
func (s *TCPTunnelServer) GetEndpoint(endpointID string) (*TCPEndpoint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ep, ok := s.endpoints[endpointID]
	return ep, ok
}

// ---- TCPEndpoint methods ----

// Send queues a message to be sent to the endpoint
func (ep *TCPEndpoint) Send(msg *TunnelMessage) error {
	select {
	case ep.sendChan <- msg:
		return nil
	case <-ep.done:
		return errors.New("endpoint closed")
	default:
		return errors.New("send channel full")
	}
}

// SendJSON sends a JSON message to the endpoint
func (ep *TCPEndpoint) SendJSON(msgType uint8, data interface{}) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return ep.Send(&TunnelMessage{Type: msgType, Payload: payload})
}

// Close closes the endpoint connection
func (ep *TCPEndpoint) Close() {
	select {
	case <-ep.done:
		return // Already closed
	default:
		close(ep.done)
	}

	ep.Conn.Close()

	// Close all pending requests
	ep.mu.Lock()
	for _, pr := range ep.pendingRequests {
		if pr.pipeWriter != nil {
			pr.pipeWriter.CloseWithError(errors.New("endpoint disconnected"))
		}
		close(pr.responseChan)
	}
	ep.pendingRequests = make(map[string]*tcpPendingRequest)

	// Close all proxy connections
	for _, pc := range ep.proxyConns {
		pc.mu.Lock()
		if !pc.closed {
			pc.closed = true
			close(pc.done)
			if pc.clientConn != nil {
				pc.clientConn.Close()
			}
		}
		pc.mu.Unlock()
	}
	ep.proxyConns = make(map[string]*tcpProxyConnection)
	ep.mu.Unlock()
}

// writeLoop sends messages to the endpoint
func (ep *TCPEndpoint) writeLoop() {
	heartbeatTicker := time.NewTicker(30 * time.Second)
	defer heartbeatTicker.Stop()

	for {
		select {
		case msg := <-ep.sendChan:
			if err := ep.Conn.WriteMessage(msg); err != nil {
				log.Printf("[TCP TUNNEL] Write error to endpoint %s: %v", ep.ID, err)
				ep.Close()
				return
			}
		case <-heartbeatTicker.C:
			// Send heartbeat
			ep.Conn.SendJSON(MsgTypeHeartbeat, HeartbeatPayload{Timestamp: time.Now().UnixNano()})
		case <-ep.done:
			return
		}
	}
}

// readLoop reads messages from the endpoint
func (ep *TCPEndpoint) readLoop(server *TCPTunnelServer) {
	defer ep.Close()

	for {
		// Set read deadline to detect dead connections
		// Client sends heartbeat every 30s, so 90s timeout is generous
		ep.Conn.UnderlyingConn().SetReadDeadline(time.Now().Add(90 * time.Second))
		msg, err := ep.Conn.ReadMessage()
		if err != nil {
			if err != io.EOF {
				log.Printf("[TCP TUNNEL] Read error from endpoint %s: %v", ep.ID, err)
			}
			return
		}

		ep.mu.Lock()
		ep.LastActivityTime = time.Now()
		ep.mu.Unlock()

		// Handle message based on type
		switch msg.Type {
		case MsgTypeHeartbeat:
			// Heartbeat response - do nothing
		case MsgTypeResponseHeader, MsgTypeResponseChunk, MsgTypeResponseEnd:
			ep.handleResponseMessage(msg)
		case MsgTypeProxyConnectAck:
			ep.handleProxyConnectAck(msg)
		case MsgTypeProxyData:
			ep.handleProxyData(msg)
		case MsgTypeProxyClose:
			ep.handleProxyClose(msg)
		default:
			log.Printf("[TCP TUNNEL] Unknown message type %d from endpoint %s", msg.Type, ep.ID)
		}
	}
}

// handleResponseMessage handles response messages
func (ep *TCPEndpoint) handleResponseMessage(msg *TunnelMessage) {
	log.Printf("[TCP TUNNEL] Endpoint %s received response message type %d", ep.ID, msg.Type)

	// Parse based on message type
	var requestID string
	switch msg.Type {
	case MsgTypeResponseHeader:
		var payload ResponseHeaderPayloadTCP
		if err := msg.ParseJSON(&payload); err != nil {
			log.Printf("[TCP TUNNEL] Invalid response header: %v", err)
			return
		}
		requestID = payload.ID
	case MsgTypeResponseChunk:
		var payload ResponseChunkPayloadTCP
		if err := msg.ParseJSON(&payload); err != nil {
			log.Printf("[TCP TUNNEL] Invalid response chunk: %v", err)
			return
		}
		requestID = payload.ID
	case MsgTypeResponseEnd:
		var payload ResponseEndPayloadTCP
		if err := msg.ParseJSON(&payload); err != nil {
			log.Printf("[TCP TUNNEL] Invalid response end: %v", err)
			return
		}
		requestID = payload.ID
	}

	log.Printf("[TCP TUNNEL] Routing response message type %d for request %s", msg.Type, requestID)

	ep.mu.Lock()
	pending, ok := ep.pendingRequests[requestID]
	ep.mu.Unlock()

	if !ok {
		log.Printf("[TCP TUNNEL] WARNING: No pending request found for %s, message dropped", requestID)
		return
	}

	select {
	case pending.responseChan <- msg:
		log.Printf("[TCP TUNNEL] Successfully routed message type %d for request %s", msg.Type, requestID)
	default:
		log.Printf("[TCP TUNNEL] Response channel full for request %s", requestID)
	}
}

// handleProxyConnectAck handles proxy connection acknowledgement
func (ep *TCPEndpoint) handleProxyConnectAck(msg *TunnelMessage) {
	var payload ProxyConnectAckPayload
	if err := msg.ParseJSON(&payload); err != nil {
		log.Printf("[TCP TUNNEL] Invalid proxy connect ack: %v", err)
		return
	}

	ep.mu.Lock()
	pc, ok := ep.proxyConns[payload.ConnectionID]
	ep.mu.Unlock()

	if !ok {
		log.Printf("[TCP TUNNEL] Proxy connection %s not found for ack", payload.ConnectionID)
		return
	}

	if payload.Success {
		log.Printf("[TCP TUNNEL] Proxy connection %s established", payload.ConnectionID)
		select {
		case pc.connectAck <- nil:
		default:
		}
	} else {
		log.Printf("[TCP TUNNEL] Proxy connection %s failed: %s", payload.ConnectionID, payload.Error)
		select {
		case pc.connectAck <- errors.New(payload.Error):
		default:
		}
	}
}

// handleProxyData handles proxy data from endpoint
func (ep *TCPEndpoint) handleProxyData(msg *TunnelMessage) {
	var payload ProxyDataPayload
	if err := msg.ParseJSON(&payload); err != nil {
		log.Printf("[TCP TUNNEL] Invalid proxy data: %v", err)
		return
	}

	ep.mu.Lock()
	pc, ok := ep.proxyConns[payload.ConnectionID]
	ep.mu.Unlock()

	if !ok {
		return
	}

	pc.mu.Lock()
	closed := pc.closed
	pc.mu.Unlock()

	if closed {
		return
	}

	// Write data to client connection
	if _, err := pc.clientConn.Write(payload.Data); err != nil {
		log.Printf("[TCP TUNNEL] Write to client error for proxy %s: %v", payload.ConnectionID, err)
		ep.closeProxyConnection(payload.ConnectionID, "write error")
	}
}

// handleProxyClose handles proxy close from endpoint
func (ep *TCPEndpoint) handleProxyClose(msg *TunnelMessage) {
	var payload ProxyClosePayload
	if err := msg.ParseJSON(&payload); err != nil {
		log.Printf("[TCP TUNNEL] Invalid proxy close: %v", err)
		return
	}

	log.Printf("[TCP TUNNEL] Received proxy close for %s: %s", payload.ConnectionID, payload.Reason)
	ep.closeProxyConnection(payload.ConnectionID, payload.Reason)
}

// closeProxyConnection closes a proxy connection
func (ep *TCPEndpoint) closeProxyConnection(connectionID, reason string) {
	ep.mu.Lock()
	pc, ok := ep.proxyConns[connectionID]
	if ok {
		delete(ep.proxyConns, connectionID)
	}
	ep.mu.Unlock()

	if ok && pc != nil {
		pc.mu.Lock()
		if !pc.closed {
			pc.closed = true
			close(pc.done)
		}
		pc.mu.Unlock()

		if pc.clientConn != nil {
			pc.clientConn.Close()
		}
	}
}

// CreateProxyConnection creates a new proxy connection through this endpoint
func (ep *TCPEndpoint) CreateProxyConnection(ctx context.Context, host string, port int, useTLS bool, clientConn net.Conn, clientIP string) (<-chan struct{}, error) {
	connectionID := generateRequestID()

	pc := &tcpProxyConnection{
		connectionID: connectionID,
		clientConn:   clientConn,
		endpoint:     ep,
		connectAck:   make(chan error, 1),
		done:         make(chan struct{}),
		closed:       false,
	}

	ep.mu.Lock()
	ep.proxyConns[connectionID] = pc
	ep.mu.Unlock()

	// Send proxy connect request
	if err := ep.SendJSON(MsgTypeProxyConnect, ProxyConnectPayload{
		ConnectionID: connectionID,
		Host:         host,
		Port:         port,
		TLS:          useTLS,
		ClientIP:     clientIP,
	}); err != nil {
		ep.closeProxyConnection(connectionID, "send error")
		return nil, err
	}

	// Wait for connection acknowledgement
	select {
	case err := <-pc.connectAck:
		if err != nil {
			ep.closeProxyConnection(connectionID, "connect failed")
			return nil, err
		}
	case <-ctx.Done():
		ep.closeProxyConnection(connectionID, "context cancelled")
		return nil, ctx.Err()
	case <-time.After(30 * time.Second):
		ep.closeProxyConnection(connectionID, "connect timeout")
		return nil, errors.New("proxy connect timeout")
	}

	// Start reading from client and forwarding to endpoint
	go ep.proxyClientReadLoop(connectionID, pc)

	return pc.done, nil
}

func generateRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// proxyClientReadLoop reads data from client and sends to endpoint
func (ep *TCPEndpoint) proxyClientReadLoop(connectionID string, pc *tcpProxyConnection) {
	defer func() {
		log.Printf("[TCP TUNNEL] Proxy client read loop ended for %s", connectionID)

		// Send close to endpoint
		ep.SendJSON(MsgTypeProxyClose, ProxyClosePayload{
			ConnectionID: connectionID,
			Reason:       "client connection closed",
		})

		ep.closeProxyConnection(connectionID, "client closed")
	}()

	buf := make([]byte, 32*1024)
	for {
		pc.mu.Lock()
		closed := pc.closed
		pc.mu.Unlock()
		if closed {
			return
		}

		n, err := pc.clientConn.Read(buf)
		if n > 0 {
			// Send data to endpoint
			if err := ep.SendJSON(MsgTypeProxyData, ProxyDataPayload{
				ConnectionID: connectionID,
				Data:         buf[:n],
			}); err != nil {
				log.Printf("[TCP TUNNEL] Send to endpoint error for proxy %s: %v", connectionID, err)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[TCP TUNNEL] Client read error for proxy %s: %v", connectionID, err)
			}
			return
		}
	}
}
