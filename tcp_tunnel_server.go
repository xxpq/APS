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

	"github.com/xtaci/smux"
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

	// Session key manager for dynamic encryption
	KeyManager *SessionKeyManager

	// Pending requests and proxy connections
	mu              sync.Mutex
	pendingRequests map[string]*tcpPendingRequest  // requestID -> pending
	proxyConns      map[string]*tcpProxyConnection // connectionID -> proxy

	// Control channels
	sendChan  chan *TunnelMessage
	done      chan struct{}
	closeOnce sync.Once // Ensures done channel is closed only once
	session   *smux.Session
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

	DebugLog("[TCP TUNNEL] Server listening on %s", addr)

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
			DebugLog("[TCP TUNNEL] Accept error: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

// handleConnection handles a new endpoint connection
func (s *TCPTunnelServer) handleConnection(conn net.Conn) {
	// Optimize TCP connection for better throughput
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetReadBuffer(256 * 1024)  // 256KB
		tcpConn.SetWriteBuffer(256 * 1024) // 256KB
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(60 * time.Second)
	}

	tc := NewTunnelConn(conn)
	remoteAddr := conn.RemoteAddr().String()
	DebugLog("[TCP TUNNEL] New connection from %s", remoteAddr)

	// Set read deadline for registration
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Read first message - must be registration
	msg, err := tc.ReadMessage()
	if err != nil {
		DebugLog("[TCP TUNNEL] Failed to read registration from %s: %v", remoteAddr, err)
		tc.Close()
		return
	}

	if msg.Type != MsgTypeRegister {
		DebugLog("[TCP TUNNEL] Expected registration message, got type %d from %s", msg.Type, remoteAddr)
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
		DebugLog("[TCP TUNNEL] Invalid registration payload from %s: %v", remoteAddr, err)
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
		DebugLog("[TCP TUNNEL] Tunnel '%s' not found from %s", reg.TunnelName, remoteAddr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "tunnel not found",
		})
		tc.Close()
		return
	}

	if tunnelConfig.Password != "" && tunnelConfig.Password != reg.Password {
		DebugLog("[TCP TUNNEL] Invalid password for tunnel '%s' from %s", reg.TunnelName, remoteAddr)
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
		sendChan:         make(chan *TunnelMessage, 1000), // Increased from 100 to 1000
		done:             make(chan struct{}),
	}

	// Initialize per-connection session key manager
	endpoint.KeyManager = NewSessionKeyManager(reg.Password, reg.EndpointName)
	if err := endpoint.KeyManager.DeriveInitialKey(); err != nil {
		DebugLog("[TCP TUNNEL] Failed to derive initial key for %s: %v", remoteAddr, err)
		tc.Close()
		return
	}

	// Register endpoint
	s.mu.Lock()
	s.endpoints[endpoint.ID] = endpoint
	s.mu.Unlock()

	// Send registration acknowledgement
	if err := tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{Success: true}); err != nil {
		DebugLog("[TCP TUNNEL] Failed to send registration ack to %s: %v", remoteAddr, err)
		tc.Close()
		s.unregisterEndpoint(endpoint.ID)
		return
	}

	DebugLog("[TCP TUNNEL] Endpoint '%s' connected to tunnel '%s' (ID: %s)",
		reg.EndpointName, reg.TunnelName, endpoint.ID)

	// Upgrade to SMUX
	// Server side acts as SMUX server
	session, err := smux.Server(conn, nil)
	if err != nil {
		DebugLog("[TCP TUNNEL] Failed to create SMUX server for %s: %v", remoteAddr, err)
		tc.Close()
		s.unregisterEndpoint(endpoint.ID)
		return
	}
	endpoint.session = session

	// Accept the first stream for control channel
	controlStream, err := session.AcceptStream()
	if err != nil {
		DebugLog("[TCP TUNNEL] Failed to accept control stream from %s: %v", remoteAddr, err)
		session.Close()
		s.unregisterEndpoint(endpoint.ID)
		return
	}
	DebugLog("[TCP TUNNEL] Control stream established for %s", endpoint.ID)

	// Replace the connection in TunnelConn with the control stream
	// Note: We need to create a new TunnelConn or update the existing one
	// Since TunnelConn is just a wrapper, we can create a new one for the control stream
	// But we need to be careful about the initial tc which wrapped the raw conn.
	// The raw conn is now owned by SMUX.
	// We should update endpoint.Conn to use the control stream.
	endpoint.Conn = NewTunnelConn(controlStream)

	// Notify tunnel manager
	if s.tunnelManager != nil {
		s.tunnelManager.RegisterEndpoint(endpoint)
	}

	// Start goroutines for read/write
	go endpoint.writeLoop()
	go endpoint.readLoop(s)

	// Send mirror addresses if configured (non-blocking)
	go sendMirrorUpdate(s, endpoint)

	// Start auto key rotation (APS initiates first key negotiation after a delay)
	go func() {
		time.Sleep(5 * time.Second) // Wait for connection to stabilize
		endpoint.initiateKeyRotation()
		endpoint.KeyManager.StartAutoRotation(func() error {
			return endpoint.initiateKeyRotation()
		})
	}()

	// Wait for endpoint to disconnect
	<-endpoint.done

	DebugLog("[TCP TUNNEL] Endpoint '%s' disconnected (ID: %s)", reg.EndpointName, endpoint.ID)
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
	// First try non-blocking send
	select {
	case ep.sendChan <- msg:
		return nil
	case <-ep.done:
		return errors.New("endpoint closed")
	default:
		// Channel is full, try with timeout to implement backpressure
		select {
		case ep.sendChan <- msg:
			return nil
		case <-ep.done:
			return errors.New("endpoint closed")
		case <-time.After(5 * time.Second):
			// Still full after timeout - this indicates serious congestion
			DebugLog("[TCP TUNNEL] Send channel timeout for endpoint %s (possible congestion)", ep.ID)
			return errors.New("send timeout - channel congestion")
		}
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
	// Use sync.Once to ensure done channel is closed exactly once
	ep.closeOnce.Do(func() {
		close(ep.done)
	})

	ep.Conn.Close()
	if ep.session != nil {
		ep.session.Close()
	}

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
				DebugLog("[TCP TUNNEL] Write error to endpoint %s: %v", ep.ID, err)
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
		// Client sends heartbeat every 30s, use 120s for large transfers
		ep.Conn.UnderlyingConn().SetReadDeadline(time.Now().Add(120 * time.Second))
		msg, err := ep.Conn.ReadMessage()
		if err != nil {
			if err != io.EOF {
				DebugLog("[TCP TUNNEL] Read error from endpoint %s: %v", ep.ID, err)
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
		case MsgTypeProxyDataBinary:
			ep.handleTCPProxyDataBinary(msg)
		case MsgTypeProxyClose:
			ep.handleProxyClose(msg)
		case MsgTypePortForwardRequest:
			ep.handlePortForwardRequest(server, msg)
		case MsgTypePortForwardData:
			ep.handlePortForwardDataRoute(server, msg)
		case MsgTypePortForwardClose:
			ep.handlePortForwardCloseRoute(server, msg)
		case MsgTypeKeyRequest:
			ep.handleKeyRequest(msg)
		case MsgTypeKeyResponse:
			ep.handleKeyResponse(msg)
		case MsgTypeKeyConfirm:
			ep.handleKeyConfirm(msg)
		default:
			DebugLog("[TCP TUNNEL] Unknown message type %d from endpoint %s", msg.Type, ep.ID)
		}
	}
}

// handleResponseMessage handles response messages
func (ep *TCPEndpoint) handleResponseMessage(msg *TunnelMessage) {
	DebugLog("[TCP TUNNEL] Endpoint %s received response message type %d", ep.ID, msg.Type)

	// Parse based on message type
	var requestID string
	switch msg.Type {
	case MsgTypeResponseHeader:
		var payload ResponseHeaderPayloadTCP
		if err := msg.ParseJSON(&payload); err != nil {
			DebugLog("[TCP TUNNEL] Invalid response header: %v", err)
			return
		}
		requestID = payload.ID
	case MsgTypeResponseChunk:
		var payload ResponseChunkPayloadTCP
		if err := msg.ParseJSON(&payload); err != nil {
			DebugLog("[TCP TUNNEL] Invalid response chunk: %v", err)
			return
		}
		requestID = payload.ID
	case MsgTypeResponseEnd:
		var payload ResponseEndPayloadTCP
		if err := msg.ParseJSON(&payload); err != nil {
			DebugLog("[TCP TUNNEL] Invalid response end: %v", err)
			return
		}
		requestID = payload.ID
	}

	DebugLog("[TCP TUNNEL] Routing response message type %d for request %s", msg.Type, requestID)

	ep.mu.Lock()
	pending, ok := ep.pendingRequests[requestID]
	ep.mu.Unlock()

	if !ok {
		DebugLog("[TCP TUNNEL] WARNING: No pending request found for %s, message dropped", requestID)
		return
	}

	defer func() {
		if r := recover(); r != nil {
			DebugLog("[TCP TUNNEL] Recovered from panic in handleResponseMessage (likely closed channel): %v", r)
		}
	}()

	select {
	case pending.responseChan <- msg:
		DebugLog("[TCP TUNNEL] Successfully routed message type %d for request %s", msg.Type, requestID)
	default:
		DebugLog("[TCP TUNNEL] Response channel full for request %s", requestID)
	}
}

// handleProxyConnectAck handles proxy connection acknowledgement
func (ep *TCPEndpoint) handleProxyConnectAck(msg *TunnelMessage) {
	var payload ProxyConnectAckPayload
	if err := msg.ParseJSON(&payload); err != nil {
		DebugLog("[TCP TUNNEL] Invalid proxy connect ack: %v", err)
		return
	}

	ep.mu.Lock()
	pc, ok := ep.proxyConns[payload.ConnectionID]
	ep.mu.Unlock()

	if !ok {
		DebugLog("[TCP TUNNEL] Proxy connection %s not found for ack", payload.ConnectionID)
		return
	}

	if payload.Success {
		DebugLog("[TCP TUNNEL] Proxy connection %s established", payload.ConnectionID)
		select {
		case pc.connectAck <- nil:
		default:
		}
	} else {
		DebugLog("[TCP TUNNEL] Proxy connection %s failed: %s", payload.ConnectionID, payload.Error)
		select {
		case pc.connectAck <- errors.New(payload.Error):
		default:
		}
	}
}

// handleProxyData removed (legacy JSON format)

// handleProxyClose handles proxy close from endpoint
func (ep *TCPEndpoint) handleProxyClose(msg *TunnelMessage) {
	var payload ProxyClosePayload
	if err := msg.ParseJSON(&payload); err != nil {
		DebugLog("[TCP TUNNEL] Invalid proxy close: %v", err)
		return
	}

	DebugLog("[TCP TUNNEL] Received proxy close for %s: %s", payload.ConnectionID, payload.Reason)
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

	// Open a new stream for this proxy connection
	stream, err := ep.session.OpenStream()
	if err != nil {
		ep.closeProxyConnection(connectionID, "open stream failed")
		return nil, err
	}

	// Send proxy connect request on the new stream
	// We use a temporary TunnelConn wrapper to send the JSON payload
	streamConn := NewTunnelConn(stream)
	if err := streamConn.SendJSON(MsgTypeProxyConnect, ProxyConnectPayload{
		ConnectionID: connectionID,
		Host:         host,
		Port:         port,
		TLS:          useTLS,
		ClientIP:     clientIP,
	}); err != nil {
		stream.Close()
		ep.closeProxyConnection(connectionID, "send error")
		return nil, err
	}

	// Wait for connection acknowledgement (on the control channel? No, usually on the same stream if possible,
	// but our protocol sends Acks on the control channel.
	// The client will receive the request on the new stream, connect to backend, and send Ack on the control channel.
	// So we still wait for Ack here.

	select {
	case err := <-pc.connectAck:
		if err != nil {
			stream.Close()
			ep.closeProxyConnection(connectionID, "connect failed")
			return nil, err
		}
	case <-ctx.Done():
		stream.Close()
		ep.closeProxyConnection(connectionID, "context cancelled")
		return nil, ctx.Err()
	case <-time.After(30 * time.Second):
		stream.Close()
		ep.closeProxyConnection(connectionID, "connect timeout")
		return nil, errors.New("proxy connect timeout")
	}

	// Start bidirectional copy
	// No need to switch mode or hijack, just copy between clientConn and stream
	go func() {
		defer func() {
			// Close stream when copy is done
			stream.Close()
			// Don't close endpoint, just this proxy connection
			clientConn.Close()
			ep.closeProxyConnection(connectionID, "stream ended")
		}()

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			io.Copy(stream, clientConn)
		}()

		go func() {
			defer wg.Done()
			io.Copy(clientConn, stream)
		}()

		wg.Wait()
	}()

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
		DebugLog("[TCP TUNNEL] Proxy client read loop ended for %s", connectionID)

		// Send close to endpoint
		ep.SendJSON(MsgTypeProxyClose, ProxyClosePayload{
			ConnectionID: connectionID,
			Reason:       "client connection closed",
		})

		ep.closeProxyConnection(connectionID, "client closed")
	}()

	buf := GetMediumBuffer()
	defer PutMediumBuffer(buf)
	for {
		pc.mu.Lock()
		closed := pc.closed
		pc.mu.Unlock()
		if closed {
			return
		}

		n, err := pc.clientConn.Read(buf)
		if n > 0 {
			// Send data to endpoint using binary format
			// Format: [ID Length (1 byte)] + [Connection ID] + [Data]
			connIDBytes := []byte(connectionID)
			payload := make([]byte, 1+len(connIDBytes)+n)
			payload[0] = uint8(len(connIDBytes))
			copy(payload[1:], connIDBytes)
			copy(payload[1+len(connIDBytes):], buf[:n])

			if err := ep.Send(&TunnelMessage{
				Type:    MsgTypeProxyDataBinary,
				Payload: payload,
			}); err != nil {
				DebugLog("[TCP TUNNEL] Send to endpoint error for proxy %s: %v", connectionID, err)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				DebugLog("[TCP TUNNEL] Client read error for proxy %s: %v", connectionID, err)
			}
			return
		}
	}
}

// handleTCPProxyDataBinary handles proxy data in binary format
func (ep *TCPEndpoint) handleTCPProxyDataBinary(msg *TunnelMessage) {
	if len(msg.Payload) < 1 {
		return
	}

	idLen := int(msg.Payload[0])
	if len(msg.Payload) < 1+idLen {
		return
	}

	connectionID := string(msg.Payload[1 : 1+idLen])
	data := msg.Payload[1+idLen:]

	ep.mu.Lock()
	pc, ok := ep.proxyConns[connectionID]
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
	if _, err := pc.clientConn.Write(data); err != nil {
		DebugLog("[TCP TUNNEL] Write to client error for proxy %s: %v", connectionID, err)
		ep.closeProxyConnection(connectionID, "write error")
	}
}

// Port forward payload types (must match endpoint side)
type PortForwardRequestPayload struct {
	ConnectionID   string `json:"connection_id"`
	TargetEndpoint string `json:"target_endpoint"` // Which endpoint to forward to
	RemoteTarget   string `json:"remote_target"`   // IP:Port on target endpoint's network
	ClientIP       string `json:"client_ip"`       // Original client IP
}

type PortForwardResponsePayload struct {
	ConnectionID string `json:"connection_id"`
	Success      bool   `json:"success"`
	Error        string `json:"error,omitempty"`
}

type PortForwardDataPayload struct {
	ConnectionID string `json:"connection_id"`
	Data         []byte `json:"data"`
}

type PortForwardClosePayload struct {
	ConnectionID string `json:"connection_id"`
	Reason       string `json:"reason,omitempty"`
}

// handlePortForwardRequest handles a port forward request from an endpoint
// Routes the request to the target endpoint
func (ep *TCPEndpoint) handlePortForwardRequest(server *TCPTunnelServer, msg *TunnelMessage) {
	var payload PortForwardRequestPayload
	if err := msg.ParseJSON(&payload); err != nil {
		DebugLog("[TCP TUNNEL] Invalid port forward request: %v", err)
		return
	}

	DebugLog("[PORT-FWD] Request from %s to endpoint %s -> %s",
		ep.EndpointName, payload.TargetEndpoint, payload.RemoteTarget)

	// Find the target endpoint in the same tunnel
	var targetEp *TCPEndpoint
	server.mu.RLock()
	for _, endpoint := range server.endpoints {
		if endpoint.TunnelName == ep.TunnelName &&
			endpoint.EndpointName == payload.TargetEndpoint {
			targetEp = endpoint
			break
		}
	}
	server.mu.RUnlock()

	if targetEp == nil {
		DebugLog("[PORT-FWD] Target endpoint %s not found in tunnel %s",
			payload.TargetEndpoint, ep.TunnelName)
		ep.SendJSON(MsgTypePortForwardResponse, PortForwardResponsePayload{
			ConnectionID: payload.ConnectionID,
			Success:      false,
			Error:        "target endpoint not found",
		})
		return
	}

	// Forward the request to the target endpoint (msg type changes for target)
	// Target endpoint will connect to RemoteTarget and send response
	if err := targetEp.SendJSON(MsgTypePortForwardRequest, payload); err != nil {
		DebugLog("[PORT-FWD] Failed to forward request to %s: %v",
			payload.TargetEndpoint, err)
		ep.SendJSON(MsgTypePortForwardResponse, PortForwardResponsePayload{
			ConnectionID: payload.ConnectionID,
			Success:      false,
			Error:        "failed to reach target endpoint",
		})
		return
	}

	DebugLog("[PORT-FWD] Request forwarded to %s for connection %s",
		payload.TargetEndpoint, payload.ConnectionID)
}

// handlePortForwardDataRoute routes port forward data between endpoints
func (ep *TCPEndpoint) handlePortForwardDataRoute(server *TCPTunnelServer, msg *TunnelMessage) {
	var payload PortForwardDataPayload
	if err := msg.ParseJSON(&payload); err != nil {
		DebugLog("[TCP TUNNEL] Invalid port forward data: %v", err)
		return
	}

	// Route data to the other endpoint in the connection
	// For now, broadcast to all endpoints in the same tunnel (connection ID will filter)
	server.mu.RLock()
	for _, endpoint := range server.endpoints {
		if endpoint.ID != ep.ID && endpoint.TunnelName == ep.TunnelName {
			endpoint.SendJSON(MsgTypePortForwardData, payload)
		}
	}
	server.mu.RUnlock()
}

// handlePortForwardCloseRoute routes port forward close to the other endpoint
func (ep *TCPEndpoint) handlePortForwardCloseRoute(server *TCPTunnelServer, msg *TunnelMessage) {
	var payload PortForwardClosePayload
	if err := msg.ParseJSON(&payload); err != nil {
		DebugLog("[TCP TUNNEL] Invalid port forward close: %v", err)
		return
	}

	DebugLog("[PORT-FWD] Close for connection %s: %s", payload.ConnectionID, payload.Reason)

	// Route close to other endpoints in the same tunnel
	server.mu.RLock()
	for _, endpoint := range server.endpoints {
		if endpoint.ID != ep.ID && endpoint.TunnelName == ep.TunnelName {
			endpoint.SendJSON(MsgTypePortForwardClose, payload)
		}
	}
	server.mu.RUnlock()
}

// initiateKeyRotation initiates a new key rotation by sending a key request
func (ep *TCPEndpoint) initiateKeyRotation() error {
	if ep.KeyManager == nil {
		return nil
	}

	req, err := ep.KeyManager.GenerateKeyRequest()
	if err != nil {
		DebugLog("[KEY] Failed to generate key request for %s: %v", ep.EndpointName, err)
		return err
	}

	payload, err := MarshalKeyRequest(req)
	if err != nil {
		DebugLog("[KEY] Failed to marshal key request: %v", err)
		return err
	}

	if err := ep.Conn.WriteMessage(&TunnelMessage{Type: MsgTypeKeyRequest, Payload: payload}); err != nil {
		DebugLog("[KEY] Failed to send key request to %s: %v", ep.EndpointName, err)
		return err
	}

	DebugLog("[KEY] Key rotation initiated for endpoint %s", ep.EndpointName)
	return nil
}

// handleKeyRequest handles an incoming key rotation request
func (ep *TCPEndpoint) handleKeyRequest(msg *TunnelMessage) {
	if ep.KeyManager == nil {
		return
	}

	req, err := UnmarshalKeyRequest(msg.Payload)
	if err != nil {
		DebugLog("[KEY] Failed to parse key request from %s: %v", ep.EndpointName, err)
		return
	}

	resp, err := ep.KeyManager.HandleKeyRequest(req)
	if err != nil {
		DebugLog("[KEY] Failed to handle key request from %s: %v", ep.EndpointName, err)
		return
	}

	payload, err := MarshalKeyResponse(resp)
	if err != nil {
		DebugLog("[KEY] Failed to marshal key response: %v", err)
		return
	}

	if err := ep.Conn.WriteMessage(&TunnelMessage{Type: MsgTypeKeyResponse, Payload: payload}); err != nil {
		DebugLog("[KEY] Failed to send key response to %s: %v", ep.EndpointName, err)
		return
	}

	DebugLog("[KEY] Key response sent to endpoint %s", ep.EndpointName)
}

// handleKeyResponse handles a key response and sends confirmation
func (ep *TCPEndpoint) handleKeyResponse(msg *TunnelMessage) {
	if ep.KeyManager == nil {
		return
	}

	resp, err := UnmarshalKeyResponse(msg.Payload)
	if err != nil {
		DebugLog("[KEY] Failed to parse key response from %s: %v", ep.EndpointName, err)
		return
	}

	confirm, err := ep.KeyManager.HandleKeyResponse(resp)
	if err != nil {
		DebugLog("[KEY] Failed to handle key response from %s: %v", ep.EndpointName, err)
		return
	}

	payload, err := MarshalKeyConfirm(confirm)
	if err != nil {
		DebugLog("[KEY] Failed to marshal key confirm: %v", err)
		return
	}

	if err := ep.Conn.WriteMessage(&TunnelMessage{Type: MsgTypeKeyConfirm, Payload: payload}); err != nil {
		DebugLog("[KEY] Failed to send key confirm to %s: %v", ep.EndpointName, err)
		return
	}

	// Activate key on initiator side after sending confirm
	if err := ep.KeyManager.ActivateKey(); err != nil {
		DebugLog("[KEY] Failed to activate key: %v", err)
		return
	}

	DebugLog("[KEY] Key rotation completed for endpoint %s (initiator)", ep.EndpointName)
}

// handleKeyConfirm handles key confirmation and activates the new key
func (ep *TCPEndpoint) handleKeyConfirm(msg *TunnelMessage) {
	if ep.KeyManager == nil {
		return
	}

	confirm, err := UnmarshalKeyConfirm(msg.Payload)
	if err != nil {
		DebugLog("[KEY] Failed to parse key confirm from %s: %v", ep.EndpointName, err)
		return
	}

	if err := ep.KeyManager.HandleKeyConfirm(confirm); err != nil {
		DebugLog("[KEY] Failed to handle key confirm from %s: %v", ep.EndpointName, err)
		return
	}

	DebugLog("[KEY] Key rotation completed for endpoint %s (responder)", ep.EndpointName)
}

// sendMirrorUpdate sends mirror APS addresses to an endpoint after registration
func sendMirrorUpdate(s *TCPTunnelServer, ep *TCPEndpoint) {
	// Get endpoint config from global config
	s.mu.RLock()
	endpointKey := ep.TunnelName + "/" + ep.EndpointName
	endpointConfig, exists := s.config.Endpoints[endpointKey]
	mirrors := s.config.Mirrors
	s.mu.RUnlock()

	if !exists || endpointConfig.Mirror == "" {
		// No mirror configured for this endpoint
		return
	}

	// Get mirror group
	mirrorList, exists := mirrors[endpointConfig.Mirror]

	if !exists || len(mirrorList) == 0 {
		DebugLog("[MIRROR] Mirror group '%s' not found or empty for endpoint %s",
			endpointConfig.Mirror, ep.EndpointName)
		return
	}

	// Send mirror update to endpoint
	payload := MirrorUpdatePayload{
		Mirrors: mirrorList,
	}

	if err := ep.Conn.SendJSON(MsgTypeMirrorUpdate, payload); err != nil {
		DebugLog("[MIRROR] Failed to send mirror update to %s: %v", ep.EndpointName, err)
		return
	}

	DebugLog("[MIRROR] Sent %d mirror(s) from group '%s' to endpoint %s",
		len(mirrorList), endpointConfig.Mirror, ep.EndpointName)
}
