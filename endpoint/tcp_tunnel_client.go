package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

// Local buffer pools for the endpoint client
var (
	mediumBufPool = sync.Pool{New: func() any { return make([]byte, 64*1024) }}
	largeBufPool  = sync.Pool{New: func() any { return make([]byte, 256*1024) }}
)

func GetMediumBuffer() []byte { return mediumBufPool.Get().([]byte) }
func PutMediumBuffer(b []byte) {
	if cap(b) >= 64*1024 {
		mediumBufPool.Put(b[:64*1024])
	}
}
func GetLargeBuffer() []byte { return largeBufPool.Get().([]byte) }
func PutLargeBuffer(b []byte) {
	if cap(b) >= 256*1024 {
		largeBufPool.Put(b[:256*1024])
	}
}

// TCP Tunnel Protocol Message Types (must match APS side)
const (
	MsgTypeRegister        uint8 = 0x01
	MsgTypeRegisterAck     uint8 = 0x02
	MsgTypeRequest         uint8 = 0x10
	MsgTypeResponse        uint8 = 0x11
	MsgTypeResponseHeader  uint8 = 0x12
	MsgTypeResponseChunk   uint8 = 0x13
	MsgTypeResponseEnd     uint8 = 0x14
	MsgTypeProxyConnect    uint8 = 0x20
	MsgTypeProxyConnectAck uint8 = 0x21
	// MsgTypeProxyData removed
	MsgTypeProxyClose      uint8 = 0x23
	MsgTypeProxyDataBinary uint8 = 0x24
	MsgTypeHeartbeat       uint8 = 0xF0
	MsgTypeCancel          uint8 = 0xF1

	// Port forwarding between endpoints
	MsgTypePortForwardRequest  uint8 = 0x30
	MsgTypePortForwardResponse uint8 = 0x31
	MsgTypePortForwardData     uint8 = 0x32
	MsgTypePortForwardClose    uint8 = 0x33

	// Configuration management
	MsgTypeConfigUpdate uint8 = 0x40 // APS pushes config update to endpoint

	// Key negotiation for dynamic encryption
	MsgTypeKeyRequest  uint8 = 0x50 // Request new session key negotiation
	MsgTypeKeyResponse uint8 = 0x51 // Response with encrypted new key
	MsgTypeKeyConfirm  uint8 = 0x52 // Confirmation key is activated
)

const headerSize = 5
const maxMessageSize = 10 * 1024 * 1024

// TunnelMessage represents a message in the TCP tunnel protocol
type TunnelMessage struct {
	Type    uint8
	Payload []byte
}

// RegisterPayload for registration
type RegisterPayload struct {
	TunnelName   string `json:"tunnel_name"`
	EndpointName string `json:"endpoint_name"`
	Password     string `json:"password"`
}

// RegisterAckPayload for registration response
type RegisterAckPayload struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// RequestPayloadTCP for HTTP request
type RequestPayloadTCP struct {
	ID   string `json:"id"`
	URL  string `json:"url"`
	Data []byte `json:"data"`
}

// ResponseHeaderPayloadTCP for HTTP response header
type ResponseHeaderPayloadTCP struct {
	ID     string `json:"id"`
	Header []byte `json:"header"`
}

// ResponseChunkPayloadTCP for response chunk
type ResponseChunkPayloadTCP struct {
	ID   string `json:"id"`
	Data []byte `json:"data"`
}

// ResponseEndPayloadTCP marks end of response
type ResponseEndPayloadTCP struct {
	ID    string `json:"id"`
	Error string `json:"error,omitempty"`
}

// ProxyConnectPayload for TCP proxy connect
type ProxyConnectPayload struct {
	ConnectionID string `json:"connection_id"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	TLS          bool   `json:"tls"`
	ClientIP     string `json:"client_ip"`
}

// ProxyConnectAckPayload for proxy connect response
type ProxyConnectAckPayload struct {
	ConnectionID string `json:"connection_id"`
	Success      bool   `json:"success"`
	Error        string `json:"error,omitempty"`
}

// ProxyDataPayload removed

// ProxyClosePayload for closing proxy
type ProxyClosePayload struct {
	ConnectionID string `json:"connection_id"`
	Reason       string `json:"reason,omitempty"`
}

// HeartbeatPayload for keepalive
type HeartbeatPayload struct {
	Timestamp int64 `json:"timestamp"`
}

// TunnelConn wraps a net.Conn with protocol read/write
type TunnelConn struct {
	conn     net.Conn
	readMu   sync.Mutex
	writeMu  sync.Mutex
	closed   bool
	closedMu sync.RWMutex
}

// NewTunnelConn creates a new TunnelConn
func NewTunnelConn(conn net.Conn) *TunnelConn {
	return &TunnelConn{conn: conn}
}

// ReadMessage reads one message
func (tc *TunnelConn) ReadMessage() (*TunnelMessage, error) {
	tc.readMu.Lock()
	defer tc.readMu.Unlock()

	tc.closedMu.RLock()
	if tc.closed {
		tc.closedMu.RUnlock()
		return nil, errors.New("connection closed")
	}
	tc.closedMu.RUnlock()

	header := make([]byte, headerSize)
	_, err := io.ReadFull(tc.conn, header)
	if err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(header[:4])
	if length > maxMessageSize {
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	msgType := header[4]
	payload := make([]byte, length)
	if length > 0 {
		_, err = io.ReadFull(tc.conn, payload)
		if err != nil {
			return nil, err
		}
	}

	return &TunnelMessage{Type: msgType, Payload: payload}, nil
}

// WriteMessage writes one message
func (tc *TunnelConn) WriteMessage(msg *TunnelMessage) error {
	tc.writeMu.Lock()
	defer tc.writeMu.Unlock()

	tc.closedMu.RLock()
	if tc.closed {
		tc.closedMu.RUnlock()
		return errors.New("connection closed")
	}
	tc.closedMu.RUnlock()

	frame := make([]byte, headerSize+len(msg.Payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(msg.Payload)))
	frame[4] = msg.Type
	copy(frame[headerSize:], msg.Payload)

	_, err := tc.conn.Write(frame)
	return err
}

// SendJSON marshals and sends
func (tc *TunnelConn) SendJSON(msgType uint8, data interface{}) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return tc.WriteMessage(&TunnelMessage{Type: msgType, Payload: payload})
}

// Close closes the connection
func (tc *TunnelConn) Close() error {
	tc.closedMu.Lock()
	tc.closed = true
	tc.closedMu.Unlock()
	return tc.conn.Close()
}

// ParseJSON unmarshals payload
func (msg *TunnelMessage) ParseJSON(v interface{}) error {
	return json.Unmarshal(msg.Payload, v)
}

// runTCPTunnelSession connects to APS via TCP tunnel protocol
func runTCPTunnelSession(ctx context.Context) bool {
	log.Printf("Connecting to TCP tunnel server at %s", *serverAddr)

	conn, err := net.DialTimeout("tcp", *serverAddr, 30*time.Second)
	if err != nil {
		log.Printf("Failed to connect: %v", err)
		return true
	}

	tc := NewTunnelConn(conn)
	defer tc.Close()

	// Optimize TCP connection for better throughput
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetReadBuffer(256 * 1024)  // 256KB
		tcpConn.SetWriteBuffer(256 * 1024) // 256KB
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(60 * time.Second)
	}

	// Send registration using effective config values
	if err := tc.SendJSON(MsgTypeRegister, RegisterPayload{
		TunnelName:   GetEffectiveTunnelName(),
		EndpointName: GetEffectiveEndpointName(),
		Password:     GetEffectivePassword(),
	}); err != nil {
		log.Printf("Failed to send registration: %v", err)
		return true
	}

	// Wait for registration ack
	msg, err := tc.ReadMessage()
	if err != nil {
		log.Printf("Failed to read registration ack: %v", err)
		return true
	}

	if msg.Type != MsgTypeRegisterAck {
		log.Printf("Unexpected message type: %d", msg.Type)
		return true
	}

	var ack RegisterAckPayload
	if err := msg.ParseJSON(&ack); err != nil {
		log.Printf("Failed to parse registration ack: %v", err)
		return true
	}

	if !ack.Success {
		log.Printf("Registration failed: %s", ack.Error)
		if isPermanentError(errors.New(ack.Error)) {
			return false
		}
		return true
	}

	log.Println("Successfully registered with TCP tunnel server")

	// Initialize session key manager
	password := *tunnelPassword
	if runtimeConfig != nil && runtimeConfig.Password != "" {
		password = runtimeConfig.Password
	}
	keyManager := NewSessionKeyManager(password, GetEffectiveEndpointName())
	if err := keyManager.DeriveInitialKey(); err != nil {
		log.Printf("Failed to derive initial key: %v", err)
		return true
	}

	// Start message handling loop
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			// Set read deadline to detect dead connections
			// Server sends heartbeat every 30s, use 120s for large transfers
			tc.conn.SetReadDeadline(time.Now().Add(120 * time.Second))
			msg, err := tc.ReadMessage()
			if err != nil {
				if err != io.EOF {
					log.Printf("Read error: %v", err)
				}
				return
			}
			go handleTCPMessage(tc, msg, keyManager)
		}
	}()

	// Start auto key rotation (endpoint can also initiate)
	go func() {
		time.Sleep(5 * time.Second) // Wait for connection to stabilize
		keyManager.StartAutoRotation(func() error {
			return initiateKeyRotation(tc, keyManager)
		})
	}()

	// Heartbeat loop
	heartbeatTicker := time.NewTicker(30 * time.Second)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return false
		case <-done:
			return true
		case <-heartbeatTicker.C:
			tc.SendJSON(MsgTypeHeartbeat, HeartbeatPayload{Timestamp: time.Now().UnixNano()})
		}
	}
}

// handleTCPMessage handles incoming messages
func handleTCPMessage(tc *TunnelConn, msg *TunnelMessage, km *SessionKeyManager) {
	switch msg.Type {
	case MsgTypeRequest:
		handleTCPRequest(tc, msg)
	case MsgTypeProxyConnect:
		handleTCPProxyConnect(tc, msg)
	case MsgTypeProxyDataBinary:
		handleTCPProxyDataBinary(msg)
	case MsgTypeProxyClose:
		handleTCPProxyClose(msg)
	case MsgTypePortForwardResponse:
		handlePortForwardResponse(tc, msg)
	case MsgTypePortForwardData:
		handlePortForwardDataMsg(msg)
	case MsgTypePortForwardClose:
		handlePortForwardCloseMsg(msg)
	case MsgTypeHeartbeat:
		// Heartbeat - do nothing
	case MsgTypeCancel:
		// TODO: Handle cancellation
	case MsgTypeConfigUpdate:
		handleConfigUpdate(tc, msg)
	}
}

// handleTCPRequest handles HTTP request via TCP tunnel
func handleTCPRequest(tc *TunnelConn, msg *TunnelMessage) {
	var reqPayload RequestPayloadTCP
	if err := msg.ParseJSON(&reqPayload); err != nil {
		log.Printf("Failed to parse request: %v", err)
		return
	}

	requestID := reqPayload.ID
	if *debug {
		log.Printf("[DEBUG %s] Handling TCP request, URL: %s", requestID, reqPayload.URL)
	}

	// Decrypt request data
	decryptedData, err := decrypt(reqPayload.Data, GetEffectivePassword())
	if err != nil {
		log.Printf("[ERROR %s] Decryption failed: %v", requestID, err)
		sendTCPErrorResponse(tc, requestID, "decryption failed")
		return
	}

	// Parse HTTP request
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(decryptedData)))
	if err != nil {
		log.Printf("[ERROR %s] Cannot read request: %v", requestID, err)
		sendTCPErrorResponse(tc, requestID, "cannot read request")
		return
	}

	// Execute request (similar to existing handleRequest logic)
	// ... (reuse existing request handling code)

	// Use the target URL provided by APS (which contains the internal IP/port)
	// instead of the Host header (which contains the public domain).
	targetURL, err := url.Parse(reqPayload.URL)
	if err != nil {
		log.Printf("[ERROR %s] Invalid target URL: %v", requestID, err)
		sendTCPErrorResponse(tc, requestID, "invalid target url")
		return
	}

	req.URL = targetURL
	req.RequestURI = "" // RequestURI must be empty for client requests

	if *debug {
		log.Printf("[DEBUG %s] Sending request to backend: %s", requestID, req.URL.String())
	}

	resp, err := sharedClient.Do(req)
	if err != nil {
		log.Printf("[ERROR %s] Request failed: %v", requestID, err)
		sendTCPErrorResponse(tc, requestID, err.Error())
		return
	}
	defer resp.Body.Close()

	if *debug {
		log.Printf("[DEBUG %s] Got response: %d %s", requestID, resp.StatusCode, resp.Status)
	}

	// Send response header
	headerBytes, err := httputil.DumpResponse(resp, false)
	if err != nil {
		log.Printf("[ERROR %s] Failed to dump response: %v", requestID, err)
		sendTCPErrorResponse(tc, requestID, "failed to dump response")
		return
	}

	encryptedHeader, err := encrypt(headerBytes, GetEffectivePassword())
	if err != nil {
		log.Printf("[ERROR %s] Failed to encrypt response header: %v", requestID, err)
		sendTCPErrorResponse(tc, requestID, "failed to encrypt response header")
		return
	}

	if err := tc.SendJSON(MsgTypeResponseHeader, ResponseHeaderPayloadTCP{
		ID:     requestID,
		Header: encryptedHeader,
	}); err != nil {
		log.Printf("[ERROR %s] Failed to send response header: %v", requestID, err)
		return
	}

	if *debug {
		log.Printf("[DEBUG %s] Sent response header", requestID)
	}

	// Stream body
	buf := GetLargeBuffer()
	defer PutLargeBuffer(buf)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			encryptedChunk, encErr := encrypt(buf[:n], GetEffectivePassword())
			if encErr != nil {
				log.Printf("[ERROR %s] Failed to encrypt chunk: %v", requestID, encErr)
				sendTCPErrorResponse(tc, requestID, "failed to encrypt chunk")
				return
			}

			if sendErr := tc.SendJSON(MsgTypeResponseChunk, ResponseChunkPayloadTCP{
				ID:   requestID,
				Data: encryptedChunk,
			}); sendErr != nil {
				log.Printf("[ERROR %s] Failed to send chunk: %v", requestID, sendErr)
				return
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("[ERROR %s] Read body error: %v", requestID, err)
			sendTCPErrorResponse(tc, requestID, "read body error")
			return
		}
	}

	// Send end
	if err := tc.SendJSON(MsgTypeResponseEnd, ResponseEndPayloadTCP{ID: requestID}); err != nil {
		log.Printf("[ERROR %s] Failed to send response end: %v", requestID, err)
		return
	}

	if *debug {
		log.Printf("[DEBUG %s] Request completed successfully", requestID)
	}
}

// handleTCPProxyConnect handles TCP proxy connect via TCP tunnel
func handleTCPProxyConnect(tc *TunnelConn, msg *TunnelMessage) {
	var payload ProxyConnectPayload
	if err := msg.ParseJSON(&payload); err != nil {
		log.Printf("Failed to parse proxy connect: %v", err)
		return
	}

	connID := payload.ConnectionID
	address := net.JoinHostPort(payload.Host, fmt.Sprintf("%d", payload.Port))
	log.Printf("[PROXY %s] Connecting to %s (client: %s)", connID, address, payload.ClientIP)

	// Connect to target
	conn, err := net.DialTimeout("tcp", address, 30*time.Second)
	if err == nil {
		// Optimize TCP connection
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetReadBuffer(256 * 1024)
			tcpConn.SetWriteBuffer(256 * 1024)
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(60 * time.Second)
		}
	}

	// Send ack
	ack := ProxyConnectAckPayload{
		ConnectionID: connID,
		Success:      err == nil,
	}
	if err != nil {
		ack.Error = err.Error()
		log.Printf("[PROXY %s] Connection failed: %v", connID, err)
	} else {
		log.Printf("[PROXY %s] TCP connection established to %s", connID, address)
		proxyConnections.Store(connID, conn)
		log.Printf("[PROXY %s] Starting read loop", connID)
		go tcpProxyReadLoop(tc, connID, conn)
	}

	log.Printf("[PROXY %s] Sending ack (success=%v)", connID, ack.Success)
	tc.SendJSON(MsgTypeProxyConnectAck, ack)
}

// handleTCPProxyData removed (legacy JSON format)

// handleTCPProxyDataBinary handles proxy data in binary format
func handleTCPProxyDataBinary(msg *TunnelMessage) {
	if len(msg.Payload) < 1 {
		return
	}

	idLen := int(msg.Payload[0])
	if len(msg.Payload) < 1+idLen {
		return
	}

	connectionID := string(msg.Payload[1 : 1+idLen])
	data := msg.Payload[1+idLen:]

	connVal, ok := proxyConnections.Load(connectionID)
	if !ok {
		// log.Printf("[PROXY %s] Connection not found for binary proxy data", connectionID)
		return
	}

	conn := connVal.(net.Conn)
	_, err := conn.Write(data)
	if err != nil {
		log.Printf("[PROXY %s] Write error: %v", connectionID, err)
		conn.Close()
		proxyConnections.Delete(connectionID)
	}
}

// handleTCPProxyClose handles proxy close via TCP tunnel
func handleTCPProxyClose(msg *TunnelMessage) {
	var payload ProxyClosePayload
	if err := msg.ParseJSON(&payload); err != nil {
		return
	}

	log.Printf("[PROXY %s] Closing: %s", payload.ConnectionID, payload.Reason)
	if connVal, ok := proxyConnections.Load(payload.ConnectionID); ok {
		connVal.(net.Conn).Close()
		proxyConnections.Delete(payload.ConnectionID)
	}
}

// tcpProxyReadLoop reads from target and sends to APS
func tcpProxyReadLoop(tc *TunnelConn, connID string, conn net.Conn) {
	log.Printf("[PROXY %s] Read loop started", connID)
	defer func() {
		log.Printf("[PROXY %s] Read loop ending, closing connection", connID)
		conn.Close()
		proxyConnections.Delete(connID)
		log.Printf("[PROXY %s] Sending close message to APS", connID)
		tc.SendJSON(MsgTypeProxyClose, ProxyClosePayload{
			ConnectionID: connID,
			Reason:       "connection closed",
		})
	}()

	buf := GetMediumBuffer()
	defer PutMediumBuffer(buf)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			log.Printf("[PROXY %s] Read %d bytes from backend, sending to APS", connID, n)

			// Send data to APS using binary format
			connIDBytes := []byte(connID)
			payload := make([]byte, 1+len(connIDBytes)+n)
			payload[0] = uint8(len(connIDBytes))
			copy(payload[1:], connIDBytes)
			copy(payload[1+len(connIDBytes):], buf[:n])

			if sendErr := tc.WriteMessage(&TunnelMessage{
				Type:    MsgTypeProxyDataBinary,
				Payload: payload,
			}); sendErr != nil {
				log.Printf("[PROXY %s] Failed to send data to APS: %v", connID, sendErr)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[PROXY %s] Read error: %v", connID, err)
			} else {
				log.Printf("[PROXY %s] Connection closed by backend (EOF)", connID)
			}
			return
		}
	}
}

// sendTCPErrorResponse sends error response
func sendTCPErrorResponse(tc *TunnelConn, requestID, errorMsg string) {
	tc.SendJSON(MsgTypeResponseEnd, ResponseEndPayloadTCP{
		ID:    requestID,
		Error: errorMsg,
	})
}

// ConfigUpdatePayload is the payload for config update messages from APS
type ConfigUpdatePayload struct {
	TunnelName   string              `json:"tunnelName"`
	EndpointName string              `json:"endpointName"`
	Password     string              `json:"password,omitempty"`
	PortMappings []PortMappingConfig `json:"portMappings,omitempty"`
	P2PSettings  *P2PSettings        `json:"p2pSettings,omitempty"`
}

// handleConfigUpdate handles configuration update pushed from APS
func handleConfigUpdate(tc *TunnelConn, msg *TunnelMessage) {
	var payload ConfigUpdatePayload
	if err := msg.ParseJSON(&payload); err != nil {
		log.Printf("[CONFIG] Failed to parse config update: %v", err)
		return
	}

	log.Printf("[CONFIG] Received config update from APS")

	// Update runtime config
	runtimeConfigMu.Lock()
	if runtimeConfig == nil {
		runtimeConfig = &EndpointRuntimeConfig{}
	}

	// Check for critical changes that require reconnection
	shouldReconnect := false
	if payload.TunnelName != "" && payload.TunnelName != runtimeConfig.TunnelName {
		shouldReconnect = true
	}
	if payload.EndpointName != "" && payload.EndpointName != runtimeConfig.EndpointName {
		shouldReconnect = true
	}

	// Update fields from payload
	if payload.TunnelName != "" {
		runtimeConfig.TunnelName = payload.TunnelName
	}
	if payload.EndpointName != "" {
		runtimeConfig.EndpointName = payload.EndpointName
	}
	if payload.Password != "" {
		runtimeConfig.Password = payload.Password
	}
	if payload.PortMappings != nil {
		runtimeConfig.PortMappings = payload.PortMappings
	}
	if payload.P2PSettings != nil {
		runtimeConfig.P2PSettings = payload.P2PSettings
	}
	runtimeConfigMu.Unlock()

	if shouldReconnect {
		log.Printf("[CONFIG] Critical configuration changed (tunnel/endpoint name), reconnecting...")
		tc.Close()
		return
	}

	log.Printf("[CONFIG] Updated runtime config: tunnel=%s, endpoint=%s, portMappings=%d",
		payload.TunnelName, payload.EndpointName, len(payload.PortMappings))

	// Hot reload P2P components
	go func() {
		log.Println("[CONFIG] Restarting P2P components with new configuration...")

		// Stop existing P2P components
		stopP2PComponents()

		// Re-initialize with new config
		initializeP2PComponents()

		log.Println("[CONFIG] P2P components restarted successfully")
	}()
}

// initiateKeyRotation initiates a new key rotation by sending a key request
func initiateKeyRotation(tc *TunnelConn, km *SessionKeyManager) error {
	req, err := km.GenerateKeyRequest()
	if err != nil {
		log.Printf("[KEY] Failed to generate key request: %v", err)
		return err
	}

	payload, err := MarshalKeyRequest(req)
	if err != nil {
		log.Printf("[KEY] Failed to marshal key request: %v", err)
		return err
	}

	if err := tc.WriteMessage(&TunnelMessage{Type: MsgTypeKeyRequest, Payload: payload}); err != nil {
		log.Printf("[KEY] Failed to send key request: %v", err)
		return err
	}

	log.Printf("[KEY] Key rotation initiated")
	return nil
}

// handleKeyRequest handles an incoming key rotation request
func handleKeyRequest(tc *TunnelConn, msg *TunnelMessage, km *SessionKeyManager) {
	req, err := UnmarshalKeyRequest(msg.Payload)
	if err != nil {
		log.Printf("[KEY] Failed to parse key request: %v", err)
		return
	}

	resp, err := km.HandleKeyRequest(req)
	if err != nil {
		log.Printf("[KEY] Failed to handle key request: %v", err)
		return
	}

	payload, err := MarshalKeyResponse(resp)
	if err != nil {
		log.Printf("[KEY] Failed to marshal key response: %v", err)
		return
	}

	if err := tc.WriteMessage(&TunnelMessage{Type: MsgTypeKeyResponse, Payload: payload}); err != nil {
		log.Printf("[KEY] Failed to send key response: %v", err)
		return
	}

	log.Printf("[KEY] Key response sent")
}

// handleKeyResponse handles a key response and sends confirmation
func handleKeyResponse(tc *TunnelConn, msg *TunnelMessage, km *SessionKeyManager) {
	resp, err := UnmarshalKeyResponse(msg.Payload)
	if err != nil {
		log.Printf("[KEY] Failed to parse key response: %v", err)
		return
	}

	confirm, err := km.HandleKeyResponse(resp)
	if err != nil {
		log.Printf("[KEY] Failed to handle key response: %v", err)
		return
	}

	payload, err := MarshalKeyConfirm(confirm)
	if err != nil {
		log.Printf("[KEY] Failed to marshal key confirm: %v", err)
		return
	}

	if err := tc.WriteMessage(&TunnelMessage{Type: MsgTypeKeyConfirm, Payload: payload}); err != nil {
		log.Printf("[KEY] Failed to send key confirm: %v", err)
		return
	}

	// Activate key on initiator side after sending confirm
	if err := km.ActivateKey(); err != nil {
		log.Printf("[KEY] Failed to activate key: %v", err)
		return
	}

	log.Printf("[KEY] Key rotation completed (initiator)")
}

// handleKeyConfirm handles key confirmation and activates the new key
func handleKeyConfirm(tc *TunnelConn, msg *TunnelMessage, km *SessionKeyManager) {
	confirm, err := UnmarshalKeyConfirm(msg.Payload)
	if err != nil {
		log.Printf("[KEY] Failed to parse key confirm: %v", err)
		return
	}

	if err := km.HandleKeyConfirm(confirm); err != nil {
		log.Printf("[KEY] Failed to handle key confirm: %v", err)
		return
	}

	log.Printf("[KEY] Key rotation completed (responder)")
}
