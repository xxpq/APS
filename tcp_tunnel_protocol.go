package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// Message types for TCP tunnel protocol
const (
	MsgTypeRegister        uint8 = 0x01 // Endpoint registration
	MsgTypeRegisterAck     uint8 = 0x02 // Registration acknowledgement
	MsgTypeRequest         uint8 = 0x10 // HTTP request
	MsgTypeResponse        uint8 = 0x11 // HTTP response
	MsgTypeResponseHeader  uint8 = 0x12 // Response header (streaming)
	MsgTypeResponseChunk   uint8 = 0x13 // Response chunk (streaming)
	MsgTypeResponseEnd     uint8 = 0x14 // Response end (streaming)
	MsgTypeProxyConnect    uint8 = 0x20 // TCP proxy connect request
	MsgTypeProxyConnectAck uint8 = 0x21 // TCP proxy connect acknowledgement
	MsgTypeProxyStreamMode uint8 = 0x25 // Signal switch to direct stream mode
	// MsgTypeProxyData removed (legacy JSON format)
	MsgTypeProxyClose      uint8 = 0x23 // TCP proxy close
	MsgTypeProxyDataBinary uint8 = 0x24 // TCP proxy data (binary format)
	MsgTypeHeartbeat       uint8 = 0xF0 // Heartbeat/keepalive
	MsgTypeCancel          uint8 = 0xF1 // Cancel request

	// Port forwarding between endpoints
	MsgTypePortForwardRequest  uint8 = 0x30 // Request port forward through APS
	MsgTypePortForwardResponse uint8 = 0x31 // Response to port forward request
	MsgTypePortForwardData     uint8 = 0x32 // Port forward data
	MsgTypePortForwardClose    uint8 = 0x33 // Port forward close

	// Configuration management
	MsgTypeConfigUpdate uint8 = 0x40 // APS pushes config update to endpoint

	// Key negotiation for dynamic encryption
	MsgTypeKeyRequest  uint8 = 0x50 // Request new session key negotiation
	MsgTypeKeyResponse uint8 = 0x51 // Response with encrypted new key
	MsgTypeKeyConfirm  uint8 = 0x52 // Confirmation key is activated
)

// Message header size: 4 bytes length + 1 byte type
const headerSize = 5

// Maximum message size (10 MB)
const maxMessageSize = 10 * 1024 * 1024

// TunnelMessage represents a message in the TCP tunnel protocol
type TunnelMessage struct {
	Type    uint8
	Payload []byte
}

// RegisterPayload is sent by endpoint to register with APS
type RegisterPayload struct {
	TunnelName   string `json:"tunnel_name"`
	EndpointName string `json:"endpoint_name"`
	Password     string `json:"password"`
}

// RegisterAckPayload is sent by APS to acknowledge registration
type RegisterAckPayload struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// RequestPayloadTCP represents an HTTP request sent via tunnel
type RequestPayloadTCP struct {
	ID   string `json:"id"`
	URL  string `json:"url"`
	Data []byte `json:"data"` // Encrypted HTTP request bytes
}

// ResponseHeaderPayloadTCP represents HTTP response header
type ResponseHeaderPayloadTCP struct {
	ID     string `json:"id"`
	Header []byte `json:"header"` // Encrypted HTTP response header bytes
}

// ResponseChunkPayloadTCP represents a response chunk
type ResponseChunkPayloadTCP struct {
	ID   string `json:"id"`
	Data []byte `json:"data"` // Encrypted chunk data
}

// ResponseEndPayloadTCP marks the end of a response
type ResponseEndPayloadTCP struct {
	ID    string `json:"id"`
	Error string `json:"error,omitempty"`
}

// ProxyConnectPayload is sent by APS to request TCP proxy connection
type ProxyConnectPayload struct {
	ConnectionID string `json:"connection_id"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	TLS          bool   `json:"tls"`
	ClientIP     string `json:"client_ip"`   // Real client IP for audit
	StreamMode   bool   `json:"stream_mode"` // If true, switch to zero-copy stream mode
}

// ProxyConnectAckPayload is sent by endpoint to acknowledge proxy connection
type ProxyConnectAckPayload struct {
	ConnectionID string `json:"connection_id"`
	Success      bool   `json:"success"`
	Error        string `json:"error,omitempty"`
}

// ProxyStreamModePayload is sent by APS to signal switch to stream mode
type ProxyStreamModePayload struct {
	ConnectionID string `json:"connection_id"`
}

// ProxyDataPayload removed (legacy JSON format)

// ProxyClosePayload signals proxy connection close
type ProxyClosePayload struct {
	ConnectionID string `json:"connection_id"`
	Reason       string `json:"reason,omitempty"`
}

// HeartbeatPayload for keepalive
type HeartbeatPayload struct {
	Timestamp int64 `json:"timestamp"`
}

// TunnelConn wraps a net.Conn with protocol read/write methods
type TunnelConn struct {
	conn     net.Conn
	readMu   sync.Mutex
	writeMu  sync.Mutex
	closed   bool
	closedMu sync.RWMutex
}

// NewTunnelConn creates a new TunnelConn
func NewTunnelConn(conn net.Conn) *TunnelConn {
	return &TunnelConn{
		conn: conn,
	}
}

// ReadMessage reads one message from the connection
func (tc *TunnelConn) ReadMessage() (*TunnelMessage, error) {
	tc.readMu.Lock()
	defer tc.readMu.Unlock()

	tc.closedMu.RLock()
	if tc.closed {
		tc.closedMu.RUnlock()
		return nil, errors.New("connection closed")
	}
	tc.closedMu.RUnlock()

	// Use pooled header buffer
	header := GetHeaderBuffer()
	defer PutHeaderBuffer(header)

	_, err := io.ReadFull(tc.conn, header)
	if err != nil {
		return nil, err
	}

	// Parse length (big-endian)
	length := binary.BigEndian.Uint32(header[:4])
	if length > maxMessageSize {
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	msgType := header[4]

	// Read payload - allocate exact size needed (can't pool variable sizes easily)
	payload := make([]byte, length)
	if length > 0 {
		_, err = io.ReadFull(tc.conn, payload)
		if err != nil {
			return nil, err
		}
	}

	return &TunnelMessage{
		Type:    msgType,
		Payload: payload,
	}, nil
}

// WriteMessage writes one message to the connection
func (tc *TunnelConn) WriteMessage(msg *TunnelMessage) error {
	tc.writeMu.Lock()
	defer tc.writeMu.Unlock()

	tc.closedMu.RLock()
	if tc.closed {
		tc.closedMu.RUnlock()
		return errors.New("connection closed")
	}
	tc.closedMu.RUnlock()

	// Build frame: length (4) + type (1) + payload
	frame := make([]byte, headerSize+len(msg.Payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(msg.Payload)))
	frame[4] = msg.Type
	copy(frame[headerSize:], msg.Payload)

	_, err := tc.conn.Write(frame)
	return err
}

// SendJSON marshals data to JSON and sends as a message
func (tc *TunnelConn) SendJSON(msgType uint8, data interface{}) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return tc.WriteMessage(&TunnelMessage{Type: msgType, Payload: payload})
}

// Close closes the underlying connection
func (tc *TunnelConn) Close() error {
	tc.closedMu.Lock()
	tc.closed = true
	tc.closedMu.Unlock()
	return tc.conn.Close()
}

// IsClosed returns whether the connection is closed
func (tc *TunnelConn) IsClosed() bool {
	tc.closedMu.RLock()
	defer tc.closedMu.RUnlock()
	return tc.closed
}

// RemoteAddr returns the remote address
func (tc *TunnelConn) RemoteAddr() net.Addr {
	return tc.conn.RemoteAddr()
}

// LocalAddr returns the local address
func (tc *TunnelConn) LocalAddr() net.Addr {
	return tc.conn.LocalAddr()
}

// UnderlyingConn returns the underlying net.Conn
func (tc *TunnelConn) UnderlyingConn() net.Conn {
	return tc.conn
}

// ParseJSON unmarshals message payload as JSON
func (msg *TunnelMessage) ParseJSON(v interface{}) error {
	return json.Unmarshal(msg.Payload, v)
}
