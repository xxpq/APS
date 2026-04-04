package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
)

// Message types for TCP tunnel protocol
const (
	MsgTypeRegister         uint8 = 0x01 // Endpoint registration
	MsgTypeRegisterAck      uint8 = 0x02 // Registration acknowledgement
	MsgTypeRequest          uint8 = 0x10 // HTTP request
	MsgTypeResponse         uint8 = 0x11 // HTTP response
	MsgTypeResponseHeader   uint8 = 0x12 // Response header (streaming)
	MsgTypeResponseChunk    uint8 = 0x13 // Response chunk (streaming)
	MsgTypeResponseEnd      uint8 = 0x14 // Response end (streaming)
	MsgTypeRequestStart     uint8 = 0x15 // HTTP request start (streaming)
	MsgTypeRequestChunkBin  uint8 = 0x16 // HTTP request body chunk (binary)
	MsgTypeRequestEnd       uint8 = 0x17 // HTTP request end (streaming)
	MsgTypeResponseChunkBin uint8 = 0x18 // HTTP response body chunk (binary)
	MsgTypeProxyConnect     uint8 = 0x20 // TCP proxy connect request
	MsgTypeProxyConnectAck  uint8 = 0x21 // TCP proxy connect acknowledgement
	MsgTypeProxyStreamMode  uint8 = 0x25 // Signal switch to direct stream mode
	// MsgTypeProxyData removed (legacy JSON format)
	MsgTypeProxyClose      uint8 = 0x23 // TCP proxy close
	MsgTypeProxyDataBinary uint8 = 0x24 // TCP proxy data (binary format)
	MsgTypeHeartbeat       uint8 = 0xF0 // Heartbeat/keepalive
	MsgTypeCancel          uint8 = 0xF1 // Cancel request
	MsgTypeProbePing       uint8 = 0xF2 // Active probe ping
	MsgTypeProbePong       uint8 = 0xF3 // Active probe pong

	// Port forwarding between endpoints
	MsgTypePortForwardRequest  uint8 = 0x30 // Request port forward through APS
	MsgTypePortForwardResponse uint8 = 0x31 // Response to port forward request
	MsgTypePortForwardData     uint8 = 0x32 // Port forward data
	MsgTypePortForwardClose    uint8 = 0x33 // Port forward close

	// Configuration management
	MsgTypeConfigUpdate uint8 = 0x40 // APS pushes config update to endpoint
	MsgTypeMirrorUpdate uint8 = 0x41 // APS sends mirror addresses to endpoint

	// Key negotiation for dynamic encryption
	MsgTypeKeyRequest  uint8 = 0x50 // Request new session key negotiation
	MsgTypeKeyResponse uint8 = 0x51 // Response with encrypted new key
	MsgTypeKeyConfirm  uint8 = 0x52 // Confirmation key is activated
)

const (
	// SecureCipherSuiteSPKICIDTS enforces SPKI + CID + Timestamp secure transport.
	SecureCipherSuiteSPKITS = "spki-cid-ts-v2"
)

// Message header size: 4 bytes length + 1 byte type
const headerSize = 5
const pooledFrameMaxSize = 256 * 1024

const (
	defaultMaxMessageSize    = 32 * 1024 * 1024
	maxMessageSizeUpperBound = 32 * 1024 * 1024
	minMessageSizeLowerBound = 1 * 1024 * 1024
	maxFrameSizeEnv          = "APS_TUNNEL_MAX_FRAME_MB"
)

var maxMessageSize = loadTunnelMaxMessageSize()
var framePool = sync.Pool{
	New: func() any {
		return make([]byte, pooledFrameMaxSize)
	},
}

// TunnelMessage represents a message in the TCP tunnel protocol
type TunnelMessage struct {
	Type    uint8
	Payload []byte
}

// RegisterPayload is sent by endpoint to register with APS
type RegisterPayload struct {
	TunnelName   string `json:"tunnel_name"`
	EndpointName string `json:"endpoint_name"`
	ServerName   string `json:"server_name,omitempty"`
	ConfigID     string `json:"cid"`
	Timestamp    int64  `json:"ts"`
	AuthProof    string `json:"auth_proof"`
	ServerHost   string `json:"server_host,omitempty"`
	PinHash      string `json:"pin_hash,omitempty"`
	CipherSuite  string `json:"cipher_suite,omitempty"`
}

// RegisterAckPayload is sent by APS to acknowledge registration
type RegisterAckPayload struct {
	Success            bool   `json:"success"`
	Error              string `json:"error,omitempty"`
	CipherSuite        string `json:"cipher_suite,omitempty"`
	GridNodeID         string `json:"grid_node_id,omitempty"`
	GridSessionToken   string `json:"grid_session_token,omitempty"`
	GridSessionExpires int64  `json:"grid_session_expires,omitempty"`
}

// RequestPayloadTCP represents an HTTP request sent via tunnel
type RequestPayloadTCP struct {
	ID                string   `json:"id"`
	URL               string   `json:"url"`
	Data              []byte   `json:"data"` // HTTP request bytes (encrypted unless GridPayloadPlain=true)
	RouteID           string   `json:"route_id,omitempty"`
	RouteEpoch        int64    `json:"route_epoch,omitempty"`
	HopCount          int      `json:"hop_count,omitempty"`
	TraceID           string   `json:"trace_id,omitempty"`
	GridRouteTo       string   `json:"grid_route_to,omitempty"`   // APS-side immediate route target endpoint
	GridNextHop       string   `json:"grid_next_hop,omitempty"`   // receiver-side next hop endpoint
	GridHops          []string `json:"grid_hops,omitempty"`       // remaining receiver-side hop list
	GridFinalHost     string   `json:"grid_final_host,omitempty"` // final egress host on last endpoint
	GridFinalPort     int      `json:"grid_final_port,omitempty"` // final egress port on last endpoint
	GridFinalTLS      bool     `json:"grid_final_tls,omitempty"`  // final egress tls flag on last endpoint
	GridEnableQUIC    bool     `json:"grid_enable_quic,omitempty"`
	GridEnableTCP     bool     `json:"grid_enable_tcp,omitempty"`
	GridParallel      bool     `json:"grid_parallel,omitempty"`
	GridEnableICE     bool     `json:"grid_enable_ice,omitempty"`
	GridICECandidates []string `json:"grid_ice_candidates,omitempty"`
	GridPayloadPlain  bool     `json:"grid_payload_plain,omitempty"` // stream payload is plain bytes (not KeyManager encrypted)
}

// RequestStartPayloadTCP represents an HTTP request header for streaming mode
type RequestStartPayloadTCP struct {
	ID                string   `json:"id"`
	URL               string   `json:"url"`
	Header            []byte   `json:"header"` // HTTP request header bytes (encrypted unless GridPayloadPlain=true)
	RouteID           string   `json:"route_id,omitempty"`
	RouteEpoch        int64    `json:"route_epoch,omitempty"`
	HopCount          int      `json:"hop_count,omitempty"`
	TraceID           string   `json:"trace_id,omitempty"`
	GridRouteTo       string   `json:"grid_route_to,omitempty"`   // APS-side immediate route target endpoint
	GridNextHop       string   `json:"grid_next_hop,omitempty"`   // receiver-side next hop endpoint
	GridHops          []string `json:"grid_hops,omitempty"`       // remaining receiver-side hop list
	GridFinalHost     string   `json:"grid_final_host,omitempty"` // final egress host on last endpoint
	GridFinalPort     int      `json:"grid_final_port,omitempty"` // final egress port on last endpoint
	GridFinalTLS      bool     `json:"grid_final_tls,omitempty"`  // final egress tls flag on last endpoint
	GridEnableQUIC    bool     `json:"grid_enable_quic,omitempty"`
	GridEnableTCP     bool     `json:"grid_enable_tcp,omitempty"`
	GridParallel      bool     `json:"grid_parallel,omitempty"`
	GridEnableICE     bool     `json:"grid_enable_ice,omitempty"`
	GridICECandidates []string `json:"grid_ice_candidates,omitempty"`
	GridPayloadPlain  bool     `json:"grid_payload_plain,omitempty"` // stream payload is plain bytes (not KeyManager encrypted)
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

// RequestEndPayloadTCP marks the end of request body streaming
type RequestEndPayloadTCP struct {
	ID    string `json:"id"`
	Error string `json:"error,omitempty"`
}

// ResponseEndPayloadTCP marks the end of a response
type ResponseEndPayloadTCP struct {
	ID    string `json:"id"`
	Error string `json:"error,omitempty"`
}

// ProxyConnectPayload is sent by APS to request TCP proxy connection
type ProxyConnectPayload struct {
	ConnectionID      string   `json:"connection_id"`
	Host              string   `json:"host"`
	Port              int      `json:"port"`
	TLS               bool     `json:"tls"`
	ClientIP          string   `json:"client_ip"`   // Real client IP for audit
	StreamMode        bool     `json:"stream_mode"` // If true, switch to zero-copy stream mode
	RouteID           string   `json:"route_id,omitempty"`
	RouteEpoch        int64    `json:"route_epoch,omitempty"`
	HopCount          int      `json:"hop_count,omitempty"`
	TraceID           string   `json:"trace_id,omitempty"`
	GridRouteTo       string   `json:"grid_route_to,omitempty"`   // APS-side immediate route target endpoint
	GridNextHop       string   `json:"grid_next_hop,omitempty"`   // receiver-side next hop endpoint
	GridHops          []string `json:"grid_hops,omitempty"`       // remaining receiver-side hop list
	GridFinalHost     string   `json:"grid_final_host,omitempty"` // final egress host on last endpoint
	GridFinalPort     int      `json:"grid_final_port,omitempty"` // final egress port on last endpoint
	GridFinalTLS      bool     `json:"grid_final_tls,omitempty"`  // final egress tls flag on last endpoint
	GridEnableQUIC    bool     `json:"grid_enable_quic,omitempty"`
	GridEnableTCP     bool     `json:"grid_enable_tcp,omitempty"`
	GridParallel      bool     `json:"grid_parallel,omitempty"`
	GridEnableICE     bool     `json:"grid_enable_ice,omitempty"`
	GridICECandidates []string `json:"grid_ice_candidates,omitempty"`
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

// MirrorUpdatePayload is sent by server to inform endpoint of mirror APS addresses
type MirrorUpdatePayload struct {
	Mirrors []string `json:"mirrors"` // Format: ["addr:port", "cid@addr:port", ...]
}

// HeartbeatPayload for keepalive
type HeartbeatPayload struct {
	Timestamp int64 `json:"timestamp"`
}

// ProbePayload is used for active latency probes
type ProbePayload struct {
	Nonce     uint64 `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
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

	if uint32(len(msg.Payload)) > maxMessageSize {
		return fmt.Errorf("message too large: %d bytes", len(msg.Payload))
	}

	frameLen := headerSize + len(msg.Payload)

	var frame []byte
	var pooled []byte
	if frameLen <= pooledFrameMaxSize {
		pooled = framePool.Get().([]byte)
		frame = pooled[:frameLen]
	} else {
		frame = make([]byte, frameLen)
	}
	if pooled != nil {
		defer framePool.Put(pooled)
	}

	// Build frame: length (4) + type (1) + payload
	binary.BigEndian.PutUint32(frame[:4], uint32(len(msg.Payload)))
	frame[4] = msg.Type
	copy(frame[headerSize:], msg.Payload)

	totalWritten := 0
	for totalWritten < len(frame) {
		n, err := tc.conn.Write(frame[totalWritten:])
		if n > 0 {
			totalWritten += n
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}

	return nil
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

// BuildScopedBinaryPayload builds payload format: [idLen(1)][id][data...]
func BuildScopedBinaryPayload(scopeID string, data []byte) ([]byte, error) {
	if len(scopeID) == 0 {
		return nil, errors.New("scope id is required")
	}
	if len(scopeID) > 255 {
		return nil, errors.New("scope id too long")
	}

	payload := make([]byte, 1+len(scopeID)+len(data))
	payload[0] = byte(len(scopeID))
	copy(payload[1:], scopeID)
	copy(payload[1+len(scopeID):], data)
	return payload, nil
}

// ParseScopedBinaryPayload parses payload format: [idLen(1)][id][data...]
func ParseScopedBinaryPayload(payload []byte) (string, []byte, error) {
	if len(payload) < 1 {
		return "", nil, errors.New("invalid scoped payload: too short")
	}
	idLen := int(payload[0])
	if idLen <= 0 {
		return "", nil, errors.New("invalid scoped payload: empty id")
	}
	if len(payload) < 1+idLen {
		return "", nil, errors.New("invalid scoped payload: truncated id")
	}
	return string(payload[1 : 1+idLen]), payload[1+idLen:], nil
}

func loadTunnelMaxMessageSize() uint32 {
	raw := os.Getenv(maxFrameSizeEnv)
	if raw == "" {
		return uint32(defaultMaxMessageSize)
	}

	mb, err := strconv.Atoi(raw)
	if err != nil || mb <= 0 {
		return uint32(defaultMaxMessageSize)
	}

	bytes := mb * 1024 * 1024
	if bytes > maxMessageSizeUpperBound {
		bytes = maxMessageSizeUpperBound
	}
	if bytes < minMessageSizeLowerBound {
		bytes = minMessageSizeLowerBound
	}
	return uint32(bytes)
}
