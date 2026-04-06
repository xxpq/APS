package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"
)

// Local buffer pools for the endpoint client
var (
	mediumBufPool        = sync.Pool{New: func() any { return make([]byte, 64*1024) }}
	largeBufPool         = sync.Pool{New: func() any { return make([]byte, 256*1024) }}
	activeTunnelRequests int64
	requestStreams       sync.Map // map[string]*requestStreamState
	sessionHolder        = struct {
		mu      sync.RWMutex
		session *smux.Session
	}{}
	relayTransitDedup = struct {
		mu    sync.Mutex
		locks map[string]time.Time
	}{
		locks: make(map[string]time.Time),
	}
	gridFrameIntegritySeen = struct {
		mu   sync.Mutex
		seen map[string]int64
	}{
		seen: make(map[string]int64),
	}
	portMapperRuntime = struct {
		mu     sync.Mutex
		mapper *PortMapper
		owner  *TunnelConn
	}{}
)

func applyPortMappingsRuntime(mappings []PortMappingConfig, tc *TunnelConn) {
	normalized := clonePortMappingsForContext(mappings)

	portMapperRuntime.mu.Lock()
	defer portMapperRuntime.mu.Unlock()

	if len(normalized) == 0 {
		if portMapperRuntime.mapper != nil {
			portMapperRuntime.mapper.Stop()
			portMapperRuntime.mapper = nil
			portMapper = nil
			log.Printf("[PORT-MAP] Disabled (no mappings)")
		}
		if portMapperRuntime.owner == tc {
			portMapperRuntime.owner = nil
		}
		return
	}

	if portMapperRuntime.mapper == nil {
		pm := NewPortMapper(normalized)
		pm.SetTunnelConn(tc)
		if err := pm.Start(); err != nil {
			log.Printf("[PORT-MAP] Failed to apply mappings: %v", err)
		}
		portMapperRuntime.mapper = pm
		portMapper = pm
		portMapperRuntime.owner = tc
		log.Printf("[PORT-MAP] Applied %d mapping(s)", len(normalized))
		return
	}

	portMapperRuntime.mapper.UpdateMappings(normalized)
	portMapperRuntime.mapper.SetTunnelConn(tc)
	portMapperRuntime.owner = tc
	portMapper = portMapperRuntime.mapper
	log.Printf("[PORT-MAP] Updated %d mapping(s)", len(normalized))
}

func releasePortMappingsTunnel(tc *TunnelConn) {
	portMapperRuntime.mu.Lock()
	defer portMapperRuntime.mu.Unlock()

	if portMapperRuntime.owner != tc {
		return
	}
	if portMapperRuntime.mapper != nil {
		portMapperRuntime.mapper.SetTunnelConn(nil)
	}
	portMapperRuntime.owner = nil
}

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

func setActiveTunnelSession(session *smux.Session) {
	sessionHolder.mu.Lock()
	sessionHolder.session = session
	sessionHolder.mu.Unlock()
}

func getActiveTunnelSession() *smux.Session {
	sessionHolder.mu.RLock()
	defer sessionHolder.mu.RUnlock()
	return sessionHolder.session
}

// TCP Tunnel Protocol Message Types (must match APS side)
const (
	MsgTypeRegister         uint8 = 0x01
	MsgTypeRegisterAck      uint8 = 0x02
	MsgTypeRequest          uint8 = 0x10
	MsgTypeResponse         uint8 = 0x11
	MsgTypeResponseHeader   uint8 = 0x12
	MsgTypeResponseChunk    uint8 = 0x13
	MsgTypeResponseEnd      uint8 = 0x14
	MsgTypeRequestStart     uint8 = 0x15
	MsgTypeRequestChunkBin  uint8 = 0x16
	MsgTypeRequestEnd       uint8 = 0x17
	MsgTypeResponseChunkBin uint8 = 0x18
	MsgTypeProxyConnect     uint8 = 0x20
	MsgTypeProxyConnectAck  uint8 = 0x21
	MsgTypeProxyStreamMode  uint8 = 0x25
	// MsgTypeProxyData removed
	MsgTypeProxyClose      uint8 = 0x23
	MsgTypeProxyDataBinary uint8 = 0x24
	MsgTypeHeartbeat       uint8 = 0xF0
	MsgTypeCancel          uint8 = 0xF1
	MsgTypeProbePing       uint8 = 0xF2
	MsgTypeProbePong       uint8 = 0xF3

	// Port forwarding between endpoints
	MsgTypePortForwardRequest  uint8 = 0x30
	MsgTypePortForwardResponse uint8 = 0x31
	MsgTypePortForwardData     uint8 = 0x32
	MsgTypePortForwardClose    uint8 = 0x33

	// Configuration management
	MsgTypeConfigUpdate uint8 = 0x40 // APS pushes config update to endpoint
	MsgTypeMirrorUpdate uint8 = 0x41 // APS sends mirror addresses to endpoint

	// Key negotiation for dynamic encryption
	MsgTypeKeyRequest  uint8 = 0x50 // Request new session key negotiation
	MsgTypeKeyResponse uint8 = 0x51 // Response with encrypted new key
	MsgTypeKeyConfirm  uint8 = 0x52 // Confirmation key is activated
)

const (
	// SecureCipherSuiteSPKITS enforces SPKI + CID + Timestamp secure transport.
	SecureCipherSuiteSPKITS = "spki-cid-ts-v2"
)

const headerSize = 5
const connectHandshakeTimeout = 15 * time.Second
const pooledFrameMaxSize = 256 * 1024

const (
	defaultMaxMessageSize    = 32 * 1024 * 1024
	maxMessageSizeUpperBound = 32 * 1024 * 1024
	minMessageSizeLowerBound = 1 * 1024 * 1024
	maxFrameSizeEnv          = "APS_TUNNEL_MAX_FRAME_MB"
	endpointHopGuardMax      = 128
	relayTransitDedupTTL     = 20 * time.Second
	gridFrameIntegrityWindow = 60 * time.Second
	gridFrameIntegrityMaxSet = 32768
	gridFrameIntegrityNonceN = 12
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

// RegisterPayload for registration
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

// RegisterAckPayload for registration response
type RegisterAckPayload struct {
	Success            bool   `json:"success"`
	Error              string `json:"error,omitempty"`
	CipherSuite        string `json:"cipher_suite,omitempty"`
	GridNodeID         string `json:"grid_node_id,omitempty"`
	GridSessionToken   string `json:"grid_session_token,omitempty"`
	GridSessionExpires int64  `json:"grid_session_expires,omitempty"`
}

// RequestPayloadTCP for HTTP request
type RequestPayloadTCP struct {
	ID                string   `json:"id"`
	URL               string   `json:"url"`
	Data              []byte   `json:"data"`
	RouteID           string   `json:"route_id,omitempty"`
	RouteEpoch        int64    `json:"route_epoch,omitempty"`
	HopCount          int      `json:"hop_count,omitempty"`
	TraceID           string   `json:"trace_id,omitempty"`
	GridRouteTo       string   `json:"grid_route_to,omitempty"`
	GridNextHop       string   `json:"grid_next_hop,omitempty"`
	GridHops          []string `json:"grid_hops,omitempty"`
	GridFinalHost     string   `json:"grid_final_host,omitempty"`
	GridFinalPort     int      `json:"grid_final_port,omitempty"`
	GridFinalTLS      bool     `json:"grid_final_tls,omitempty"`
	GridEnableQUIC    bool     `json:"grid_enable_quic,omitempty"`
	GridEnableTCP     bool     `json:"grid_enable_tcp,omitempty"`
	GridParallel      bool     `json:"grid_parallel,omitempty"`
	GridEnableICE     bool     `json:"grid_enable_ice,omitempty"`
	GridICECandidates []string `json:"grid_ice_candidates,omitempty"`
	GridPayloadPlain  bool     `json:"grid_payload_plain,omitempty"`
	GridIntegrityTS   int64    `json:"grid_integrity_ts,omitempty"`
	GridIntegrityN    string   `json:"grid_integrity_nonce,omitempty"`
	GridIntegritySig  string   `json:"grid_integrity_sig,omitempty"`
}

type RequestStartPayloadTCP struct {
	ID                string   `json:"id"`
	URL               string   `json:"url"`
	Header            []byte   `json:"header"`
	RouteID           string   `json:"route_id,omitempty"`
	RouteEpoch        int64    `json:"route_epoch,omitempty"`
	HopCount          int      `json:"hop_count,omitempty"`
	TraceID           string   `json:"trace_id,omitempty"`
	GridRouteTo       string   `json:"grid_route_to,omitempty"`
	GridNextHop       string   `json:"grid_next_hop,omitempty"`
	GridHops          []string `json:"grid_hops,omitempty"`
	GridFinalHost     string   `json:"grid_final_host,omitempty"`
	GridFinalPort     int      `json:"grid_final_port,omitempty"`
	GridFinalTLS      bool     `json:"grid_final_tls,omitempty"`
	GridEnableQUIC    bool     `json:"grid_enable_quic,omitempty"`
	GridEnableTCP     bool     `json:"grid_enable_tcp,omitempty"`
	GridParallel      bool     `json:"grid_parallel,omitempty"`
	GridEnableICE     bool     `json:"grid_enable_ice,omitempty"`
	GridICECandidates []string `json:"grid_ice_candidates,omitempty"`
	GridPayloadPlain  bool     `json:"grid_payload_plain,omitempty"`
	GridIntegrityTS   int64    `json:"grid_integrity_ts,omitempty"`
	GridIntegrityN    string   `json:"grid_integrity_nonce,omitempty"`
	GridIntegritySig  string   `json:"grid_integrity_sig,omitempty"`
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

type RequestEndPayloadTCP struct {
	ID    string `json:"id"`
	Error string `json:"error,omitempty"`
}

// ResponseEndPayloadTCP marks end of response
type ResponseEndPayloadTCP struct {
	ID    string `json:"id"`
	Error string `json:"error,omitempty"`
}

type requestStreamState struct {
	id         string
	pipeReader *io.PipeReader
	pipeWriter *io.PipeWriter
	km         *SessionKeyManager
}

type multiReadCloser struct {
	reader  io.Reader
	closers []io.Closer
}

func (m *multiReadCloser) Read(p []byte) (int, error) {
	return m.reader.Read(p)
}

func (m *multiReadCloser) Close() error {
	var closeErr error
	for _, closer := range m.closers {
		if closer == nil {
			continue
		}
		if err := closer.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}

// ProxyConnectPayload for TCP proxy connect
type ProxyConnectPayload struct {
	ConnectionID      string   `json:"connection_id"`
	Host              string   `json:"host"`
	Port              int      `json:"port"`
	TLS               bool     `json:"tls"`
	ClientIP          string   `json:"client_ip"`
	StreamMode        bool     `json:"stream_mode"`
	RouteID           string   `json:"route_id,omitempty"`
	RouteEpoch        int64    `json:"route_epoch,omitempty"`
	HopCount          int      `json:"hop_count,omitempty"`
	TraceID           string   `json:"trace_id,omitempty"`
	GridRouteTo       string   `json:"grid_route_to,omitempty"`
	GridNextHop       string   `json:"grid_next_hop,omitempty"`
	GridHops          []string `json:"grid_hops,omitempty"`
	GridFinalHost     string   `json:"grid_final_host,omitempty"`
	GridFinalPort     int      `json:"grid_final_port,omitempty"`
	GridFinalTLS      bool     `json:"grid_final_tls,omitempty"`
	GridEnableQUIC    bool     `json:"grid_enable_quic,omitempty"`
	GridEnableTCP     bool     `json:"grid_enable_tcp,omitempty"`
	GridParallel      bool     `json:"grid_parallel,omitempty"`
	GridEnableICE     bool     `json:"grid_enable_ice,omitempty"`
	GridICECandidates []string `json:"grid_ice_candidates,omitempty"`
	GridIntegrityTS   int64    `json:"grid_integrity_ts,omitempty"`
	GridIntegrityN    string   `json:"grid_integrity_nonce,omitempty"`
	GridIntegritySig  string   `json:"grid_integrity_sig,omitempty"`
}

// ProxyConnectAckPayload for proxy connect response
type ProxyConnectAckPayload struct {
	ConnectionID string `json:"connection_id"`
	Success      bool   `json:"success"`
	Error        string `json:"error,omitempty"`
}

// ProxyStreamModePayload for stream mode signal
type ProxyStreamModePayload struct {
	ConnectionID string `json:"connection_id"`
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

type ProbePayload struct {
	Nonce     uint64 `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
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

func closeTunnelConnWithReason(tc *TunnelConn, reason string) {
	if tc == nil {
		return
	}
	if err := tc.Close(); err != nil {
		log.Printf("[CONN] Close requested (%s), close error: %v", reason, err)
		return
	}
	DebugLog("[CONN] Close requested (%s)", reason)
}

// ParseJSON unmarshals payload
func (msg *TunnelMessage) ParseJSON(v interface{}) error {
	return json.Unmarshal(msg.Payload, v)
}

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

type prefixedConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixedConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

func tunnelPeerSPKIHashFromConn(conn net.Conn) ([]byte, string, error) {
	current := conn
	for i := 0; i < 4 && current != nil; i++ {
		switch c := current.(type) {
		case *prefixedConn:
			current = c.Conn
			continue
		case *tls.Conn:
			state := c.ConnectionState()
			if len(state.PeerCertificates) == 0 {
				return nil, "", errors.New("tls peer certificate missing")
			}
			sum := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			hash := append([]byte(nil), sum[:]...)
			return hash, hex.EncodeToString(hash), nil
		case interface{ ConnectionState() tls.ConnectionState }:
			state := c.ConnectionState()
			if len(state.PeerCertificates) == 0 {
				return nil, "", errors.New("tls peer certificate missing")
			}
			sum := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			hash := append([]byte(nil), sum[:]...)
			return hash, hex.EncodeToString(hash), nil
		default:
			return nil, "", fmt.Errorf("connection type %T does not expose tls state", current)
		}
	}
	return nil, "", errors.New("unable to unwrap tunnel tls connection state")
}

func deriveRegistrationProofKey(password, cid string, pinHash []byte, kdfVersion, kdfSalt string) ([]byte, error) {
	baseKey, err := deriveInitialKeyWithKDF(password, kdfVersion, kdfSalt)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, baseKey)
	mac.Write([]byte("registration-proof-v3"))
	mac.Write([]byte{':'})
	mac.Write([]byte(strings.TrimSpace(cid)))
	mac.Write([]byte{':'})
	mac.Write(pinHash)
	return mac.Sum(nil), nil
}

func computeSecureRegistrationProof(password, cid, tunnelName, endpointName, serverHost, pinHashHex, cipherSuite string, ts int64, kdfVersion, kdfSalt string) (string, error) {
	key, err := deriveRegistrationProofKey(password, cid, []byte(pinHashHex), kdfVersion, kdfSalt)
	if err != nil {
		return "", err
	}
	message := strings.Join([]string{
		cid,
		tunnelName,
		endpointName,
		serverHost,
		pinHashHex,
		cipherSuite,
		strconv.FormatInt(ts, 10),
	}, "|")
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func buildTunnelTLSConfig(serverHost string, expectedPinHash []byte, enforceTLSPin bool, connCtx ImmutableConnectionContext) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverHost,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("missing peer certificate")
			}
			if !enforceTLSPin {
				return nil
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if !hmac.Equal(sum[:], expectedPinHash) {
				return errors.New("tls pin mismatch")
			}
			return nil
		},
	}

	if strings.TrimSpace(connCtx.MTLSCAFile) != "" {
		caPEM, err := os.ReadFile(strings.TrimSpace(connCtx.MTLSCAFile))
		if err != nil {
			return nil, fmt.Errorf("failed to read mtls CA file: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("failed to parse mtls CA file")
		}
		tlsConfig.RootCAs = roots
	}

	certPath := strings.TrimSpace(connCtx.MTLSCertFile)
	keyPath := strings.TrimSpace(connCtx.MTLSKeyFile)
	if certPath != "" || keyPath != "" {
		if certPath == "" || keyPath == "" {
			return nil, errors.New("both -mtls-cert and -mtls-key are required together")
		}
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load mTLS client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

func connectWithHTTPTunnelHandshake(conn net.Conn, serverAddress string) (net.Conn, error) {
	handshakeReq := fmt.Sprintf(
		"CONNECT /.tunnel HTTP/1.1\r\nHost: %s\r\nUser-Agent: aps-endpoint/%s\r\nConnection: keep-alive\r\nProxy-Connection: keep-alive\r\n\r\n",
		serverAddress,
		endpointVersion,
	)

	if err := conn.SetDeadline(time.Now().Add(connectHandshakeTimeout)); err != nil {
		return nil, err
	}
	defer conn.SetDeadline(time.Time{})

	if _, err := io.WriteString(conn, handshakeReq); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	req := &http.Request{Method: http.MethodConnect}
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes := []byte{}
		if resp.Body != nil {
			bodyBytes, _ = io.ReadAll(io.LimitReader(resp.Body, 256))
			resp.Body.Close()
		}
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}
	// CONNECT 200 switches to tunnel mode immediately. Do not consume resp.Body here.

	buffered := reader.Buffered()
	if buffered == 0 {
		return conn, nil
	}
	prefixBytes, err := reader.Peek(buffered)
	if err != nil {
		return nil, err
	}
	prefix := make([]byte, len(prefixBytes))
	copy(prefix, prefixBytes)
	return &prefixedConn{Conn: conn, prefix: prefix}, nil
}

func dialTunnelServer(serverAddress, serverHost string, expectedPinHash []byte, enforceTLSPin bool, connCtx ImmutableConnectionContext) (net.Conn, error) {
	tlsConfig, err := buildTunnelTLSConfig(serverHost, expectedPinHash, enforceTLSPin, connCtx)
	if err != nil {
		return nil, err
	}

	establishTunnel := func(rawConn net.Conn) (net.Conn, error) {
		if rawConn == nil {
			return nil, errors.New("raw connection is nil")
		}
		tlsConn := tls.Client(rawConn, tlsConfig)
		if err := tlsConn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("tls deadline setup failed: %w", err)
		}
		if err := tlsConn.Handshake(); err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("tls handshake failed: %w", err)
		}
		_ = tlsConn.SetDeadline(time.Time{})

		upgradedConn, err := connectWithHTTPTunnelHandshake(tlsConn, serverAddress)
		if err != nil {
			_ = tlsConn.Close()
			return nil, fmt.Errorf("CONNECT /.tunnel over TLS failed: %w", err)
		}
		return upgradedConn, nil
	}

	dialAndEstablishDirect := func(timeout time.Duration) (net.Conn, error) {
		if timeout <= 0 {
			timeout = 12 * time.Second
		}
		dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
		rawConn, err := dialer.Dial("tcp", serverAddress)
		if err != nil {
			return nil, fmt.Errorf("direct dial failed: %w", err)
		}
		conn, err := establishTunnel(rawConn)
		if err != nil {
			return nil, fmt.Errorf("direct tunnel setup failed: %w", err)
		}
		return conn, nil
	}

	var envProxyURL *url.URL
	targetURL := &url.URL{Scheme: "https", Host: serverAddress}
	if parsedProxyURL, proxyErr := endpointProxyURLForTarget(targetURL); proxyErr != nil {
		DebugLog("[CONN] Failed to resolve environment proxy for APS %s: %v", serverAddress, proxyErr)
	} else if parsedProxyURL != nil {
		envProxyURL = parsedProxyURL
	}

	dialAndEstablishEnvProxy := func(proxyURL *url.URL, timeout time.Duration) (net.Conn, error) {
		if proxyURL == nil {
			return nil, errors.New("environment proxy is nil")
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		rawConn, err := dialTargetViaEnvironmentProxy(ctx, serverAddress, proxyURL, timeout)
		if err != nil {
			return nil, fmt.Errorf("dial via env proxy failed: %w", err)
		}
		conn, err := establishTunnel(rawConn)
		if err != nil {
			return nil, fmt.Errorf("env proxy tunnel setup failed: %w", err)
		}
		return conn, nil
	}

	dialAndEstablishGateway := func(candidate string) (net.Conn, error) {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			return nil, errors.New("empty gateway candidate")
		}
		rawConn, err := dialTunnelServerViaGateway(candidate, serverAddress, connCtx.ConfigID)
		if err != nil {
			return nil, fmt.Errorf("dial via gateway failed: %w", err)
		}
		conn, err := establishTunnel(rawConn)
		if err != nil {
			return nil, fmt.Errorf("gateway tunnel setup failed: %w", err)
		}
		return conn, nil
	}

	gatewayCandidates := resolveGatewayAddressCandidates(connCtx)
	type dialAttemptResult struct {
		kind      string // direct|gateway|env-proxy
		candidate string
		conn      net.Conn
		err       error
	}

	totalAttempts := 1
	if envProxyURL != nil {
		totalAttempts++
	}
	for _, raw := range gatewayCandidates {
		if strings.TrimSpace(raw) != "" {
			totalAttempts++
		}
	}
	results := make(chan dialAttemptResult, totalAttempts)

	go func() {
		conn, err := dialAndEstablishDirect(12 * time.Second)
		results <- dialAttemptResult{kind: "direct", conn: conn, err: err}
	}()
	if envProxyURL != nil {
		proxyLabel := envProxyURL.Redacted()
		go func(proxyURL *url.URL, label string) {
			conn, err := dialAndEstablishEnvProxy(proxyURL, 12*time.Second)
			results <- dialAttemptResult{kind: "env-proxy", candidate: label, conn: conn, err: err}
		}(envProxyURL, proxyLabel)
	}
	for _, raw := range gatewayCandidates {
		candidate := strings.TrimSpace(raw)
		if candidate == "" {
			continue
		}
		go func(addr string) {
			conn, err := dialAndEstablishGateway(addr)
			results <- dialAttemptResult{kind: "gateway", candidate: addr, conn: conn, err: err}
		}(candidate)
	}

	errorParts := make([]string, 0, totalAttempts)
	received := 0
	for received < totalAttempts {
		res := <-results
		received++
		if res.err == nil && res.conn != nil {
			if res.kind == "direct" {
				markGatewayDirectTargetReachable(connCtx.ServerAddress)
				DebugLog("[CONN] Selected direct APS path for %s", serverAddress)
			} else if res.kind == "env-proxy" {
				markGatewayDirectTargetReachable(connCtx.ServerAddress)
				DebugLog("[CONN] Selected environment proxy APS path for %s via %s", serverAddress, strings.TrimSpace(res.candidate))
			} else {
				promoteGatewayRouteCacheCandidate(connCtx.ServerAddress, res.candidate)
				DebugLog("[GATEWAY] Using gateway %s for APS %s (race winner)", res.candidate, serverAddress)
			}

			remaining := totalAttempts - received
			if remaining > 0 {
				go func(rem int) {
					for i := 0; i < rem; i++ {
						r := <-results
						if r.conn != nil {
							_ = r.conn.Close()
						}
					}
				}(remaining)
			}

			DebugLog("[CONN] CONNECT /.tunnel handshake over TLS succeeded")
			return res.conn, nil
		}

		if res.conn != nil {
			_ = res.conn.Close()
		}
		if res.kind == "gateway" {
			if isGatewayTargetNotAllowedError(res.err) {
				markGatewayRouteDenied(connCtx.ServerAddress, res.candidate)
			}
			markGatewayRouteCacheCandidateFailure(connCtx.ServerAddress, res.candidate)
			DebugLog("[GATEWAY] Dial via %s failed for APS %s: %v", res.candidate, serverAddress, res.err)
		} else if res.kind == "env-proxy" {
			DebugLog("[CONN] Environment proxy path failed for APS %s via %s: %v", serverAddress, strings.TrimSpace(res.candidate), res.err)
		} else {
			DebugLog("[CONN] Direct path failed for APS %s: %v", serverAddress, res.err)
		}

		label := res.kind
		if res.kind == "gateway" {
			label = "gateway(" + strings.TrimSpace(res.candidate) + ")"
		}
		if res.kind == "env-proxy" {
			label = "env-proxy(" + strings.TrimSpace(res.candidate) + ")"
		}
		errText := "unknown error"
		if res.err != nil {
			errText = strings.TrimSpace(res.err.Error())
		}
		errorParts = append(errorParts, label+": "+errText)
	}

	return nil, fmt.Errorf("all connect attempts failed for APS %s: %s", serverAddress, strings.Join(errorParts, "; "))
}

func isGatewayTargetNotAllowedError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "target not allowed")
}

// runTCPTunnelSession connects to APS via TCP tunnel protocol
type TunnelSessionState struct {
	mu                  sync.RWMutex
	TunnelName          string
	EndpointName        string
	SessionCredential   string
	SessionExpiresAt    int64
	GridNodeID          string
	GridSessionToken    string
	GridSessionExpires  int64
	PortMappings        []PortMappingConfig
	GatewayListen       string
	GatewayAddress      string
	GatewayDiscovery    bool
	GatewayDiscoverPort int
	SSH                 *EndpointSSHConfig
	KDFVersion          string
	KDFSalt             string
}

func endpointGridBootstrapFromRegisterAck(ack RegisterAckPayload) (string, string, int64, error) {
	gridNodeID := strings.TrimSpace(ack.GridNodeID)
	if gridNodeID == "" {
		return "", "", 0, errors.New("registration failed: aps does not provide grid_node_id; endpoint requires grid-capable APS")
	}
	gridSessionToken := strings.TrimSpace(ack.GridSessionToken)
	if gridSessionToken == "" {
		return "", "", 0, errors.New("registration failed: aps does not provide grid_session_token; endpoint requires grid-capable APS")
	}
	if ack.GridSessionExpires <= 0 {
		return "", "", 0, errors.New("registration failed: aps does not provide valid grid_session_expires; endpoint requires grid-capable APS")
	}
	return gridNodeID, gridSessionToken, ack.GridSessionExpires, nil
}

func runTCPTunnelSession(ctx context.Context, connCtx ImmutableConnectionContext) bool {
	serverAddress := normalizeServerAddressForSession(connCtx.ServerAddress)
	DebugLog("Connecting to TCP tunnel server at %s", serverAddress)
	DebugLog("[CONN] Tunnel transport mode: strict TLS + CONNECT /.tunnel")
	ensureGatewayRuntime(connCtx)
	if strings.TrimSpace(connCtx.GatewayListen) != "" {
		started, listenAddr, startErr := gatewayRuntimeStateSnapshot()
		if !started {
			if startErr == "" {
				startErr = "gateway runtime not started"
			}
			log.Printf("Failed to connect: gateway runtime unavailable (listen=%s): %s", strings.TrimSpace(connCtx.GatewayListen), startErr)
			return true
		}
		DebugLog("[GATEWAY] Runtime ready on %s", listenAddr)
	}
	ensureEndpointICEConnectivityRuntime(connCtx)

	// 如果serverAddr不包含端口，则添加默认端口
	if serverAddress == "" {
		log.Printf("Failed to connect: empty server address")
		return true
	}

	regServerHost, regPinHash, enforceTLSPin, err := GetTLSPinRegistrationInfo(serverAddress)
	if err != nil {
		log.Printf("Failed to load TLS pin registration info: %v", err)
		return true
	}

	cid := strings.TrimSpace(connCtx.ConfigID)
	if cid == "" {
		log.Printf("Registration failed: config id (cid) is required for secure transport")
		return false
	}

	sessionCredential := strings.TrimSpace(connCtx.SessionCredential)
	if sessionCredential == "" {
		log.Printf("Registration failed: empty session credential is not allowed in secure mode")
		return false
	}

	if !enforceTLSPin {
		DebugLog("[CONN] Token override mode active: TLS transport pin enforcement relaxed for %s", serverAddress)
	}
	conn, err := dialTunnelServer(serverAddress, regServerHost, regPinHash, enforceTLSPin, connCtx)
	if err != nil {
		log.Printf("Failed to connect: %v", err)
		return true
	}

	// In token compatibility mode, align registration proof pin hash with the
	// actual negotiated tunnel peer certificate to avoid transient mismatch loops
	// when multiple APS paths race (direct/gateway/env-proxy).
	if !enforceTLSPin {
		liveHash, liveHashHex, liveHashErr := tunnelPeerSPKIHashFromConn(conn)
		if liveHashErr != nil {
			DebugLog("[CONN] Token mode could not inspect tunnel peer SPKI for %s: %v", serverAddress, liveHashErr)
		} else if !hmac.Equal(liveHash, regPinHash) {
			oldHashHex := hex.EncodeToString(regPinHash)
			oldHint := oldHashHex
			if len(oldHint) > 12 {
				oldHint = oldHint[:12]
			}
			regPinHash = append([]byte(nil), liveHash...)
			if pin, pinErr := ensureEndpointTLSPin(serverAddress); pinErr == nil {
				pin.addAllowedHashWithMode(liveHash, true)
			}
			newHint := liveHashHex
			if len(newHint) > 12 {
				newHint = newHint[:12]
			}
			DebugLog("[CONN] Token mode aligned registration pin hash for %s: %s... -> %s...", serverAddress, oldHint, newHint)
		}
	}

	tc := NewTunnelConn(conn)
	defer closeTunnelConnWithReason(tc, "runTCPTunnelSession exiting")

	// Optimize TCP connection for better throughput
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetReadBuffer(256 * 1024)  // 256KB
		tcpConn.SetWriteBuffer(256 * 1024) // 256KB
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(60 * time.Second)
	}

	regPinHashHex := hex.EncodeToString(regPinHash)
	regPinHint := regPinHashHex
	if len(regPinHint) > 12 {
		regPinHint = regPinHint[:12]
	}
	DebugLog("[CONN] Registration pin context host=%s hash=%s... enforce_tls_pin=%v", regServerHost, regPinHint, enforceTLSPin)
	regTS := time.Now().UTC().Unix()
	regProof, proofErr := computeSecureRegistrationProof(
		sessionCredential,
		cid,
		connCtx.TunnelName,
		connCtx.EndpointName,
		regServerHost,
		regPinHashHex,
		SecureCipherSuiteSPKITS,
		regTS,
		connCtx.KDFVersion,
		connCtx.KDFSalt,
	)
	if proofErr != nil {
		log.Printf("Failed to compute registration proof: %v", proofErr)
		return false
	}

	// Send registration using effective config values
	if err := tc.SendJSON(MsgTypeRegister, RegisterPayload{
		TunnelName:   connCtx.TunnelName,
		EndpointName: connCtx.EndpointName,
		ServerName:   strings.TrimSpace(connCtx.ServerName),
		ConfigID:     cid,
		Timestamp:    regTS,
		AuthProof:    regProof,
		ServerHost:   regServerHost,
		PinHash:      regPinHashHex,
		CipherSuite:  SecureCipherSuiteSPKITS,
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
		if strings.Contains(strings.ToLower(strings.TrimSpace(ack.Error)), "tls pin hash mismatch") {
			if enforceTLSPin {
				log.Printf("[CONN] APS rejected registration pin hash=%s... host=%s (strict transport pin mode)", regPinHint, regServerHost)
			} else {
				log.Printf("[CONN] APS rejected registration pin hash=%s... host=%s (token compatibility mode). Regenerate -token from current APS pin.", regPinHint, regServerHost)
			}
		}
		if isPermanentError(errors.New(ack.Error)) {
			return false
		}
		return true
	}
	if ack.CipherSuite != SecureCipherSuiteSPKITS {
		log.Printf("Registration failed: secure cipher suite negotiation failed (expected %s, got %s)", SecureCipherSuiteSPKITS, ack.CipherSuite)
		return false
	}
	gridNodeID, gridSessionToken, gridSessionExpires, gridBootstrapErr := endpointGridBootstrapFromRegisterAck(ack)
	if gridBootstrapErr != nil {
		log.Printf("%v", gridBootstrapErr)
		return true
	}

	log.Println("Successfully registered with TCP tunnel server")
	setEndpointGridControlSession(gridNodeID, gridSessionToken, gridSessionExpires)
	triggerEndpointGridControlMaintenance(serverAddress, connCtx, true)
	triggerEndpointGridICEMaintenance(serverAddress, connCtx, true)

	// Initialize session key manager
	keyManager := NewSessionKeyManager(sessionCredential, connCtx.EndpointName)
	if err := keyManager.SetKDFParams(connCtx.KDFVersion, connCtx.KDFSalt); err != nil {
		log.Printf("Failed to initialize KDF parameters: %v", err)
		return false
	}
	if err := keyManager.DeriveInitialKey(); err != nil {
		log.Printf("Failed to derive initial key: %v", err)
		return true
	}
	if err := keyManager.EnableSecureTransport(regPinHash, cid); err != nil {
		log.Printf("Failed to enable secure transport: %v", err)
		return false
	}

	// Upgrade to SMUX
	// Client side acts as SMUX client
	session, err := smux.Client(conn, nil)
	if err != nil {
		log.Printf("Failed to create SMUX client: %v", err)
		return false
	}
	setActiveTunnelSession(session)
	defer session.Close()
	defer setActiveTunnelSession(nil)

	// Open control stream
	controlStream, err := session.OpenStream()
	if err != nil {
		log.Printf("Failed to open control stream: %v", err)
		return false
	}
	DebugLog("Control stream established")

	// Use control stream for TunnelConn
	tc = NewTunnelConn(controlStream)

	// Start accepting incoming streams (for proxy connections)
	go acceptStreams(session, tc, keyManager)

	sessionState := &TunnelSessionState{
		TunnelName:          connCtx.TunnelName,
		EndpointName:        connCtx.EndpointName,
		SessionCredential:   connCtx.SessionCredential,
		SessionExpiresAt:    connCtx.SessionExpiresAt,
		GridNodeID:          gridNodeID,
		GridSessionToken:    gridSessionToken,
		GridSessionExpires:  gridSessionExpires,
		PortMappings:        clonePortMappingsForContext(connCtx.PortMappings),
		GatewayListen:       strings.TrimSpace(connCtx.GatewayListen),
		GatewayAddress:      strings.TrimSpace(connCtx.GatewayAddress),
		GatewayDiscovery:    connCtx.GatewayDiscovery,
		GatewayDiscoverPort: connCtx.GatewayDiscoverPort,
		SSH:                 cloneEndpointSSHConfigForContext(connCtx.SSH),
		KDFVersion:          connCtx.KDFVersion,
		KDFSalt:             connCtx.KDFSalt,
	}
	_ = EnsureNetCore()
	if err := endpointSSHManager.Apply(connCtx.SSH); err != nil {
		log.Printf("[SSH] Failed to apply runtime SSH config: %v", err)
	}
	applyPortMappingsRuntime(sessionState.PortMappings, tc)
	defer releasePortMappingsTunnel(tc)
	controlState := NewControlPlaneInboundState()

	// Start message handling loop (on control stream)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			// Set read deadline to detect dead connections
			// Server sends heartbeat every 30s, use 60s timeout for faster recovery
			tc.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			msg, err := tc.ReadMessage()
			if err != nil {
				if err != io.EOF {
					log.Printf("Read error: %v", err)
				}
				DebugLog("[CONN] Control read loop exiting, reconnect required")
				return
			}
			switch msg.Type {
			case MsgTypeRequestStart, MsgTypeRequestChunkBin, MsgTypeRequestEnd, MsgTypeProbePing, MsgTypeProbePong, MsgTypeHeartbeat, MsgTypeCancel:
				handleTCPMessage(tc, msg, keyManager, sessionState, controlState)
			default:
				go handleTCPMessage(tc, msg, keyManager, sessionState, controlState)
			}
		}
	}()

	// Start auto key rotation (endpoint can also initiate)
	go func() {
		select {
		case <-done:
			return
		case <-time.After(5 * time.Second):
			// Wait for connection to stabilize
		}
		select {
		case <-done:
			return
		default:
		}
		keyManager.StartAutoRotation(func() error {
			return initiateKeyRotation(tc, keyManager)
		})
	}()
	// Ensure key rotation is stopped when connection closes
	defer keyManager.StopAutoRotation()

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
			triggerEndpointGridControlMaintenance(serverAddress, connCtx, false)
			triggerEndpointGridICEMaintenance(serverAddress, connCtx, false)
			tc.SendJSON(MsgTypeHeartbeat, HeartbeatPayload{Timestamp: time.Now().UnixNano()})
		}
	}
}

// handleTCPMessage handles incoming messages
func handleTCPMessage(tc *TunnelConn, msg *TunnelMessage, km *SessionKeyManager, sessionState *TunnelSessionState, controlState *ControlPlaneInboundState) {
	switch msg.Type {
	case MsgTypeRequest:
		handleTCPRequest(tc, msg, km)
	case MsgTypeRequestStart:
		handleTCPRequestStart(tc, msg, km)
	case MsgTypeRequestChunkBin:
		handleTCPRequestChunkBinary(msg)
	case MsgTypeRequestEnd:
		handleTCPRequestEnd(msg)
	case MsgTypeProxyConnect:
		handleTCPProxyConnect(tc, msg)
	case MsgTypeProxyDataBinary:
		handleTCPProxyDataBinary(msg)
	case MsgTypeProxyClose:
		handleTCPProxyClose(msg)
	case MsgTypePortForwardRequest:
		handlePortForwardRequestMsg(tc, msg)
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
	case MsgTypeProbePing:
		handleTCPProbePing(tc, msg)
	case MsgTypeProbePong:
		// Endpoint currently only responds to probe pings.
	case MsgTypeConfigUpdate:
		plainPayload, err := UnwrapControlPlanePayload(km, msg.Type, msg.Payload, controlState)
		if err != nil {
			log.Printf("[CONTROL] ConfigUpdate rejected: %v", err)
			return
		}
		handleConfigUpdate(tc, &TunnelMessage{Type: msg.Type, Payload: plainPayload}, sessionState)

	case MsgTypeMirrorUpdate:
		plainPayload, err := UnwrapControlPlanePayload(km, msg.Type, msg.Payload, controlState)
		if err != nil {
			log.Printf("[CONTROL] MirrorUpdate rejected: %v", err)
			return
		}
		handleMirrorUpdate(tc, &TunnelMessage{Type: msg.Type, Payload: plainPayload})

	// Key rotation messages
	case MsgTypeKeyRequest:
		handleKeyRequest(tc, msg, km)
	case MsgTypeKeyResponse:
		handleKeyResponse(tc, msg, km)
	case MsgTypeKeyConfirm:
		handleKeyConfirm(tc, msg, km)
	}
}

func handleTCPRequestStart(tc *TunnelConn, msg *TunnelMessage, km *SessionKeyManager) {
	var reqPayload RequestStartPayloadTCP
	if err := msg.ParseJSON(&reqPayload); err != nil {
		log.Printf("Failed to parse request start: %v", err)
		return
	}

	requestID := reqPayload.ID
	if requestID == "" {
		return
	}
	if err := applyGridFrameMetadata(
		extractGridDestination(reqPayload.URL),
		reqPayload.RouteID,
		reqPayload.RouteEpoch,
		reqPayload.HopCount,
		reqPayload.TraceID,
	); err != nil {
		log.Printf("[ERROR %s] %v", requestID, err)
		sendTCPErrorResponse(tc, requestID, err.Error())
		return
	}

	decryptedHeader, err := km.Decrypt(reqPayload.Header)
	if err != nil {
		log.Printf("[ERROR %s] Decrypt request header failed: %v", requestID, err)
		sendTCPErrorResponse(tc, requestID, "decryption failed")
		return
	}

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(decryptedHeader)))
	if err != nil {
		log.Printf("[ERROR %s] Cannot read request header: %v", requestID, err)
		sendTCPErrorResponse(tc, requestID, "cannot read request header")
		return
	}

	targetURL, err := url.Parse(reqPayload.URL)
	if err != nil {
		log.Printf("[ERROR %s] Invalid target URL: %v", requestID, err)
		sendTCPErrorResponse(tc, requestID, "invalid target url")
		return
	}

	pipeReader, pipeWriter := io.Pipe()
	req.URL = targetURL
	req.RequestURI = ""
	req.Body = pipeReader

	state := &requestStreamState{
		id:         requestID,
		pipeReader: pipeReader,
		pipeWriter: pipeWriter,
		km:         km,
	}
	if _, loaded := requestStreams.LoadOrStore(requestID, state); loaded {
		sendTCPErrorResponse(tc, requestID, "duplicate request stream id")
		return
	}

	atomic.AddInt64(&activeTunnelRequests, 1)
	go executeStreamedHTTPRequest(tc, requestID, req, state)
}

func handleTCPRequestChunkBinary(msg *TunnelMessage) {
	requestID, encryptedChunk, err := ParseScopedBinaryPayload(msg.Payload)
	if err != nil {
		return
	}

	stateVal, ok := requestStreams.Load(requestID)
	if !ok {
		return
	}
	state := stateVal.(*requestStreamState)

	plainChunk, err := state.km.Decrypt(encryptedChunk)
	if err != nil {
		_ = state.pipeWriter.CloseWithError(err)
		requestStreams.Delete(requestID)
		return
	}

	offset := 0
	for offset < len(plainChunk) {
		n, writeErr := state.pipeWriter.Write(plainChunk[offset:])
		offset += n
		if writeErr != nil {
			requestStreams.Delete(requestID)
			return
		}
	}
}

func handleTCPRequestEnd(msg *TunnelMessage) {
	var payload RequestEndPayloadTCP
	if err := msg.ParseJSON(&payload); err != nil {
		return
	}

	stateVal, ok := requestStreams.Load(payload.ID)
	if !ok {
		return
	}
	state := stateVal.(*requestStreamState)

	if payload.Error != "" {
		_ = state.pipeWriter.CloseWithError(errors.New(payload.Error))
		return
	}
	_ = state.pipeWriter.Close()
}

func executeStreamedHTTPRequest(tc *TunnelConn, requestID string, req *http.Request, state *requestStreamState) {
	startAt := time.Now()
	defer func() {
		atomic.AddInt64(&activeTunnelRequests, -1)
		requestStreams.Delete(requestID)
		_ = state.pipeReader.Close()
		_ = state.pipeWriter.Close()
		DebugLog("[REQ %s] Streamed request completed in %v", requestID, time.Since(startAt))
	}()

	resp, err := sharedClient.Do(req)
	if err != nil {
		log.Printf("[ERROR %s] Streamed request failed: %v", requestID, err)
		sendTCPErrorResponse(tc, requestID, err.Error())
		return
	}
	defer resp.Body.Close()

	headerBytes, err := httputil.DumpResponse(resp, false)
	if err != nil {
		log.Printf("[ERROR %s] Failed to dump response: %v", requestID, err)
		sendTCPErrorResponse(tc, requestID, "failed to dump response")
		return
	}

	encryptedHeader, err := state.km.Encrypt(headerBytes)
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

	buf := GetLargeBuffer()
	defer PutLargeBuffer(buf)

	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			encryptedChunk, encErr := state.km.Encrypt(buf[:n])
			if encErr != nil {
				log.Printf("[ERROR %s] Failed to encrypt chunk: %v", requestID, encErr)
				sendTCPErrorResponse(tc, requestID, "failed to encrypt chunk")
				return
			}

			if err := sendScopedBinaryMessage(tc, MsgTypeResponseChunkBin, requestID, encryptedChunk); err != nil {
				log.Printf("[ERROR %s] Failed to send binary chunk: %v", requestID, err)
				return
			}
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			log.Printf("[ERROR %s] Response body read error: %v", requestID, readErr)
			sendTCPErrorResponse(tc, requestID, "read body error")
			return
		}
	}

	if err := tc.SendJSON(MsgTypeResponseEnd, ResponseEndPayloadTCP{ID: requestID}); err != nil {
		log.Printf("[ERROR %s] Failed to send response end: %v", requestID, err)
	}
}

func sendScopedBinaryMessage(tc *TunnelConn, msgType uint8, scopeID string, data []byte) error {
	payload, err := BuildScopedBinaryPayload(scopeID, data)
	if err != nil {
		return err
	}
	return tc.WriteMessage(&TunnelMessage{
		Type:    msgType,
		Payload: payload,
	})
}

func writeAllToPipe(pipeWriter *io.PipeWriter, data []byte) error {
	offset := 0
	for offset < len(data) {
		n, err := pipeWriter.Write(data[offset:])
		offset += n
		if err != nil {
			return err
		}
	}
	return nil
}

func handleTCPProbePing(tc *TunnelConn, msg *TunnelMessage) {
	var payload ProbePayload
	if err := msg.ParseJSON(&payload); err != nil {
		return
	}
	_ = tc.SendJSON(MsgTypeProbePong, payload)
}

func extractGridDestination(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return strings.TrimSpace(rawURL)
	}
	if host := strings.TrimSpace(parsed.Hostname()); host != "" {
		return host
	}
	return strings.TrimSpace(rawURL)
}

func applyGridFrameMetadata(destination, routeID string, routeEpoch int64, hopCount int, traceID string) error {
	if hopCount > endpointHopGuardMax {
		return fmt.Errorf("hop_guard rejected frame hop_count=%d max_hop=%d", hopCount, endpointHopGuardMax)
	}
	if strings.TrimSpace(routeID) != "" || strings.TrimSpace(traceID) != "" {
		DebugLog("[GRID] frame dst=%s route=%s epoch=%d hop=%d trace=%s", strings.TrimSpace(destination), strings.TrimSpace(routeID), routeEpoch, hopCount, strings.TrimSpace(traceID))
	}
	RecordRelayPath(destination, strings.TrimSpace(routeID), routeEpoch, hopCount)
	return nil
}

func normalizeGridHops(hops []string) []string {
	if len(hops) == 0 {
		return nil
	}
	out := make([]string, 0, len(hops))
	for _, hop := range hops {
		h := strings.TrimSpace(hop)
		if h == "" {
			continue
		}
		out = append(out, h)
	}
	return out
}

func buildTransitRelayDedupSeed(traceID, routeID string, routeEpoch int64) string {
	traceID = strings.TrimSpace(traceID)
	if traceID != "" {
		return "trace:" + traceID
	}
	routeID = strings.TrimSpace(routeID)
	if routeID != "" && routeEpoch > 0 {
		return "route:" + routeID + ":" + strconv.FormatInt(routeEpoch, 10)
	}
	return ""
}

func buildProxyTransitRelayDedupKey(payload ProxyConnectPayload, finalHost string, finalPort int, nextHop string, remainingHops []string) string {
	seed := buildTransitRelayDedupSeed(payload.TraceID, payload.RouteID, payload.RouteEpoch)
	if seed == "" {
		return ""
	}
	parts := []string{
		seed,
		strings.TrimSpace(finalHost),
		strconv.Itoa(finalPort),
		strings.TrimSpace(nextHop),
	}
	if len(remainingHops) > 0 {
		parts = append(parts, strings.Join(normalizeGridHops(remainingHops), ","))
	}
	return strings.Join(parts, "|")
}

func buildRequestTransitRelayDedupKey(payload RequestStartPayloadTCP, finalHost string, nextHop string, remainingHops []string) string {
	seed := buildTransitRelayDedupSeed(payload.TraceID, payload.RouteID, payload.RouteEpoch)
	if seed == "" {
		return ""
	}
	parts := []string{
		seed,
		strings.TrimSpace(finalHost),
		strings.TrimSpace(payload.URL),
		strings.TrimSpace(nextHop),
	}
	if len(remainingHops) > 0 {
		parts = append(parts, strings.Join(normalizeGridHops(remainingHops), ","))
	}
	return strings.Join(parts, "|")
}

func acquireTransitRelayDedup(key string) bool {
	key = strings.TrimSpace(key)
	if key == "" {
		return true
	}
	now := time.Now()
	relayTransitDedup.mu.Lock()
	defer relayTransitDedup.mu.Unlock()
	for k, ts := range relayTransitDedup.locks {
		if now.Sub(ts) > relayTransitDedupTTL {
			delete(relayTransitDedup.locks, k)
		}
	}
	if _, exists := relayTransitDedup.locks[key]; exists {
		return false
	}
	relayTransitDedup.locks[key] = now
	return true
}

func releaseTransitRelayDedup(key string) {
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	relayTransitDedup.mu.Lock()
	delete(relayTransitDedup.locks, key)
	relayTransitDedup.mu.Unlock()
}

func currentGridFrameIntegritySecret() string {
	return ""
}

func gridFrameIntegritySecretForConn(conn net.Conn) string {
	if conn != nil {
		if provider, ok := conn.(interface{ GridIntegrityKey() string }); ok {
			if secret := strings.TrimSpace(provider.GridIntegrityKey()); secret != "" {
				return secret
			}
		}
	}
	return currentGridFrameIntegritySecret()
}

func generateGridFrameIntegrityNonce() string {
	buf := make([]byte, gridFrameIntegrityNonceN)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func isGridFrameIntegrityTimestampFresh(ts int64) bool {
	if ts <= 0 {
		return false
	}
	now := time.Now().UTC().Unix()
	delta := now - ts
	if delta < 0 {
		delta = -delta
	}
	return time.Duration(delta)*time.Second <= gridFrameIntegrityWindow
}

func computeGridFrameIntegritySignature(secret string, fields ...string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	for _, field := range fields {
		mac.Write([]byte(strings.TrimSpace(field)))
		mac.Write([]byte{'\n'})
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func consumeGridFrameIntegrityReplay(kind, nonce, sig string, ts int64) bool {
	key := strings.TrimSpace(kind) + "|" + strings.TrimSpace(nonce) + "|" + strings.TrimSpace(sig)
	if key == "||" {
		return false
	}
	now := time.Now().UTC()
	nowUnix := now.Unix()
	gridFrameIntegritySeen.mu.Lock()
	defer gridFrameIntegritySeen.mu.Unlock()
	for k, exp := range gridFrameIntegritySeen.seen {
		if exp < nowUnix {
			delete(gridFrameIntegritySeen.seen, k)
		}
	}
	if exp, exists := gridFrameIntegritySeen.seen[key]; exists && exp >= nowUnix {
		return false
	}
	gridFrameIntegritySeen.seen[key] = ts + int64((gridFrameIntegrityWindow + time.Minute).Seconds())
	if len(gridFrameIntegritySeen.seen) > gridFrameIntegrityMaxSet {
		toDelete := len(gridFrameIntegritySeen.seen) - gridFrameIntegrityMaxSet
		for k := range gridFrameIntegritySeen.seen {
			delete(gridFrameIntegritySeen.seen, k)
			toDelete--
			if toDelete <= 0 {
				break
			}
		}
	}
	return true
}

func proxyGridFrameIntegrityFields(payload ProxyConnectPayload) []string {
	return []string{
		"proxy-v1",
		strings.TrimSpace(payload.ConnectionID),
		strings.TrimSpace(payload.GridFinalHost),
		strconv.Itoa(payload.GridFinalPort),
		strconv.FormatBool(payload.GridFinalTLS),
		strings.TrimSpace(payload.RouteID),
		strconv.FormatInt(payload.RouteEpoch, 10),
		strconv.Itoa(payload.HopCount),
		strings.TrimSpace(payload.TraceID),
		strings.TrimSpace(payload.GridNextHop),
		strings.Join(normalizeGridHops(payload.GridHops), ","),
		strconv.FormatInt(payload.GridIntegrityTS, 10),
		strings.TrimSpace(payload.GridIntegrityN),
	}
}

func signProxyGridFrameIntegrityWithSecret(payload *ProxyConnectPayload, secret string) {
	if payload == nil {
		return
	}
	secret = strings.TrimSpace(secret)
	if secret == "" {
		payload.GridIntegrityTS = 0
		payload.GridIntegrityN = ""
		payload.GridIntegritySig = ""
		return
	}
	payload.GridIntegrityTS = time.Now().UTC().Unix()
	payload.GridIntegrityN = generateGridFrameIntegrityNonce()
	payload.GridIntegritySig = computeGridFrameIntegritySignature(secret, proxyGridFrameIntegrityFields(*payload)...)
}

func signProxyGridFrameIntegrity(payload *ProxyConnectPayload) {
	signProxyGridFrameIntegrityWithSecret(payload, currentGridFrameIntegritySecret())
}

func verifyProxyGridFrameIntegrityWithSecret(payload ProxyConnectPayload, secret string) error {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil
	}
	if !isGridFrameIntegrityTimestampFresh(payload.GridIntegrityTS) {
		return errors.New("grid frame integrity timestamp invalid")
	}
	if strings.TrimSpace(payload.GridIntegrityN) == "" || strings.TrimSpace(payload.GridIntegritySig) == "" {
		return errors.New("grid frame integrity missing")
	}
	expected := computeGridFrameIntegritySignature(secret, proxyGridFrameIntegrityFields(payload)...)
	if expected == "" || !hmac.Equal([]byte(strings.ToLower(strings.TrimSpace(payload.GridIntegritySig))), []byte(expected)) {
		return errors.New("grid frame integrity mismatch")
	}
	if !consumeGridFrameIntegrityReplay("proxy", payload.GridIntegrityN, payload.GridIntegritySig, payload.GridIntegrityTS) {
		return errors.New("grid frame integrity replay detected")
	}
	return nil
}

func verifyProxyGridFrameIntegrity(payload ProxyConnectPayload) error {
	return verifyProxyGridFrameIntegrityWithSecret(payload, currentGridFrameIntegritySecret())
}

func requestGridFrameIntegrityFields(payload RequestStartPayloadTCP) []string {
	return []string{
		"request-v1",
		strings.TrimSpace(payload.ID),
		strings.TrimSpace(payload.URL),
		strings.TrimSpace(payload.GridFinalHost),
		strconv.Itoa(payload.GridFinalPort),
		strconv.FormatBool(payload.GridFinalTLS),
		strings.TrimSpace(payload.RouteID),
		strconv.FormatInt(payload.RouteEpoch, 10),
		strconv.Itoa(payload.HopCount),
		strings.TrimSpace(payload.TraceID),
		strings.TrimSpace(payload.GridNextHop),
		strings.Join(normalizeGridHops(payload.GridHops), ","),
		strconv.FormatInt(payload.GridIntegrityTS, 10),
		strings.TrimSpace(payload.GridIntegrityN),
	}
}

func signRequestGridFrameIntegrityWithSecret(payload *RequestStartPayloadTCP, secret string) {
	if payload == nil {
		return
	}
	secret = strings.TrimSpace(secret)
	if secret == "" {
		payload.GridIntegrityTS = 0
		payload.GridIntegrityN = ""
		payload.GridIntegritySig = ""
		return
	}
	payload.GridIntegrityTS = time.Now().UTC().Unix()
	payload.GridIntegrityN = generateGridFrameIntegrityNonce()
	payload.GridIntegritySig = computeGridFrameIntegritySignature(secret, requestGridFrameIntegrityFields(*payload)...)
}

func signRequestGridFrameIntegrity(payload *RequestStartPayloadTCP) {
	signRequestGridFrameIntegrityWithSecret(payload, currentGridFrameIntegritySecret())
}

func verifyRequestGridFrameIntegrityWithSecret(payload RequestStartPayloadTCP, secret string) error {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil
	}
	if !isGridFrameIntegrityTimestampFresh(payload.GridIntegrityTS) {
		return errors.New("grid frame integrity timestamp invalid")
	}
	if strings.TrimSpace(payload.GridIntegrityN) == "" || strings.TrimSpace(payload.GridIntegritySig) == "" {
		return errors.New("grid frame integrity missing")
	}
	expected := computeGridFrameIntegritySignature(secret, requestGridFrameIntegrityFields(payload)...)
	if expected == "" || !hmac.Equal([]byte(strings.ToLower(strings.TrimSpace(payload.GridIntegritySig))), []byte(expected)) {
		return errors.New("grid frame integrity mismatch")
	}
	if !consumeGridFrameIntegrityReplay("request", payload.GridIntegrityN, payload.GridIntegritySig, payload.GridIntegrityTS) {
		return errors.New("grid frame integrity replay detected")
	}
	return nil
}

func verifyRequestGridFrameIntegrity(payload RequestStartPayloadTCP) error {
	return verifyRequestGridFrameIntegrityWithSecret(payload, currentGridFrameIntegritySecret())
}

func generateRelayConnectionID() string {
	return fmt.Sprintf("relay-%d", time.Now().UTC().UnixNano())
}

// handleTCPRequest handles HTTP request via TCP tunnel
func handleTCPRequest(tc *TunnelConn, msg *TunnelMessage, km *SessionKeyManager) {
	atomic.AddInt64(&activeTunnelRequests, 1)
	defer atomic.AddInt64(&activeTunnelRequests, -1)

	var reqPayload RequestPayloadTCP
	if err := msg.ParseJSON(&reqPayload); err != nil {
		log.Printf("Failed to parse request: %v", err)
		return
	}

	requestID := reqPayload.ID
	startAt := time.Now()
	DebugLog("[REQ %s] Started: %s", requestID, reqPayload.URL)
	DebugLog("[DEBUG %s] Handling TCP request, URL: %s", requestID, reqPayload.URL)
	if err := applyGridFrameMetadata(
		extractGridDestination(reqPayload.URL),
		reqPayload.RouteID,
		reqPayload.RouteEpoch,
		reqPayload.HopCount,
		reqPayload.TraceID,
	); err != nil {
		log.Printf("[ERROR %s] %v", requestID, err)
		sendTCPErrorResponse(tc, requestID, err.Error())
		return
	}

	// Use KeyManager.Decrypt instead of password-based decrypt
	// This will try both currentKey and previousKey during grace period
	decryptedData, err := km.Decrypt(reqPayload.Data)
	if err != nil {
		log.Printf("[ERROR] Decryption failed - trying all available keys: %v", err)
		log.Printf("[ERROR] This may indicate a key synchronization issue")
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

	DebugLog("[DEBUG %s] Sending request to backend: %s", requestID, req.URL.String())

	resp, err := sharedClient.Do(req)
	if err != nil {
		log.Printf("[ERROR %s] Request failed: %v", requestID, err)
		sendTCPErrorResponse(tc, requestID, err.Error())
		return
	}
	defer resp.Body.Close()

	DebugLog("[DEBUG %s] Got response: %d %s", requestID, resp.StatusCode, resp.Status)

	// Send response header
	headerBytes, err := httputil.DumpResponse(resp, false)
	if err != nil {
		log.Printf("[ERROR %s] Failed to dump response: %v", requestID, err)
		sendTCPErrorResponse(tc, requestID, "failed to dump response")
		return
	}

	encryptedHeader, err := km.Encrypt(headerBytes)
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

	DebugLog("[DEBUG %s] Sent response header", requestID)

	// Stream body
	buf := GetLargeBuffer()
	defer PutLargeBuffer(buf)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			encryptedChunk, encErr := km.Encrypt(buf[:n])
			if encErr != nil {
				log.Printf("[ERROR %s] Failed to encrypt chunk: %v", requestID, encErr)
				sendTCPErrorResponse(tc, requestID, "failed to encrypt chunk")
				return
			}

			if sendErr := sendScopedBinaryMessage(tc, MsgTypeResponseChunkBin, requestID, encryptedChunk); sendErr != nil {
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

	DebugLog("[REQ %s] Completed in %v", requestID, time.Since(startAt))
	DebugLog("[DEBUG %s] Request completed successfully", requestID)
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
	DebugLog("[PROXY %s] Connecting to %s (client: %s)", connID, address, payload.ClientIP)
	if err := applyGridFrameMetadata(payload.Host, payload.RouteID, payload.RouteEpoch, payload.HopCount, payload.TraceID); err != nil {
		log.Printf("[PROXY %s] %v", connID, err)
		ack := ProxyConnectAckPayload{
			ConnectionID: connID,
			Success:      false,
			Error:        err.Error(),
		}
		tc.SendJSON(MsgTypeProxyConnectAck, ack)
		return
	}

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
		DebugLog("[PROXY %s] TCP connection established to %s", connID, address)
		proxyConnections.Store(connID, conn)

		if payload.StreamMode {
			DebugLog("[PROXY %s] Stream mode requested, waiting for switch signal", connID)
			// Do not start read loop, wait for MsgTypeProxyStreamMode
		} else {
			DebugLog("[PROXY %s] Starting read loop", connID)
			go tcpProxyReadLoop(tc, connID, conn)
		}
	}

	DebugLog("[PROXY %s] Sending ack (success=%v)", connID, ack.Success)
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

	DebugLog("[PROXY %s] Closing: %s", payload.ConnectionID, payload.Reason)
	if connVal, ok := proxyConnections.Load(payload.ConnectionID); ok {
		connVal.(net.Conn).Close()
		proxyConnections.Delete(payload.ConnectionID)
	}
}

// tcpProxyReadLoop reads from target and sends to APS
func tcpProxyReadLoop(tc *TunnelConn, connID string, conn net.Conn) {
	DebugLog("[PROXY %s] Read loop started", connID)
	defer func() {
		DebugLog("[PROXY %s] Read loop ending, closing connection", connID)
		conn.Close()
		proxyConnections.Delete(connID)
		DebugLog("[PROXY %s] Sending close message to APS", connID)
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
			DebugLog("[PROXY %s] Read %d bytes from backend, sending to APS", connID, n)

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
				DebugLog("[PROXY %s] Connection closed by backend (EOF)", connID)
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
	TunnelName          string              `json:"tunnelName"`
	EndpointName        string              `json:"endpointName"`
	SessionCredential   string              `json:"sessionCredential,omitempty"`
	SessionExpiresAt    int64               `json:"sessionExpiresAt,omitempty"`
	KDFVersion          string              `json:"kdfVersion,omitempty"`
	KDFSalt             string              `json:"kdfSalt,omitempty"`
	PortMappings        []PortMappingConfig `json:"portMappings,omitempty"`
	GatewayListen       string              `json:"gatewayListen,omitempty"`
	GatewayAddress      string              `json:"gatewayAddress,omitempty"`
	GatewayDiscovery    bool                `json:"gatewayDiscovery,omitempty"`
	GatewayDiscoverPort int                 `json:"gatewayDiscoverPort,omitempty"`
	SSH                 *EndpointSSHConfig  `json:"ssh,omitempty"`
}

func (p *ConfigUpdatePayload) UnmarshalJSON(data []byte) error {
	type alias ConfigUpdatePayload
	var aux struct {
		alias
		GatewayAddress json.RawMessage `json:"gatewayAddress"`
	}
	aux.alias = alias(*p)
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	parsed := alias(aux.alias)
	if len(aux.GatewayAddress) > 0 {
		decodedGatewayAddress, err := decodeGatewayAddressField(aux.GatewayAddress)
		if err != nil {
			return err
		}
		parsed.GatewayAddress = canonicalizeEndpointGatewayAddressField(decodedGatewayAddress)
	} else {
		parsed.GatewayAddress = canonicalizeEndpointGatewayAddressField(parsed.GatewayAddress)
	}
	*p = ConfigUpdatePayload(parsed)
	return nil
}

// MirrorUpdatePayload is sent by APS to inform endpoint of mirror addresses
type MirrorUpdatePayload struct {
	Mirrors []string `json:"mirrors"` // Format: ["addr:port", "cid@addr:port", ...]
}

// handleConfigUpdate handles configuration update pushed from APS
func handleConfigUpdate(tc *TunnelConn, msg *TunnelMessage, sessionState *TunnelSessionState) {
	payload := ConfigUpdatePayload{
		GatewayDiscovery:    true,
		GatewayDiscoverPort: defaultGatewayDiscoverPort,
	}
	if err := msg.ParseJSON(&payload); err != nil {
		log.Printf("[CONFIG] Failed to parse config update: %v", err)
		return
	}
	payload.GatewayListen = strings.TrimSpace(payload.GatewayListen)
	payload.GatewayAddress = canonicalizeEndpointGatewayAddressField(payload.GatewayAddress)
	if payload.GatewayDiscoverPort <= 0 {
		payload.GatewayDiscoverPort = defaultGatewayDiscoverPort
	}
	if payload.GatewayListen == "" {
		payload.GatewayListen = defaultGatewayListenAddress(payload.GatewayDiscoverPort)
	}

	DebugLog("[CONFIG] Received config update from APS")

	if sessionState == nil {
		log.Printf("[CONFIG] Session state is nil; ignoring config update")
		return
	}

	sessionState.mu.Lock()
	oldTunnel := sessionState.TunnelName
	oldEndpoint := sessionState.EndpointName
	oldSessionCredential := sessionState.SessionCredential
	oldKDFVersion := sessionState.KDFVersion
	oldKDFSalt := sessionState.KDFSalt
	oldGatewayListen := sessionState.GatewayListen
	oldGatewayAddress := sessionState.GatewayAddress
	oldGatewayDiscovery := sessionState.GatewayDiscovery
	oldGatewayDiscoverPort := sessionState.GatewayDiscoverPort

	// Check for critical changes that require reconnection
	shouldReconnect := false
	if payload.TunnelName != "" && payload.TunnelName != oldTunnel {
		shouldReconnect = true
	}
	if payload.EndpointName != "" && payload.EndpointName != oldEndpoint {
		shouldReconnect = true
	}
	if payload.SessionCredential != "" && payload.SessionCredential != oldSessionCredential {
		shouldReconnect = true
	}
	if payload.KDFVersion != "" && payload.KDFVersion != oldKDFVersion {
		shouldReconnect = true
	}
	if payload.KDFSalt != "" && payload.KDFSalt != oldKDFSalt {
		shouldReconnect = true
	}
	if !equalGatewayAddressField(payload.GatewayAddress, oldGatewayAddress) ||
		payload.GatewayDiscovery != oldGatewayDiscovery ||
		payload.GatewayDiscoverPort != oldGatewayDiscoverPort {
		shouldReconnect = true
	}

	// Update fields from payload
	if payload.TunnelName != "" {
		sessionState.TunnelName = payload.TunnelName
	}
	if payload.EndpointName != "" {
		sessionState.EndpointName = payload.EndpointName
	}
	if payload.SessionCredential != "" {
		sessionState.SessionCredential = payload.SessionCredential
	}
	if payload.SessionExpiresAt > 0 {
		sessionState.SessionExpiresAt = payload.SessionExpiresAt
	}
	if payload.KDFVersion != "" {
		sessionState.KDFVersion = payload.KDFVersion
	}
	if payload.KDFSalt != "" {
		sessionState.KDFSalt = payload.KDFSalt
	}
	if payload.PortMappings != nil {
		sessionState.PortMappings = clonePortMappingsForContext(payload.PortMappings)
	}
	sessionState.GatewayListen = payload.GatewayListen
	sessionState.GatewayAddress = payload.GatewayAddress
	sessionState.GatewayDiscovery = payload.GatewayDiscovery
	sessionState.GatewayDiscoverPort = payload.GatewayDiscoverPort
	sessionState.SSH = cloneEndpointSSHConfigForContext(payload.SSH)
	updatedGatewayListen := sessionState.GatewayListen
	updatedGatewayDiscoverPort := sessionState.GatewayDiscoverPort

	sessionState.mu.Unlock()

	if updatedGatewayListen != "" {
		ensureGatewayRuntime(ImmutableConnectionContext{
			GatewayListen:       updatedGatewayListen,
			GatewayDiscoverPort: updatedGatewayDiscoverPort,
		})
	}
	ensureEndpointICEConnectivityRuntime(ImmutableConnectionContext{
		GatewayListen:       updatedGatewayListen,
		GatewayDiscoverPort: updatedGatewayDiscoverPort,
	})
	if oldGatewayListen != "" && updatedGatewayListen != "" && oldGatewayListen != updatedGatewayListen {
		log.Printf("[GATEWAY] gatewayListen changed from %s to %s; runtime keeps first listener until process restart", oldGatewayListen, updatedGatewayListen)
	}

	if err := endpointSSHManager.Apply(payload.SSH); err != nil {
		log.Printf("[SSH] Failed to apply SSH config update: %v", err)
	}

	if shouldReconnect {
		log.Printf("[CONFIG] Critical configuration changed (tunnel/endpoint/sessionCredential/KDF/gateway route), reconnecting...")
		closeTunnelConnWithReason(tc, "config update requires reconnect")
		return
	}

	updatedMappings := clonePortMappingsForContext(sessionState.PortMappings)
	applyPortMappingsRuntime(updatedMappings, tc)

	sshState := "disabled"
	if payload.SSH != nil {
		sshState = "configured"
	}
	DebugLog("[CONFIG] Updated runtime config: tunnel=%s, endpoint=%s, portMappings=%d, gateway=%s, discovery=%v:%d, ssh=%s",
		payload.TunnelName,
		payload.EndpointName,
		len(payload.PortMappings),
		strings.TrimSpace(payload.GatewayAddress),
		payload.GatewayDiscovery,
		payload.GatewayDiscoverPort,
		sshState,
	)
}

func equalGatewayAddressField(a, b string) bool {
	aList := normalizeEndpointGatewayAddresses(strings.TrimSpace(a))
	bList := normalizeEndpointGatewayAddresses(strings.TrimSpace(b))
	if len(aList) != len(bList) {
		return false
	}
	for i := range aList {
		if !sameGatewayAddress(aList[i], bList[i]) {
			return false
		}
	}
	return true
}

// handleMirrorUpdate processes mirror address updates from APS
func handleMirrorUpdate(_ *TunnelConn, msg *TunnelMessage) {
	var payload MirrorUpdatePayload
	if err := msg.ParseJSON(&payload); err != nil {
		log.Printf("[MIRROR] Failed to parse mirror update: %v", err)
		return
	}

	if connectionManager == nil {
		log.Printf("[MIRROR] Connection manager not initialized, ignoring mirror update")
		return
	}

	DebugLog("[MIRROR] Received %d mirror address(es) from APS", len(payload.Mirrors))

	// Process each mirror address
	for _, mirror := range payload.Mirrors {
		// Parse the mirror address (could be "addr:port" or "cid@addr:port")
		cfg := connectionManager.ParseServerAddress(mirror, false) // false = not a seed

		// Add as dynamic server if not already connected
		if connectionManager.AddDynamicServer(cfg) {
			DebugLog("[MIRROR] Starting connection to new mirror: %s (cid: %s)", cfg.Address, cfg.ConfigID)

			// Start connection in a new goroutine
			go runServerConnection(context.Background(), cfg.Address)
		} else {
			DebugLog("[MIRROR] Already connected to mirror: %s", cfg.Address)
		}
	}
}

// initiateKeyRotation initiates a new key rotation by sending a key request
func initiateKeyRotation(tc *TunnelConn, km *SessionKeyManager) error {
	if n := atomic.LoadInt64(&activeTunnelRequests); n > 0 {
		DebugLog("[KEY] Deferring key rotation while %d request(s) are active", n)
		return nil
	}

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

	DebugLog("[KEY] Key rotation initiated")
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

	DebugLog("[KEY] Key response sent")
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

	DebugLog("[KEY] Key rotation completed (initiator)")
}

// handleKeyConfirm handles key confirmation and activates the new key
func handleKeyConfirm(_ *TunnelConn, msg *TunnelMessage, km *SessionKeyManager) {
	confirm, err := UnmarshalKeyConfirm(msg.Payload)
	if err != nil {
		log.Printf("[KEY] Failed to parse key confirm: %v", err)
		return
	}

	if err := km.HandleKeyConfirm(confirm); err != nil {
		log.Printf("[KEY] Failed to handle key confirm: %v", err)
		return
	}

	DebugLog("[KEY] Key rotation completed (responder)")
}

// acceptStreams handles incoming streams from SMUX session
func acceptStreams(session *smux.Session, controlTc *TunnelConn, km *SessionKeyManager) {
	_ = km
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			log.Printf("SMUX accept error: %v", err)
			return
		}
		go handleIncomingStream(stream, controlTc)
	}
}

func handleEndpointGridTransitConnection(conn net.Conn) {
	if conn == nil {
		return
	}
	handleIncomingStream(conn, nil)
}

// handleIncomingStream handles a new stream from APS
func handleIncomingStream(stream net.Conn, controlTc *TunnelConn) {
	defer stream.Close()

	// Read ProxyConnectPayload from the stream
	tc := NewTunnelConn(stream)
	msg, err := tc.ReadMessage()
	if err != nil {
		log.Printf("Failed to read proxy connect from stream: %v", err)
		return
	}

	if msg.Type != MsgTypeProxyConnect {
		if msg.Type == MsgTypeRequestStart {
			handleIncomingRequestStream(tc, stream, msg, controlTc == nil)
			return
		}
		if msg.Type == MsgTypePortForwardRequest {
			handleIncomingPortForwardStream(tc, stream, msg)
			return
		}
		log.Printf("Unexpected message type on new stream: %d", msg.Type)
		return
	}

	var payload ProxyConnectPayload
	if err := msg.ParseJSON(&payload); err != nil {
		log.Printf("Failed to parse proxy connect payload: %v", err)
		return
	}
	integritySecret := gridFrameIntegritySecretForConn(stream)
	if controlTc == nil {
		if err := verifyProxyGridFrameIntegrityWithSecret(payload, integritySecret); err != nil {
			log.Printf("[GRID] Reject transit proxy frame: %v", err)
			return
		}
	}

	connID := payload.ConnectionID
	finalHost := strings.TrimSpace(payload.GridFinalHost)
	if finalHost == "" {
		finalHost = strings.TrimSpace(payload.Host)
	}
	finalPort := payload.GridFinalPort
	if finalPort <= 0 {
		finalPort = payload.Port
	}
	finalTLS := payload.TLS
	if payload.GridFinalHost != "" {
		finalTLS = payload.GridFinalTLS
	}
	nextHop := strings.TrimSpace(payload.GridNextHop)
	remainingHops := normalizeGridHops(payload.GridHops)

	if err := applyGridFrameMetadata(finalHost, payload.RouteID, payload.RouteEpoch, payload.HopCount, payload.TraceID); err != nil {
		log.Printf("[PROXY %s] %v", connID, err)
		if controlTc != nil {
			ack := ProxyConnectAckPayload{
				ConnectionID: connID,
				Success:      false,
				Error:        err.Error(),
			}
			_ = controlTc.SendJSON(MsgTypeProxyConnectAck, ack)
		}
		return
	}

	var (
		backendConn       net.Conn
		relayConn         net.Conn
		connErr           error
		selectedTransport string
		relayMode         string
	)
	if nextHop != "" {
		dedupSuppressed := false
		transitDedupKey := buildProxyTransitRelayDedupKey(payload, finalHost, finalPort, nextHop, remainingHops)
		if !acquireTransitRelayDedup(transitDedupKey) {
			dedupSuppressed = true
			connErr = errors.New("duplicate transit probe suppressed")
			DebugLog("[PROXY %s] duplicate transit suppressed key=%s next=%s", connID, transitDedupKey, nextHop)
		} else if strings.TrimSpace(transitDedupKey) != "" {
			defer releaseTransitRelayDedup(transitDedupKey)
		}

		selectedTransport = "relay"
		relayMode = "p2p"
		if connErr == nil {
			relayConn, nextHop, connErr = dialGatewayPeerGridBundle(nextHop, remainingHops, gatewayRouteBundleMaxAddrs)
		}
		if connErr != nil && !dedupSuppressed {
			relayMode = "aps-relay"
			relaySession := getActiveTunnelSession()
			if relaySession == nil {
				connErr = errors.New("relay session not available")
			} else {
				relayConn, connErr = relaySession.OpenStream()
			}
		}
		if connErr == nil {
			nextForReceiver := ""
			tail := []string(nil)
			if len(remainingHops) > 0 {
				nextForReceiver = remainingHops[0]
				if len(remainingHops) > 1 {
					tail = append(tail, remainingHops[1:]...)
				}
			}

			relayTC := NewTunnelConn(relayConn)
			relayPayload := ProxyConnectPayload{
				ConnectionID:      generateRelayConnectionID(),
				Host:              finalHost,
				Port:              finalPort,
				TLS:               finalTLS,
				ClientIP:          payload.ClientIP,
				RouteID:           payload.RouteID,
				RouteEpoch:        payload.RouteEpoch,
				HopCount:          payload.HopCount + 1,
				TraceID:           payload.TraceID,
				GridNextHop:       nextForReceiver,
				GridHops:          tail,
				GridFinalHost:     finalHost,
				GridFinalPort:     finalPort,
				GridFinalTLS:      finalTLS,
				GridEnableQUIC:    payload.GridEnableQUIC,
				GridEnableTCP:     payload.GridEnableTCP,
				GridParallel:      payload.GridParallel,
				GridEnableICE:     payload.GridEnableICE,
				GridICECandidates: append([]string(nil), payload.GridICECandidates...),
			}
			if relayMode == "aps-relay" {
				relayPayload.GridRouteTo = nextHop
			}
			signProxyGridFrameIntegrityWithSecret(&relayPayload, gridFrameIntegritySecretForConn(relayConn))
			connErr = relayTC.SendJSON(MsgTypeProxyConnect, relayPayload)
			if connErr != nil && relayConn != nil {
				_ = relayConn.Close()
				relayConn = nil
			}
		}
		if connErr == nil {
			selectedTransport = relayMode
		}
		DebugLog("[PROXY %s] Transit relay next=%s remaining=%v final=%s:%d mode=%s", connID, nextHop, remainingHops, finalHost, finalPort, relayMode)
	} else {
		selectedTransport = "tcp"
		backendConn, selectedTransport, connErr = dialGridBackendWithPolicy(finalHost, finalPort, finalTLS, payload)
		DebugLog("[PROXY %s] Connecting to final backend %s:%d via %s (client: %s)", connID, finalHost, finalPort, selectedTransport, payload.ClientIP)
	}

	ack := ProxyConnectAckPayload{
		ConnectionID: connID,
		Success:      connErr == nil,
	}
	if connErr != nil {
		ack.Error = connErr.Error()
		log.Printf("[PROXY %s] Connection failed: %v", connID, connErr)
	} else {
		DebugLog("[PROXY %s] Proxy connection established (transit=%v transport=%s)", connID, relayConn != nil, selectedTransport)
	}

	// Send Ack on control channel
	if controlTc != nil {
		if err := controlTc.SendJSON(MsgTypeProxyConnectAck, ack); err != nil {
			log.Printf("[PROXY %s] Failed to send ack: %v", connID, err)
			if backendConn != nil {
				backendConn.Close()
			}
			if relayConn != nil {
				relayConn.Close()
			}
			return
		}
	}

	if connErr != nil {
		return
	}

	if backendConn != nil {
		defer backendConn.Close()
	}
	if relayConn != nil {
		defer relayConn.Close()
	}

	// Bidirectional copy
	DebugLog("[PROXY %s] Starting stream copy", connID)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if relayConn != nil {
			_, _ = io.Copy(stream, relayConn)
			return
		}
		_, _ = io.Copy(stream, backendConn)
	}()

	go func() {
		defer wg.Done()
		if relayConn != nil {
			_, _ = io.Copy(relayConn, stream)
			return
		}
		_, _ = io.Copy(backendConn, stream)
	}()

	wg.Wait()
	DebugLog("[PROXY %s] Stream copy finished", connID)
}

func handleIncomingPortForwardStream(tc *TunnelConn, stream net.Conn, bootstrap *TunnelMessage) {
	var payload PortForwardRequestPayload
	if err := bootstrap.ParseJSON(&payload); err != nil {
		log.Printf("[PORT-MAP] Failed to parse inbound P2P request: %v", err)
		return
	}

	connectionID := strings.TrimSpace(payload.ConnectionID)
	remoteTarget := strings.TrimSpace(payload.RemoteTarget)
	targetEndpoint := strings.TrimSpace(payload.TargetEndpoint)
	nextHop := strings.TrimSpace(payload.GridNextHop)
	payload.GridHops = normalizeGridHops(payload.GridHops)
	sourceClient := strings.TrimSpace(payload.ClientIP)
	if sourceClient == "" {
		sourceClient = "unknown-source"
	}
	if targetEndpoint == "" {
		targetEndpoint = GetEffectiveEndpointName()
		payload.TargetEndpoint = targetEndpoint
	}
	if connectionID == "" || remoteTarget == "" {
		_ = tc.SendJSON(MsgTypePortForwardResponse, PortForwardResponsePayload{
			ConnectionID: connectionID,
			Success:      false,
			Error:        "invalid p2p port-forward request",
		})
		return
	}
	if payload.HopCount > endpointHopGuardMax {
		_ = tc.SendJSON(MsgTypePortForwardResponse, PortForwardResponsePayload{
			ConnectionID: connectionID,
			Success:      false,
			Error:        fmt.Sprintf("hop_guard rejected hop_count=%d max_hop=%d", payload.HopCount, endpointHopGuardMax),
		})
		return
	}

	DebugLog("[PORT-MAP] Inbound P2P request conn=%s from=%s target_endpoint=%s remote_target=%s",
		connectionID, sourceClient, targetEndpoint, remoteTarget)

	selfNode := localPrimaryGatewayNodeID()
	targetNode := normalizeGatewayNodeID(targetEndpoint)
	if isLocalGatewayNodeID(targetNode) {
		targetNode = selfNode
	}
	nextHopNode := normalizeGatewayNodeID(nextHop)
	if nextHopNode != "" && !isLocalGatewayNodeID(nextHopNode) {
		handleIncomingPortForwardTransit(tc, stream, payload, sourceClient)
		return
	}
	if targetNode != "" && !isLocalGatewayNodeID(targetNode) {
		payload.GridNextHop = targetNode
		handleIncomingPortForwardTransit(tc, stream, payload, sourceClient)
		return
	}

	backendConn, err := net.DialTimeout("tcp", remoteTarget, 8*time.Second)
	if err != nil {
		log.Printf("[PORT-MAP] Inbound P2P connect failed conn=%s remote_target=%s: %v", connectionID, remoteTarget, err)
		_ = tc.SendJSON(MsgTypePortForwardResponse, PortForwardResponsePayload{
			ConnectionID: connectionID,
			Success:      false,
			Error:        err.Error(),
		})
		return
	}
	defer backendConn.Close()

	if err := tc.SendJSON(MsgTypePortForwardResponse, PortForwardResponsePayload{
		ConnectionID: connectionID,
		Success:      true,
	}); err != nil {
		log.Printf("[PORT-MAP] Inbound P2P response send failed conn=%s: %v", connectionID, err)
		return
	}

	DebugLog("[PORT-MAP] Inbound P2P established conn=%s target_endpoint=%s remote_target=%s",
		connectionID, targetEndpoint, remoteTarget)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(backendConn, stream)
		_ = backendConn.SetReadDeadline(time.Now())
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(stream, backendConn)
		_ = stream.SetReadDeadline(time.Now())
	}()
	wg.Wait()
}

func handleIncomingPortForwardTransit(tc *TunnelConn, upstream net.Conn, payload PortForwardRequestPayload, sourceClient string) {
	connectionID := strings.TrimSpace(payload.ConnectionID)
	targetEndpoint := normalizeGatewayNodeID(strings.TrimSpace(payload.TargetEndpoint))
	candidates := buildPortForwardTransitCandidates(payload)
	if len(candidates) == 0 {
		_ = tc.SendJSON(MsgTypePortForwardResponse, PortForwardResponsePayload{
			ConnectionID: connectionID,
			Success:      false,
			Error:        "no p2p transit candidate available",
		})
		return
	}

	relayConn, selectedNode, err := dialPortForwardPeerCandidates(candidates)
	if err != nil {
		_ = tc.SendJSON(MsgTypePortForwardResponse, PortForwardResponsePayload{
			ConnectionID: connectionID,
			Success:      false,
			Error:        err.Error(),
		})
		return
	}
	defer relayConn.Close()

	relayPayload := payload
	relayPayload.HopCount = payload.HopCount + 1
	if relayPayload.HopCount > endpointHopGuardMax {
		_ = tc.SendJSON(MsgTypePortForwardResponse, PortForwardResponsePayload{
			ConnectionID: connectionID,
			Success:      false,
			Error:        fmt.Sprintf("hop_guard rejected hop_count=%d max_hop=%d", relayPayload.HopCount, endpointHopGuardMax),
		})
		return
	}
	if targetEndpoint != "" && strings.EqualFold(normalizeGatewayNodeID(selectedNode), targetEndpoint) {
		relayPayload.GridNextHop = ""
		relayPayload.GridHops = nil
	} else {
		relayPayload.GridNextHop = targetEndpoint
		relayPayload.GridHops = buildPortForwardTransitBackups(targetEndpoint, candidates, selectedNode)
	}

	relayTC := NewTunnelConn(relayConn)
	if err := relayTC.SendJSON(MsgTypePortForwardRequest, relayPayload); err != nil {
		_ = tc.SendJSON(MsgTypePortForwardResponse, PortForwardResponsePayload{
			ConnectionID: connectionID,
			Success:      false,
			Error:        fmt.Sprintf("send transit request failed: %v", err),
		})
		return
	}

	_ = relayConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	respMsg, err := relayTC.ReadMessage()
	_ = relayConn.SetReadDeadline(time.Time{})
	if err != nil {
		_ = tc.SendJSON(MsgTypePortForwardResponse, PortForwardResponsePayload{
			ConnectionID: connectionID,
			Success:      false,
			Error:        fmt.Sprintf("read transit response failed: %v", err),
		})
		return
	}
	if respMsg.Type != MsgTypePortForwardResponse {
		_ = tc.SendJSON(MsgTypePortForwardResponse, PortForwardResponsePayload{
			ConnectionID: connectionID,
			Success:      false,
			Error:        fmt.Sprintf("unexpected transit response type %d", respMsg.Type),
		})
		return
	}

	var resp PortForwardResponsePayload
	if err := respMsg.ParseJSON(&resp); err != nil {
		_ = tc.SendJSON(MsgTypePortForwardResponse, PortForwardResponsePayload{
			ConnectionID: connectionID,
			Success:      false,
			Error:        fmt.Sprintf("parse transit response failed: %v", err),
		})
		return
	}

	_ = tc.SendJSON(MsgTypePortForwardResponse, resp)
	if !resp.Success {
		return
	}

	DebugLog("[PORT-MAP] Transit relay established conn=%s from=%s via=%s next=%s backups=%v",
		connectionID, sourceClient, selectedNode, strings.TrimSpace(relayPayload.GridNextHop), relayPayload.GridHops)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(relayConn, upstream)
		_ = relayConn.SetReadDeadline(time.Now())
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, relayConn)
		_ = upstream.SetReadDeadline(time.Now())
	}()
	wg.Wait()
}

func buildPortForwardTransitCandidates(payload PortForwardRequestPayload) []string {
	target := normalizeGatewayNodeID(strings.TrimSpace(payload.TargetEndpoint))
	explicit := make([]string, 0, len(payload.GridHops)+2)
	if next := normalizeGatewayNodeID(strings.TrimSpace(payload.GridNextHop)); next != "" {
		explicit = append(explicit, next)
	}
	for _, hop := range normalizeGridHops(payload.GridHops) {
		if nodeID := normalizeGatewayNodeID(hop); nodeID != "" {
			explicit = append(explicit, nodeID)
		}
	}
	if target != "" {
		explicit = append(explicit, target)
	}
	return buildPortForwardPeerCandidates(target, explicit)
}

func handleIncomingRequestStream(tc *TunnelConn, stream net.Conn, bootstrap *TunnelMessage, fromGatewayPeer bool) {
	var payload RequestStartPayloadTCP
	if err := bootstrap.ParseJSON(&payload); err != nil {
		log.Printf("[GRID] Failed to parse request start payload: %v", err)
		return
	}
	integritySecret := gridFrameIntegritySecretForConn(stream)
	if fromGatewayPeer {
		if err := verifyRequestGridFrameIntegrityWithSecret(payload, integritySecret); err != nil {
			log.Printf("[GRID] Reject transit request frame: %v", err)
			return
		}
	}

	requestID := strings.TrimSpace(payload.ID)
	if requestID == "" {
		requestID = generateRelayConnectionID()
	}

	finalHost := strings.TrimSpace(payload.GridFinalHost)
	if finalHost == "" {
		finalHost = extractGridDestination(payload.URL)
	}
	if err := applyGridFrameMetadata(finalHost, payload.RouteID, payload.RouteEpoch, payload.HopCount, payload.TraceID); err != nil {
		log.Printf("[GRID-REQ %s] %v", requestID, err)
		sendTCPErrorResponse(tc, requestID, err.Error())
		return
	}

	nextHop := strings.TrimSpace(payload.GridNextHop)
	remainingHops := normalizeGridHops(payload.GridHops)
	if nextHop != "" {
		transitDedupKey := buildRequestTransitRelayDedupKey(payload, finalHost, nextHop, remainingHops)
		if !acquireTransitRelayDedup(transitDedupKey) {
			DebugLog("[GRID-REQ %s] duplicate transit suppressed key=%s next=%s", requestID, transitDedupKey, nextHop)
			sendTCPErrorResponse(tc, requestID, "duplicate transit probe suppressed")
			return
		}
		if strings.TrimSpace(transitDedupKey) != "" {
			defer releaseTransitRelayDedup(transitDedupKey)
		}

		relayMode := "p2p"
		relayConn, selectedNextHop, err := dialGatewayPeerGridBundle(nextHop, remainingHops, gatewayRouteBundleMaxAddrs)
		if err == nil {
			nextHop = selectedNextHop
		}
		if err != nil {
			relayMode = "aps-relay"
			relaySession := getActiveTunnelSession()
			if relaySession == nil {
				sendTCPErrorResponse(tc, requestID, "relay session not available")
				return
			}
			relayConn, err = relaySession.OpenStream()
			if err != nil {
				sendTCPErrorResponse(tc, requestID, err.Error())
				return
			}
		}
		defer relayConn.Close()

		nextForReceiver := ""
		tail := []string(nil)
		if len(remainingHops) > 0 {
			nextForReceiver = remainingHops[0]
			if len(remainingHops) > 1 {
				tail = append(tail, remainingHops[1:]...)
			}
		}

		relayPayload := payload
		relayPayload.GridRouteTo = ""
		relayPayload.GridNextHop = nextForReceiver
		relayPayload.GridHops = tail
		relayPayload.HopCount = payload.HopCount + 1
		if relayMode == "aps-relay" {
			relayPayload.GridRouteTo = nextHop
		}
		signRequestGridFrameIntegrityWithSecret(&relayPayload, gridFrameIntegritySecretForConn(relayConn))

		relayTC := NewTunnelConn(relayConn)
		if err := relayTC.SendJSON(MsgTypeRequestStart, relayPayload); err != nil {
			sendTCPErrorResponse(tc, requestID, err.Error())
			return
		}
		DebugLog("[GRID-REQ %s] Transit relay next=%s remaining=%v final=%s mode=%s", requestID, nextHop, remainingHops, finalHost, relayMode)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = io.Copy(relayConn, stream)
		}()
		go func() {
			defer wg.Done()
			_, _ = io.Copy(stream, relayConn)
		}()
		wg.Wait()
		return
	}

	if !payload.GridPayloadPlain {
		sendTCPErrorResponse(tc, requestID, "encrypted request stream over relay is not supported")
		return
	}

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload.Header)))
	if err != nil {
		sendTCPErrorResponse(tc, requestID, "cannot read request header")
		return
	}

	targetURL, err := url.Parse(payload.URL)
	if err != nil {
		sendTCPErrorResponse(tc, requestID, "invalid target url")
		return
	}
	req.URL = targetURL
	req.RequestURI = ""

	pipeReader, pipeWriter := io.Pipe()
	initialBody := req.Body
	if initialBody != nil {
		req.Body = &multiReadCloser{
			reader:  io.MultiReader(initialBody, pipeReader),
			closers: []io.Closer{initialBody, pipeReader},
		}
	} else {
		req.Body = pipeReader
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		executeIncomingStreamHTTPRequest(tc, requestID, req)
	}()

	for {
		msg, readErr := tc.ReadMessage()
		if readErr != nil {
			_ = pipeWriter.CloseWithError(readErr)
			<-done
			return
		}
		switch msg.Type {
		case MsgTypeRequestChunkBin:
			scopeID, chunkData, err := ParseScopedBinaryPayload(msg.Payload)
			if err != nil {
				_ = pipeWriter.CloseWithError(err)
				<-done
				return
			}
			if scopeID != requestID {
				continue
			}
			if err := writeAllToPipe(pipeWriter, chunkData); err != nil {
				_ = pipeWriter.CloseWithError(err)
				<-done
				return
			}
		case MsgTypeRequestEnd:
			var endPayload RequestEndPayloadTCP
			if err := msg.ParseJSON(&endPayload); err != nil {
				_ = pipeWriter.CloseWithError(err)
				<-done
				return
			}
			if endPayload.ID != requestID {
				continue
			}
			if endPayload.Error != "" {
				_ = pipeWriter.CloseWithError(errors.New(endPayload.Error))
			} else {
				_ = pipeWriter.Close()
			}
			<-done
			return
		}
	}
}

func executeIncomingStreamHTTPRequest(tc *TunnelConn, requestID string, req *http.Request) {
	atomic.AddInt64(&activeTunnelRequests, 1)
	defer atomic.AddInt64(&activeTunnelRequests, -1)
	if req != nil && req.Body != nil {
		defer req.Body.Close()
	}

	resp, err := sharedClient.Do(req)
	if err != nil {
		sendTCPErrorResponse(tc, requestID, err.Error())
		return
	}
	defer resp.Body.Close()

	headerBytes, err := httputil.DumpResponse(resp, false)
	if err != nil {
		sendTCPErrorResponse(tc, requestID, "failed to dump response")
		return
	}

	if err := tc.SendJSON(MsgTypeResponseHeader, ResponseHeaderPayloadTCP{
		ID:     requestID,
		Header: headerBytes,
	}); err != nil {
		return
	}

	buf := GetLargeBuffer()
	defer PutLargeBuffer(buf)

	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if err := sendScopedBinaryMessage(tc, MsgTypeResponseChunkBin, requestID, buf[:n]); err != nil {
				return
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			sendTCPErrorResponse(tc, requestID, "read body error")
			return
		}
	}

	_ = tc.SendJSON(MsgTypeResponseEnd, ResponseEndPayloadTCP{ID: requestID})
}
