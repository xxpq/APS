package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
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

const (
	defaultMaxMessageSize    = 32 * 1024 * 1024
	maxMessageSizeUpperBound = 32 * 1024 * 1024
	minMessageSizeLowerBound = 1 * 1024 * 1024
	maxFrameSizeEnv          = "APS_TUNNEL_MAX_FRAME_MB"
)

var maxMessageSize = loadTunnelMaxMessageSize()

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
	Success     bool   `json:"success"`
	Error       string `json:"error,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`
}

// RequestPayloadTCP for HTTP request
type RequestPayloadTCP struct {
	ID   string `json:"id"`
	URL  string `json:"url"`
	Data []byte `json:"data"`
}

type RequestStartPayloadTCP struct {
	ID     string `json:"id"`
	URL    string `json:"url"`
	Header []byte `json:"header"`
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

// ProxyConnectPayload for TCP proxy connect
type ProxyConnectPayload struct {
	ConnectionID string `json:"connection_id"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	TLS          bool   `json:"tls"`
	ClientIP     string `json:"client_ip"`
	StreamMode   bool   `json:"stream_mode"`
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

	frame := make([]byte, headerSize+len(msg.Payload))
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

func buildTunnelTLSConfig(serverHost string, expectedPinHash []byte, connCtx ImmutableConnectionContext) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverHost,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("missing peer certificate")
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

func dialTunnelServer(serverAddress, serverHost string, expectedPinHash []byte, connCtx ImmutableConnectionContext) (net.Conn, error) {
	tlsConfig, err := buildTunnelTLSConfig(serverHost, expectedPinHash, connCtx)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", serverAddress, tlsConfig)
	if err != nil {
		return nil, err
	}

	upgradedConn, err := connectWithHTTPTunnelHandshake(conn, serverAddress)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("CONNECT /.tunnel over TLS failed: %w", err)
	}

	DebugLog("[CONN] CONNECT /.tunnel handshake over TLS succeeded")
	return upgradedConn, nil
}

// runTCPTunnelSession connects to APS via TCP tunnel protocol
type TunnelSessionState struct {
	mu                sync.RWMutex
	TunnelName        string
	EndpointName      string
	SessionCredential string
	SessionExpiresAt  int64
	PortMappings      []PortMappingConfig
	KDFVersion        string
	KDFSalt           string
}

func runTCPTunnelSession(ctx context.Context, connCtx ImmutableConnectionContext) bool {
	serverAddress := normalizeServerAddressForSession(connCtx.ServerAddress)
	DebugLog("Connecting to TCP tunnel server at %s", serverAddress)
	DebugLog("[CONN] Tunnel transport mode: strict TLS + CONNECT /.tunnel")

	// 如果serverAddr不包含端口，则添加默认端口
	if serverAddress == "" {
		log.Printf("Failed to connect: empty server address")
		return true
	}

	regServerHost, regPinHash, err := GetTLSPinRegistrationInfo(serverAddress)
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

	conn, err := dialTunnelServer(serverAddress, regServerHost, regPinHash, connCtx)
	if err != nil {
		log.Printf("Failed to connect: %v", err)
		return true
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
		if isPermanentError(errors.New(ack.Error)) {
			return false
		}
		return true
	}
	if ack.CipherSuite != SecureCipherSuiteSPKITS {
		log.Printf("Registration failed: secure cipher suite negotiation failed (expected %s, got %s)", SecureCipherSuiteSPKITS, ack.CipherSuite)
		return false
	}

	log.Println("Successfully registered with TCP tunnel server")

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
	defer session.Close()

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
		TunnelName:        connCtx.TunnelName,
		EndpointName:      connCtx.EndpointName,
		SessionCredential: connCtx.SessionCredential,
		SessionExpiresAt:  connCtx.SessionExpiresAt,
		PortMappings:      clonePortMappingsForContext(connCtx.PortMappings),
		KDFVersion:        connCtx.KDFVersion,
		KDFSalt:           connCtx.KDFSalt,
	}
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

func handleTCPProbePing(tc *TunnelConn, msg *TunnelMessage) {
	var payload ProbePayload
	if err := msg.ParseJSON(&payload); err != nil {
		return
	}
	_ = tc.SendJSON(MsgTypeProbePong, payload)
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
	TunnelName        string              `json:"tunnelName"`
	EndpointName      string              `json:"endpointName"`
	SessionCredential string              `json:"sessionCredential,omitempty"`
	SessionExpiresAt  int64               `json:"sessionExpiresAt,omitempty"`
	KDFVersion        string              `json:"kdfVersion,omitempty"`
	KDFSalt           string              `json:"kdfSalt,omitempty"`
	PortMappings      []PortMappingConfig `json:"portMappings,omitempty"`
}

// MirrorUpdatePayload is sent by APS to inform endpoint of mirror addresses
type MirrorUpdatePayload struct {
	Mirrors []string `json:"mirrors"` // Format: ["addr:port", "cid@addr:port", ...]
}

// handleConfigUpdate handles configuration update pushed from APS
func handleConfigUpdate(tc *TunnelConn, msg *TunnelMessage, sessionState *TunnelSessionState) {
	var payload ConfigUpdatePayload
	if err := msg.ParseJSON(&payload); err != nil {
		log.Printf("[CONFIG] Failed to parse config update: %v", err)
		return
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

	sessionState.mu.Unlock()

	if shouldReconnect {
		log.Printf("[CONFIG] Critical configuration changed (tunnel/endpoint/sessionCredential/KDF), reconnecting...")
		closeTunnelConnWithReason(tc, "config update requires reconnect")
		return
	}

	DebugLog("[CONFIG] Updated runtime config: tunnel=%s, endpoint=%s, portMappings=%d",
		payload.TunnelName, payload.EndpointName, len(payload.PortMappings))
}

// handleMirrorUpdate processes mirror address updates from APS
func handleMirrorUpdate(tc *TunnelConn, msg *TunnelMessage) {
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

	DebugLog("[KEY] Key rotation completed (responder)")
}

// acceptStreams handles incoming streams from SMUX session
func acceptStreams(session *smux.Session, controlTc *TunnelConn, km *SessionKeyManager) {
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			log.Printf("SMUX accept error: %v", err)
			return
		}
		go handleIncomingStream(stream, controlTc)
	}
}

// handleIncomingStream handles a new stream from APS
func handleIncomingStream(stream *smux.Stream, controlTc *TunnelConn) {
	defer stream.Close()

	// Read ProxyConnectPayload from the stream
	tc := NewTunnelConn(stream)
	msg, err := tc.ReadMessage()
	if err != nil {
		log.Printf("Failed to read proxy connect from stream: %v", err)
		return
	}

	if msg.Type != MsgTypeProxyConnect {
		log.Printf("Unexpected message type on new stream: %d", msg.Type)
		return
	}

	var payload ProxyConnectPayload
	if err := msg.ParseJSON(&payload); err != nil {
		log.Printf("Failed to parse proxy connect payload: %v", err)
		return
	}

	connID := payload.ConnectionID
	address := net.JoinHostPort(payload.Host, fmt.Sprintf("%d", payload.Port))
	DebugLog("[PROXY %s] Connecting to %s (client: %s)", connID, address, payload.ClientIP)

	// Dial backend
	backendConn, err := net.DialTimeout("tcp", address, 30*time.Second)

	ack := ProxyConnectAckPayload{
		ConnectionID: connID,
		Success:      err == nil,
	}
	if err != nil {
		ack.Error = err.Error()
		log.Printf("[PROXY %s] Connection failed: %v", connID, err)
	} else {
		DebugLog("[PROXY %s] TCP connection established to %s", connID, address)
	}

	// Send Ack on control channel
	if err := controlTc.SendJSON(MsgTypeProxyConnectAck, ack); err != nil {
		log.Printf("[PROXY %s] Failed to send ack: %v", connID, err)
		if backendConn != nil {
			backendConn.Close()
		}
		return
	}

	if err != nil {
		return
	}

	defer backendConn.Close()

	// Bidirectional copy
	DebugLog("[PROXY %s] Starting stream copy", connID)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(stream, backendConn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(backendConn, stream)
	}()

	wg.Wait()
	DebugLog("[PROXY %s] Stream copy finished", connID)
}
