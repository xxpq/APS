package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"

	"aps/security"
)

const responseRouteEnqueueTimeout = 10 * time.Second

// TCPTunnelServer handles TCP connections from endpoints
type TCPTunnelServer struct {
	mu            sync.RWMutex
	listener      net.Listener
	tunnelManager *TCPTunnelManager
	endpoints     map[string]*TCPEndpoint // endpointID -> endpoint
	portForwards  map[string]portForwardRouteState
	config        *Config
	statsDB       *StatsDB
	running       bool
	replayMu      sync.Mutex
	replaySeen    map[string]int64
}

const secureRegistrationWindow = 90 * time.Second


// EndpointStats holds statistics for an endpoint
type EndpointStats struct {
	RequestCount uint64  `json:"requestCount"`
	Errors       uint64  `json:"errors"`
	Intercepted  uint64  `json:"intercepted"`
	BytesSent    uint64  `json:"bytesSent"`
	BytesRecv    uint64  `json:"bytesRecv"`
	QPS          float64 `json:"qps"`
}

// TCPEndpoint represents an endpoint connected via TCP
type TCPEndpoint struct {
	ID               string
	TunnelName       string
	EndpointName     string
	ConfigID         string
	Conn             *TunnelConn
	RemoteAddr       string
	OnlineTime       time.Time
	LastActivityTime time.Time
	Stats            EndpointStats

	// Session key manager for dynamic encryption
	KeyManager *SessionKeyManager
	ControlOut *ControlPlaneOutboundState

	// Pending requests and proxy connections
	mu              sync.Mutex
	pendingRequests map[string]*tcpPendingRequest  // requestID -> pending
	proxyConns      map[string]*tcpProxyConnection // connectionID -> proxy

	// Control channels
	sendChan    chan *TunnelMessage
	done        chan struct{}
	closeOnce   sync.Once // Ensures done channel is closed only once
	session     *smux.Session
	closeReason string

	// Scheduling + health
	activeRequests int64
	schedMu        sync.RWMutex
	ewmaLatency    time.Duration
	lastProbeRTT   time.Duration
	lastProbeAt    time.Time
	healthScore    float64
	probeFailures  int

	// Active probe rendezvous
	probeMu      sync.Mutex
	probeWaiters map[uint64]chan struct{}
	probeNonce   uint64
}

// tcpPendingRequest represents a pending HTTP request
type tcpPendingRequest struct {
	responseChan chan *TunnelMessage
	pipeWriter   *io.PipeWriter
	sourceIP     string
	targetAddr   string
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

type portForwardRouteState struct {
	ConnectionID     string
	TunnelName       string
	SourceEndpointID string
	SourceEndpoint   string
	TargetEndpointID string
	TargetEndpoint   string
	RemoteTarget     string
	LastActivity     time.Time
	Established      bool
}

// NewTCPTunnelServer creates a new TCP tunnel server.
func NewTCPTunnelServer(config *Config, statsDB *StatsDB) *TCPTunnelServer {
	return &TCPTunnelServer{
		config:       config,
		statsDB:      statsDB,
		endpoints:    make(map[string]*TCPEndpoint),
		portForwards: make(map[string]portForwardRouteState),
		replaySeen:   make(map[string]int64, 1024),
	}
}

// SetTunnelManager sets the tunnel manager (called after manager is created)
func (s *TCPTunnelServer) SetTunnelManager(tm *TCPTunnelManager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tunnelManager = tm
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

func isRegistrationTimestampFresh(ts int64) bool {
	now := time.Now().UTC().Unix()
	delta := now - ts
	if delta < 0 {
		delta = -delta
	}
	return time.Duration(delta)*time.Second <= secureRegistrationWindow
}

func (s *TCPTunnelServer) registerSecureRegistrationReplayToken(cid string, ts int64, proof string) error {
	now := time.Now().UTC().Unix()
	expiry := ts + int64((secureRegistrationWindow + time.Minute).Seconds())
	token := cid + "|" + strconv.FormatInt(ts, 10) + "|" + proof

	if s.statsDB == nil {
		return errors.New("persistent replay storage unavailable")
	}

	isReplay, err := s.statsDB.CheckAndStoreReplayToken("secure_reg", token, expiry)
	if err != nil {
		return fmt.Errorf("persistent registration replay check failed: %w", err)
	}
	if isReplay {
		return errors.New("registration replay detected")
	}
	if err := s.statsDB.DeleteExpiredReplayTokens(now); err != nil {
		return fmt.Errorf("persistent registration replay cleanup failed: %w", err)
	}

	s.replayMu.Lock()
	defer s.replayMu.Unlock()

	for k, exp := range s.replaySeen {
		if exp < now {
			delete(s.replaySeen, k)
		}
	}
	if exp, exists := s.replaySeen[token]; exists && exp >= now {
		return errors.New("registration replay detected")
	}
	s.replaySeen[token] = expiry
	if len(s.replaySeen) > SecureReplayMaxEntries {
		toDelete := len(s.replaySeen) - SecureReplayMaxEntries
		for k := range s.replaySeen {
			delete(s.replaySeen, k)
			toDelete--
			if toDelete <= 0 {
				break
			}
		}
	}
	return nil
}

func isTunnelBoundToServer(tunnelConfig *TunnelConfig, serverName string) bool {
	if tunnelConfig == nil || strings.TrimSpace(serverName) == "" {
		return false
	}
	for _, bound := range tunnelConfig.Servers {
		if strings.TrimSpace(bound) == strings.TrimSpace(serverName) {
			return true
		}
	}
	return false
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
	listenerServerName := ""
	if tagged, ok := conn.(interface{ TunnelServerName() string }); ok {
		listenerServerName = strings.TrimSpace(tagged.TunnelServerName())
	}

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

	// Validate tunnel and endpoint binding
	s.mu.RLock()
	tunnelConfig, tunnelExists := s.config.Tunnels[reg.TunnelName]
	endpointConfig, endpointExists := s.config.Endpoints[reg.ConfigID]
	s.mu.RUnlock()

	if !tunnelExists {
		DebugLog("[TCP TUNNEL] Tunnel '%s' not found from %s", reg.TunnelName, remoteAddr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "tunnel not found",
		})
		tc.Close()
		return
	}
	if strings.TrimSpace(reg.ServerName) == "" {
		DebugLog("[TCP TUNNEL] Missing server_name in registration from %s", remoteAddr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "missing server_name",
		})
		tc.Close()
		return
	}
	if listenerServerName == "" {
		DebugLog("[TCP TUNNEL] Listener server name unavailable for registration from %s", remoteAddr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "listener server context unavailable",
		})
		tc.Close()
		return
	}
	if !isTunnelBoundToServer(tunnelConfig, reg.ServerName) {
		DebugLog("[TCP TUNNEL] tunnel '%s' is not bound to server '%s' for %s", reg.TunnelName, reg.ServerName, remoteAddr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "server_name not bound to tunnel",
		})
		tc.Close()
		return
	}
	if strings.TrimSpace(reg.ServerName) != listenerServerName {
		DebugLog("[TCP TUNNEL] server_name mismatch reg='%s' listener='%s' from %s", reg.ServerName, listenerServerName, remoteAddr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "server_name mismatch",
		})
		tc.Close()
		return
	}

	// Enforce secure handshake; no legacy compatibility mode.
	if reg.CipherSuite != SecureCipherSuiteSPKITS {
		DebugLog("[TCP TUNNEL] Unsupported cipher suite '%s' from %s", reg.CipherSuite, remoteAddr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "unsupported cipher suite",
		})
		tc.Close()
		return
	}
	if reg.ServerHost == "" || reg.PinHash == "" || strings.TrimSpace(reg.ConfigID) == "" || strings.TrimSpace(reg.AuthProof) == "" || reg.Timestamp == 0 {
		DebugLog("[TCP TUNNEL] Missing secure registration fields from %s", remoteAddr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "missing secure registration fields",
		})
		tc.Close()
		return
	}
	if !isRegistrationTimestampFresh(reg.Timestamp) {
		DebugLog("[TCP TUNNEL] Registration timestamp out of window from %s", remoteAddr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "registration timestamp out of window",
		})
		tc.Close()
		return
	}
	if !endpointExists || endpointConfig == nil {
		DebugLog("[TCP TUNNEL] Config id '%s' not found from %s", reg.ConfigID, remoteAddr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "config id not found",
		})
		tc.Close()
		return
	}
	if endpointConfig.TunnelName != reg.TunnelName || endpointConfig.EndpointName != reg.EndpointName {
		DebugLog("[TCP TUNNEL] CID binding mismatch for cid '%s' from %s", reg.ConfigID, remoteAddr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "cid binding mismatch",
		})
		tc.Close()
		return
	}
	if !endpointConfig.AllowMultiNode {
		s.mu.RLock()
		alreadyOnline := false
		for _, online := range s.endpoints {
			if online == nil || !online.IsOnline() {
				continue
			}
			if online.TunnelName == reg.TunnelName && online.EndpointName == reg.EndpointName {
				alreadyOnline = true
				break
			}
		}
		s.mu.RUnlock()
		if alreadyOnline {
			DebugLog("[TCP TUNNEL] multi-node denied for tunnel='%s' endpoint='%s' from %s", reg.TunnelName, reg.EndpointName, remoteAddr)
			tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
				Success: false,
				Error:   "multiple online nodes are not allowed",
			})
			tc.Close()
			return
		}
	}

	effectiveCredential, credErr := security.PeekEndpointSessionCredential(reg.ConfigID, reg.TunnelName, reg.EndpointName)
	if credErr != nil {
		DebugLog("[TCP TUNNEL] Missing/invalid session credential for cid '%s' from %s: %v", reg.ConfigID, remoteAddr, credErr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "session credential missing or expired",
		})
		tc.Close()
		return
	}
	if !isHostInACMEWhitelist(reg.ServerHost) {
		DebugLog("[TCP TUNNEL] server_host '%s' is not in ACME whitelist from %s", reg.ServerHost, remoteAddr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "server_host not in ACME whitelist",
		})
		tc.Close()
		return
	}
	expectedPinHash, ok := lookupTLSPinHashForHost(reg.ServerHost)
	if !ok {
		DebugLog("[TCP TUNNEL] TLS pin hash unavailable for host '%s' from %s", reg.ServerHost, remoteAddr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "tls pin not available for host",
		})
		tc.Close()
		return
	}
	expectedHashHex := hex.EncodeToString(expectedPinHash)
	if !strings.EqualFold(expectedHashHex, reg.PinHash) {
		providedHash := strings.ToLower(strings.TrimSpace(reg.PinHash))
		providedHint := providedHash
		if len(providedHint) > 12 {
			providedHint = providedHint[:12]
		}
		expectedHint := expectedHashHex
		if len(expectedHint) > 12 {
			expectedHint = expectedHint[:12]
		}
		DebugLog("[TCP TUNNEL] TLS pin hash mismatch for host '%s' from %s provided=%s... expected=%s...", reg.ServerHost, remoteAddr, providedHint, expectedHint)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "tls pin hash mismatch",
		})
		tc.Close()
		return
	}
	expectedProofHex, proofErr := computeSecureRegistrationProof(
		effectiveCredential,
		reg.ConfigID,
		reg.TunnelName,
		reg.EndpointName,
		reg.ServerHost,
		expectedHashHex,
		reg.CipherSuite,
		reg.Timestamp,
		tunnelConfig.KDFVersion,
		tunnelConfig.KDFSalt,
	)
	if proofErr != nil {
		DebugLog("[TCP TUNNEL] Failed to derive registration proof key for cid '%s' from %s: %v", reg.ConfigID, remoteAddr, proofErr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "registration proof derivation failed",
		})
		tc.Close()
		return
	}
	providedProof, err := hex.DecodeString(strings.TrimSpace(reg.AuthProof))
	if err != nil {
		DebugLog("[TCP TUNNEL] Invalid auth proof encoding from %s", remoteAddr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "invalid auth proof encoding",
		})
		tc.Close()
		return
	}
	expectedProof, _ := hex.DecodeString(expectedProofHex)
	if !hmac.Equal(providedProof, expectedProof) {
		DebugLog("[TCP TUNNEL] Auth proof mismatch for cid '%s' from %s", reg.ConfigID, remoteAddr)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "auth proof mismatch",
		})
		tc.Close()
		return
	}
	if err := s.registerSecureRegistrationReplayToken(reg.ConfigID, reg.Timestamp, strings.TrimSpace(reg.AuthProof)); err != nil {
		DebugLog("[TCP TUNNEL] Replay rejected for cid '%s' from %s: %v", reg.ConfigID, remoteAddr, err)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "registration replay detected",
		})
		tc.Close()
		return
	}
	if err := security.ConsumeEndpointSessionCredential(reg.ConfigID, reg.TunnelName, reg.EndpointName, effectiveCredential); err != nil {
		DebugLog("[TCP TUNNEL] Session credential consume failed for cid '%s' from %s: %v", reg.ConfigID, remoteAddr, err)
		tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
			Success: false,
			Error:   "session credential already used or invalid",
		})
		tc.Close()
		return
	}
	securePinHash := expectedPinHash
	negotiatedCipherSuite := SecureCipherSuiteSPKITS

	// Clear read deadline after successful registration
	conn.SetReadDeadline(time.Time{})

	// Create endpoint
	endpoint := &TCPEndpoint{
		ID:               generateRequestID(),
		TunnelName:       reg.TunnelName,
		EndpointName:     reg.EndpointName,
		ConfigID:         strings.TrimSpace(reg.ConfigID),
		Conn:             tc,
		RemoteAddr:       remoteAddr,
		OnlineTime:       time.Now(),
		LastActivityTime: time.Now(),
		pendingRequests:  make(map[string]*tcpPendingRequest),
		proxyConns:       make(map[string]*tcpProxyConnection),
		sendChan:         make(chan *TunnelMessage, 1000), // Increased from 100 to 1000
		done:             make(chan struct{}),
		healthScore:      1.0,
		probeWaiters:     make(map[uint64]chan struct{}),
	}

	// Initialize per-connection session key manager
	endpoint.KeyManager = NewSessionKeyManager(effectiveCredential, reg.EndpointName, s.statsDB)
	if err := endpoint.KeyManager.SetKDFParams(tunnelConfig.KDFVersion, tunnelConfig.KDFSalt); err != nil {
		DebugLog("[TCP TUNNEL] Failed to set KDF parameters for %s: %v", remoteAddr, err)
		tc.Close()
		return
	}
	if err := endpoint.KeyManager.DeriveInitialKey(); err != nil {
		DebugLog("[TCP TUNNEL] Failed to derive initial key for %s: %v", remoteAddr, err)
		tc.Close()
		return
	}
	if err := endpoint.KeyManager.EnableSecureTransport(securePinHash, reg.ConfigID); err != nil {
		DebugLog("[TCP TUNNEL] Failed to enable secure transport for %s: %v", remoteAddr, err)
		tc.Close()
		return
	}
	endpoint.ControlOut = NewControlPlaneOutboundState()

	// Register endpoint
	s.mu.Lock()
	s.endpoints[endpoint.ID] = endpoint
	s.mu.Unlock()



	// Send registration acknowledgement
	if err := tc.SendJSON(MsgTypeRegisterAck, RegisterAckPayload{
		Success:            true,
		CipherSuite:        negotiatedCipherSuite,
	}); err != nil {
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
	go endpoint.probeLoop()

	// Send mirror addresses if configured (non-blocking)
	go sendMirrorUpdate(s, endpoint)

	// Start auto key rotation (APS initiates first key negotiation after a delay)
	go func(ep *TCPEndpoint) {
		select {
		case <-ep.done:
			return
		case <-time.After(5 * time.Second):
			// Wait for connection to stabilize
		}
		if !ep.IsOnline() {
			return
		}
		ep.initiateKeyRotation()
		ep.KeyManager.StartAutoRotation(func() error {
			return ep.initiateKeyRotation()
		})
	}(endpoint)

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
		for connectionID, route := range s.portForwards {
			if route.SourceEndpointID == endpointID || route.TargetEndpointID == endpointID {
				delete(s.portForwards, connectionID)
			}
		}
	}
	s.mu.Unlock()

	if exists && s.tunnelManager != nil {
		s.tunnelManager.UnregisterEndpoint(endpoint)
	}
	if exists {
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

// CloseWithReason closes the endpoint connection and records the trigger reason once.
func (ep *TCPEndpoint) CloseWithReason(reason string) {
	if reason == "" {
		reason = "unspecified"
	}

	// Use sync.Once to ensure done channel is closed exactly once
	ep.closeOnce.Do(func() {
		ep.closeReason = reason

		ep.mu.Lock()
		pendingCount := len(ep.pendingRequests)
		proxyCount := len(ep.proxyConns)
		ep.mu.Unlock()

		log.Printf("[TCP TUNNEL] Closing endpoint '%s' (id=%s, remote=%s): %s (pending_requests=%d, proxy_conns=%d)",
			ep.EndpointName, ep.ID, ep.RemoteAddr, ep.closeReason, pendingCount, proxyCount)
		close(ep.done)

		if ep.KeyManager != nil {
			ep.KeyManager.StopAutoRotation()
		}

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

		ep.probeMu.Lock()
		for nonce, ch := range ep.probeWaiters {
			select {
			case ch <- struct{}{}:
			default:
			}
			delete(ep.probeWaiters, nonce)
		}
		ep.probeMu.Unlock()
	})
}

// Close closes the endpoint connection with a default reason.
func (ep *TCPEndpoint) Close() {
	ep.CloseWithReason("Close() called")
}

// IsOnline returns true if the endpoint is online
func (ep *TCPEndpoint) IsOnline() bool {
	select {
	case <-ep.done:
		return false
	default:
		return true
	}
}

func (ep *TCPEndpoint) MarkRequestStart() {
	atomic.AddInt64(&ep.activeRequests, 1)
}

func (ep *TCPEndpoint) MarkRequestDone(latency time.Duration, err error) {
	current := atomic.AddInt64(&ep.activeRequests, -1)
	if current < 0 {
		atomic.StoreInt64(&ep.activeRequests, 0)
	}

	ep.schedMu.Lock()
	defer ep.schedMu.Unlock()
	ep.updateEWMA(latency)
	if ep.healthScore <= 0 {
		ep.healthScore = 1.0
	}
	if err != nil {
		ep.healthScore -= 0.1
	} else {
		ep.healthScore += 0.02
	}
	if ep.healthScore < 0.1 {
		ep.healthScore = 0.1
	}
	if ep.healthScore > 1.5 {
		ep.healthScore = 1.5
	}
}

func (ep *TCPEndpoint) GetSchedulingSnapshot() (int64, time.Duration, float64) {
	active := atomic.LoadInt64(&ep.activeRequests)

	ep.schedMu.RLock()
	latency := ep.ewmaLatency
	if latency <= 0 {
		latency = ep.lastProbeRTT
	}
	health := ep.healthScore
	lastProbeAt := ep.lastProbeAt
	probeFailures := ep.probeFailures
	ep.schedMu.RUnlock()

	if health <= 0 {
		health = 1.0
	}
	if !lastProbeAt.IsZero() && time.Since(lastProbeAt) > 2*time.Minute {
		health *= 0.85
	}
	if probeFailures > 0 {
		penalty := 1.0 - float64(probeFailures)*0.1
		if penalty < 0.5 {
			penalty = 0.5
		}
		health *= penalty
	}
	if health < 0.1 {
		health = 0.1
	}

	return active, latency, health
}

func (ep *TCPEndpoint) updateEWMA(sample time.Duration) {
	if sample <= 0 {
		return
	}
	const alpha = 0.2
	if ep.ewmaLatency <= 0 {
		ep.ewmaLatency = sample
		return
	}
	ep.ewmaLatency = time.Duration((1.0-alpha)*float64(ep.ewmaLatency) + alpha*float64(sample))
}

func (ep *TCPEndpoint) recordProbeSuccess(rtt time.Duration) {
	ep.schedMu.Lock()
	defer ep.schedMu.Unlock()
	if rtt > 0 {
		ep.lastProbeRTT = rtt
		ep.lastProbeAt = time.Now()
		ep.updateEWMA(rtt)
	}
	ep.probeFailures = 0
	if ep.healthScore <= 0 {
		ep.healthScore = 1.0
	}
	ep.healthScore += 0.05
	if ep.healthScore > 1.5 {
		ep.healthScore = 1.5
	}
}

func (ep *TCPEndpoint) recordProbeFailure() {
	ep.schedMu.Lock()
	defer ep.schedMu.Unlock()
	ep.probeFailures++
	if ep.healthScore <= 0 {
		ep.healthScore = 1.0
	}
	ep.healthScore *= 0.8
	if ep.healthScore < 0.1 {
		ep.healthScore = 0.1
	}
}

func (ep *TCPEndpoint) probeLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ep.done:
			return
		case <-ticker.C:
			ep.sendProbe()
		}
	}
}

func (ep *TCPEndpoint) sendProbe() {
	nonce := atomic.AddUint64(&ep.probeNonce, 1)
	waitCh := make(chan struct{}, 1)

	ep.probeMu.Lock()
	ep.probeWaiters[nonce] = waitCh
	ep.probeMu.Unlock()

	ts := time.Now().UnixNano()
	if err := ep.SendJSON(MsgTypeProbePing, ProbePayload{
		Nonce:     nonce,
		Timestamp: ts,
	}); err != nil {
		ep.probeMu.Lock()
		delete(ep.probeWaiters, nonce)
		ep.probeMu.Unlock()
		ep.recordProbeFailure()
		return
	}

	select {
	case <-ep.done:
		return
	case <-waitCh:
		ep.recordProbeSuccess(time.Since(time.Unix(0, ts)))
	case <-time.After(3 * time.Second):
		ep.probeMu.Lock()
		delete(ep.probeWaiters, nonce)
		ep.probeMu.Unlock()
		ep.recordProbeFailure()
	}
}

func (ep *TCPEndpoint) handleProbePing(msg *TunnelMessage) {
	var payload ProbePayload
	if err := msg.ParseJSON(&payload); err != nil {
		return
	}
	_ = ep.SendJSON(MsgTypeProbePong, payload)
}

func (ep *TCPEndpoint) handleProbePong(msg *TunnelMessage) {
	var payload ProbePayload
	if err := msg.ParseJSON(&payload); err != nil {
		return
	}

	ep.probeMu.Lock()
	waitCh := ep.probeWaiters[payload.Nonce]
	delete(ep.probeWaiters, payload.Nonce)
	ep.probeMu.Unlock()
	if waitCh == nil {
		return
	}
	select {
	case waitCh <- struct{}{}:
	default:
	}
}

// writeLoop sends messages to the endpoint
func (ep *TCPEndpoint) writeLoop() {
	heartbeatTicker := time.NewTicker(30 * time.Second)
	defer heartbeatTicker.Stop()

	for {
		select {
		case msg := <-ep.sendChan:
			if err := ep.Conn.WriteMessage(msg); err != nil {
				log.Printf("[TCP TUNNEL] Write error to endpoint '%s' (id=%s, remote=%s): %v",
					ep.EndpointName, ep.ID, ep.RemoteAddr, err)
				ep.CloseWithReason("writeLoop write error")
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
	for {
		// Set read deadline to detect dead connections
		// Client sends heartbeat every 30s, use 120s for large transfers
		ep.Conn.UnderlyingConn().SetReadDeadline(time.Now().Add(120 * time.Second))
		msg, err := ep.Conn.ReadMessage()
		if err != nil {
			if err == io.EOF {
				log.Printf("[TCP TUNNEL] Endpoint '%s' (id=%s, remote=%s) closed control stream (EOF)",
					ep.EndpointName, ep.ID, ep.RemoteAddr)
				ep.CloseWithReason("readLoop EOF from endpoint")
			} else {
				log.Printf("[TCP TUNNEL] Read error from endpoint '%s' (id=%s, remote=%s): %v",
					ep.EndpointName, ep.ID, ep.RemoteAddr, err)
				ep.CloseWithReason("readLoop read error")
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
		case MsgTypeProbePing:
			ep.handleProbePing(msg)
		case MsgTypeProbePong:
			ep.handleProbePong(msg)
		case MsgTypeResponseChunk:
			log.Printf("[TCP TUNNEL] Legacy response chunk format is not supported for endpoint '%s' (id=%s, remote=%s)",
				ep.EndpointName, ep.ID, ep.RemoteAddr)
			ep.CloseWithReason("legacy response chunk unsupported")
			return
		case MsgTypeResponseHeader, MsgTypeResponseChunkBin, MsgTypeResponseEnd:
			ep.handleResponseMessage(msg)
		case MsgTypeProxyConnectAck:
			ep.handleProxyConnectAck(msg)
		case MsgTypeProxyDataBinary:
			ep.handleTCPProxyDataBinary(msg)
		case MsgTypeProxyClose:
			ep.handleProxyClose(msg)
		case MsgTypePortForwardRequest:
			ep.handlePortForwardRequest(server, msg)
		case MsgTypePortForwardResponse:
			ep.handlePortForwardResponseRoute(server, msg)
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
	basePrefix := buildTCPTunnelRoutePrefix("", ep.EndpointName, ep.ID, "")

	// Parse based on message type
	var requestID string
	switch msg.Type {
	case MsgTypeResponseHeader:
		var payload ResponseHeaderPayloadTCP
		if err := msg.ParseJSON(&payload); err != nil {
			DebugLog("%s [TCP TUNNEL] Invalid response header: %v", basePrefix, err)
			return
		}
		requestID = payload.ID
	case MsgTypeResponseChunkBin:
		scopeID, _, err := ParseScopedBinaryPayload(msg.Payload)
		if err != nil {
			DebugLog("%s [TCP TUNNEL] Invalid binary response chunk: %v", basePrefix, err)
			return
		}
		requestID = scopeID
	case MsgTypeResponseEnd:
		var payload ResponseEndPayloadTCP
		if err := msg.ParseJSON(&payload); err != nil {
			DebugLog("%s [TCP TUNNEL] Invalid response end: %v", basePrefix, err)
			return
		}
		requestID = payload.ID
	}

	ep.mu.Lock()
	pending, ok := ep.pendingRequests[requestID]
	ep.mu.Unlock()

	logPrefix := basePrefix
	scopeSourceIP := ""
	scopeTargetAddr := ""
	if ok {
		logPrefix = buildTCPTunnelRoutePrefix(pending.sourceIP, ep.EndpointName, ep.ID, pending.targetAddr)
		scopeSourceIP = pending.sourceIP
		scopeTargetAddr = pending.targetAddr
	}

	debugLogTCPTunnelThrottled(
		scopeSourceIP,
		ep.EndpointName,
		ep.ID,
		scopeTargetAddr,
		tcpTunnelEventKey("endpoint_received_response_type", msg.Type),
		"%s [TCP TUNNEL] Endpoint %s received response message type %d",
		logPrefix,
		ep.ID,
		msg.Type,
	)
	debugLogTCPTunnelThrottled(
		scopeSourceIP,
		ep.EndpointName,
		ep.ID,
		scopeTargetAddr,
		tcpTunnelEventKey("routing_response_type", msg.Type),
		"%s [TCP TUNNEL] Routing response message type %d for request %s",
		logPrefix,
		msg.Type,
		requestID,
	)

	if !ok {
		debugLogTCPTunnelThrottled(
			scopeSourceIP,
			ep.EndpointName,
			ep.ID,
			scopeTargetAddr,
			"no_pending_request",
			"%s [TCP TUNNEL] WARNING: No pending request found for %s, message dropped",
			logPrefix,
			requestID,
		)
		return
	}

	defer func() {
		if r := recover(); r != nil {
			DebugLog("%s [TCP TUNNEL] Recovered from panic in handleResponseMessage (likely closed channel): %v", logPrefix, r)
		}
	}()

	select {
	case pending.responseChan <- msg:
		debugLogTCPTunnelThrottled(
			scopeSourceIP,
			ep.EndpointName,
			ep.ID,
			scopeTargetAddr,
			tcpTunnelEventKey("successfully_routed_response_type", msg.Type),
			"%s [TCP TUNNEL] Successfully routed message type %d for request %s",
			logPrefix,
			msg.Type,
			requestID,
		)
	case <-ep.done:
		return
	case <-time.After(responseRouteEnqueueTimeout):
		dropErr := fmt.Errorf("response routing timeout (type=%d): channel congested", msg.Type)
		DebugLog("%s [TCP TUNNEL] %v for request %s", logPrefix, dropErr, requestID)
		ep.failPendingRequest(requestID, pending, dropErr, logPrefix)
	}
}

func (ep *TCPEndpoint) failPendingRequest(requestID string, pending *tcpPendingRequest, cause error, logPrefix string) {
	ep.mu.Lock()
	current, ok := ep.pendingRequests[requestID]
	if ok && current == pending {
		delete(ep.pendingRequests, requestID)
	}
	ep.mu.Unlock()

	if !ok || current != pending {
		return
	}

	if pending.pipeWriter != nil {
		_ = pending.pipeWriter.CloseWithError(cause)
	}

	defer func() {
		if r := recover(); r != nil {
			DebugLog("%s [TCP TUNNEL] Recovered closing pending response channel for %s: %v", logPrefix, requestID, r)
		}
	}()
	close(pending.responseChan)
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
	payload.ConnectionID = strings.TrimSpace(payload.ConnectionID)
	payload.TargetEndpoint = strings.TrimSpace(payload.TargetEndpoint)
	payload.RemoteTarget = strings.TrimSpace(payload.RemoteTarget)
	if payload.ConnectionID == "" || payload.TargetEndpoint == "" || payload.RemoteTarget == "" {
		DebugLog("[PORT-FWD] Invalid request payload from %s (conn=%q target=%q remote=%q)",
			ep.EndpointName, payload.ConnectionID, payload.TargetEndpoint, payload.RemoteTarget)
		_ = ep.SendJSON(MsgTypePortForwardResponse, PortForwardResponsePayload{
			ConnectionID: payload.ConnectionID,
			Success:      false,
			Error:        "invalid port forward request",
		})
		return
	}

	DebugLog("[PORT-FWD] Request from %s to endpoint %s -> %s",
		ep.EndpointName, payload.TargetEndpoint, payload.RemoteTarget)

	// Find the target endpoint in the same tunnel by endpointName or CID.
	var (
		targetEp     *TCPEndpoint
		onlineTarget string
	)
	server.mu.RLock()
	targetEp = server.findPortForwardTargetEndpointLocked(ep.TunnelName, payload.TargetEndpoint)
	if targetEp == nil {
		onlineTarget = server.listOnlinePortForwardEndpointsLocked(ep.TunnelName)
	}
	server.mu.RUnlock()

	if targetEp == nil {
		DebugLog("[PORT-FWD] Target endpoint %s not found in tunnel %s (online=%s)",
			payload.TargetEndpoint, ep.TunnelName, onlineTarget)
		_ = ep.SendJSON(MsgTypePortForwardResponse, PortForwardResponsePayload{
			ConnectionID: payload.ConnectionID,
			Success:      false,
			Error:        "target endpoint not found",
		})
		return
	}

	server.mu.Lock()
	server.portForwards[payload.ConnectionID] = portForwardRouteState{
		ConnectionID:     payload.ConnectionID,
		TunnelName:       ep.TunnelName,
		SourceEndpointID: ep.ID,
		SourceEndpoint:   ep.EndpointName,
		TargetEndpointID: targetEp.ID,
		TargetEndpoint:   targetEp.EndpointName,
		RemoteTarget:     payload.RemoteTarget,
		LastActivity:     time.Now(),
	}
	server.mu.Unlock()

	// Forward the request to the target endpoint (msg type changes for target)
	// Target endpoint will connect to RemoteTarget and send response
	if err := targetEp.SendJSON(MsgTypePortForwardRequest, payload); err != nil {
		DebugLog("[PORT-FWD] Failed to forward request to %s: %v",
			payload.TargetEndpoint, err)
		server.mu.Lock()
		delete(server.portForwards, payload.ConnectionID)
		server.mu.Unlock()
		_ = ep.SendJSON(MsgTypePortForwardResponse, PortForwardResponsePayload{
			ConnectionID: payload.ConnectionID,
			Success:      false,
			Error:        "failed to reach target endpoint",
		})
		return
	}

	DebugLog("[PORT-FWD] Request forwarded conn=%s route=%s -> APS -> %s -> %s",
		payload.ConnectionID, ep.EndpointName, payload.TargetEndpoint, payload.RemoteTarget)
}

func endpointMatchesPortForwardTarget(endpoint *TCPEndpoint, target string) bool {
	if endpoint == nil {
		return false
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(endpoint.EndpointName), target) {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(endpoint.ConfigID), target) {
		return true
	}
	return false
}

func (s *TCPTunnelServer) findPortForwardTargetEndpointLocked(tunnelName, target string) *TCPEndpoint {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	}
	for _, endpoint := range s.endpoints {
		if endpoint == nil || endpoint.TunnelName != tunnelName {
			continue
		}
		if endpointMatchesPortForwardTarget(endpoint, target) {
			return endpoint
		}
	}
	return nil
}

func (s *TCPTunnelServer) listOnlinePortForwardEndpointsLocked(tunnelName string) string {
	labels := make([]string, 0, len(s.endpoints))
	for _, endpoint := range s.endpoints {
		if endpoint == nil || endpoint.TunnelName != tunnelName {
			continue
		}
		name := strings.TrimSpace(endpoint.EndpointName)
		cid := strings.TrimSpace(endpoint.ConfigID)
		switch {
		case name != "" && cid != "" && !strings.EqualFold(name, cid):
			labels = append(labels, fmt.Sprintf("%s[cid=%s]", name, cid))
		case name != "":
			labels = append(labels, name)
		case cid != "":
			labels = append(labels, "cid="+cid)
		}
	}
	if len(labels) == 0 {
		return "-"
	}
	sort.Strings(labels)
	return strings.Join(labels, ",")
}

// handlePortForwardResponseRoute routes port-forward response to the other endpoint.
func (ep *TCPEndpoint) handlePortForwardResponseRoute(server *TCPTunnelServer, msg *TunnelMessage) {
	var payload PortForwardResponsePayload
	if err := msg.ParseJSON(&payload); err != nil {
		DebugLog("[TCP TUNNEL] Invalid port forward response: %v", err)
		return
	}
	connectionID := strings.TrimSpace(payload.ConnectionID)
	if connectionID == "" {
		DebugLog("[PORT-FWD] Response missing connection id from %s", ep.EndpointName)
		return
	}

	var (
		peer *TCPEndpoint
		ok   bool
		rt   portForwardRouteState
	)
	server.mu.Lock()
	rt, ok = server.portForwards[connectionID]
	if ok {
		switch ep.ID {
		case rt.SourceEndpointID:
			peer = server.endpoints[rt.TargetEndpointID]
		case rt.TargetEndpointID:
			peer = server.endpoints[rt.SourceEndpointID]
		default:
			ok = false
		}
		if ok {
			rt.LastActivity = time.Now()
			if payload.Success {
				rt.Established = true
			}
			server.portForwards[connectionID] = rt
		}
	}
	server.mu.Unlock()

	if !ok || peer == nil {
		DebugLog("[PORT-FWD] Response route missing conn=%s from=%s", connectionID, ep.EndpointName)
		return
	}

	if err := peer.SendJSON(MsgTypePortForwardResponse, payload); err != nil {
		DebugLog("[PORT-FWD] Failed routing response conn=%s to %s: %v", connectionID, peer.EndpointName, err)
		server.mu.Lock()
		delete(server.portForwards, connectionID)
		server.mu.Unlock()
		return
	}

	if !payload.Success {
		server.mu.Lock()
		delete(server.portForwards, connectionID)
		server.mu.Unlock()
	}

	DebugLog("[PORT-FWD] Response routed conn=%s success=%t from=%s to=%s",
		connectionID, payload.Success, ep.EndpointName, peer.EndpointName)
}

// handlePortForwardDataRoute routes port forward data between endpoints
func (ep *TCPEndpoint) handlePortForwardDataRoute(server *TCPTunnelServer, msg *TunnelMessage) {
	var payload PortForwardDataPayload
	if err := msg.ParseJSON(&payload); err != nil {
		DebugLog("[TCP TUNNEL] Invalid port forward data: %v", err)
		return
	}
	connectionID := strings.TrimSpace(payload.ConnectionID)
	if connectionID == "" {
		return
	}

	var (
		peer *TCPEndpoint
		ok   bool
		rt   portForwardRouteState
	)
	server.mu.Lock()
	rt, ok = server.portForwards[connectionID]
	if ok {
		switch ep.ID {
		case rt.SourceEndpointID:
			peer = server.endpoints[rt.TargetEndpointID]
		case rt.TargetEndpointID:
			peer = server.endpoints[rt.SourceEndpointID]
		default:
			ok = false
		}
		if ok {
			rt.LastActivity = time.Now()
			server.portForwards[connectionID] = rt
		}
	}
	server.mu.Unlock()

	if !ok || peer == nil {
		DebugLog("[PORT-FWD] Data route missing conn=%s from=%s", connectionID, ep.EndpointName)
		return
	}

	if err := peer.SendJSON(MsgTypePortForwardData, payload); err != nil {
		DebugLog("[PORT-FWD] Data route failed conn=%s from=%s to=%s: %v",
			connectionID, ep.EndpointName, peer.EndpointName, err)
	}
}

// handlePortForwardCloseRoute routes port forward close to the other endpoint
func (ep *TCPEndpoint) handlePortForwardCloseRoute(server *TCPTunnelServer, msg *TunnelMessage) {
	var payload PortForwardClosePayload
	if err := msg.ParseJSON(&payload); err != nil {
		DebugLog("[TCP TUNNEL] Invalid port forward close: %v", err)
		return
	}

	DebugLog("[PORT-FWD] Close for connection %s: %s", payload.ConnectionID, payload.Reason)

	connectionID := strings.TrimSpace(payload.ConnectionID)
	var (
		peer *TCPEndpoint
		ok   bool
		rt   portForwardRouteState
	)
	server.mu.Lock()
	rt, ok = server.portForwards[connectionID]
	if ok {
		switch ep.ID {
		case rt.SourceEndpointID:
			peer = server.endpoints[rt.TargetEndpointID]
		case rt.TargetEndpointID:
			peer = server.endpoints[rt.SourceEndpointID]
		default:
			ok = false
		}
		delete(server.portForwards, connectionID)
	}
	server.mu.Unlock()

	if !ok || peer == nil {
		DebugLog("[PORT-FWD] Close route missing conn=%s from=%s", connectionID, ep.EndpointName)
		return
	}

	if err := peer.SendJSON(MsgTypePortForwardClose, payload); err != nil {
		DebugLog("[PORT-FWD] Close route failed conn=%s from=%s to=%s: %v",
			connectionID, ep.EndpointName, peer.EndpointName, err)
	}
}

// initiateKeyRotation initiates a new key rotation by sending a key request
func (ep *TCPEndpoint) initiateKeyRotation() error {
	if ep.KeyManager == nil {
		return nil
	}

	// Avoid rotating keys while requests/proxy streams are active.
	// This keeps control-plane key negotiation away from peak data transfer windows.
	ep.mu.Lock()
	pendingReqs := len(ep.pendingRequests)
	activeProxyConns := len(ep.proxyConns)
	ep.mu.Unlock()
	if pendingReqs > 0 || activeProxyConns > 0 {
		log.Printf("[KEY] Deferring key rotation for endpoint %s (pending_requests=%d, proxy_conns=%d)",
			ep.EndpointName, pendingReqs, activeProxyConns)
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

	if err := ep.Send(&TunnelMessage{Type: MsgTypeKeyRequest, Payload: payload}); err != nil {
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

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		DebugLog("[MIRROR] Failed to marshal mirror payload for %s: %v", ep.EndpointName, err)
		return
	}

	s.mu.RLock()
	configVersion := int64(0)
	if s.config != nil {
		configVersion = s.config.Version
	}
	s.mu.RUnlock()

	protectedPayload, err := WrapControlPlanePayload(ep.KeyManager, MsgTypeMirrorUpdate, payloadBytes, configVersion, ep.ControlOut)
	if err != nil {
		DebugLog("[MIRROR] Failed to protect mirror update for %s: %v", ep.EndpointName, err)
		return
	}

	if err := ep.Conn.WriteMessage(&TunnelMessage{Type: MsgTypeMirrorUpdate, Payload: protectedPayload}); err != nil {
		DebugLog("[MIRROR] Failed to send mirror update to %s: %v", ep.EndpointName, err)
		return
	}

	DebugLog("[MIRROR] Sent %d mirror(s) from group '%s' to endpoint %s",
		len(mirrorList), endpointConfig.Mirror, ep.EndpointName)
}
