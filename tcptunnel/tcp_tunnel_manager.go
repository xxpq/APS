package tcptunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"aps/security"
	"aps/stats"
	"aps/util"
)

// pendingRequestPool removed to prevent reusing closed channels

// TCPTunnelManager manages TCP tunnel endpoints and provides proxy functionality
type TCPTunnelManager struct {
	mu      sync.RWMutex
	server  *TCPTunnelServer
	tunnels map[string]*tcpTunnel // tunnelName -> tunnel
	config  *Config
}

// tcpTunnel represents a tunnel with connected endpoints
type tcpTunnel struct {
	name      string
	endpoints map[string][]*TCPEndpoint // endpointName -> endpoints (multiple for load balancing)
	mu        sync.RWMutex
}

const (
	defaultHTTPStreamChunkSize = 256 * 1024
	minHTTPStreamChunkSize     = 16 * 1024
	maxHTTPStreamChunkSize     = 4 * 1024 * 1024
	httpChunkSizeEnv           = "APS_TUNNEL_HTTP_CHUNK_KB"
)

var httpStreamChunkSize = loadHTTPStreamChunkSize()

func loadHTTPStreamChunkSize() int {
	raw := os.Getenv(httpChunkSizeEnv)
	if raw == "" {
		return defaultHTTPStreamChunkSize
	}
	kb, err := strconv.Atoi(raw)
	if err != nil || kb <= 0 {
		return defaultHTTPStreamChunkSize
	}
	size := kb * 1024
	if size < minHTTPStreamChunkSize {
		size = minHTTPStreamChunkSize
	}
	if size > maxHTTPStreamChunkSize {
		size = maxHTTPStreamChunkSize
	}
	return size
}

// NewTCPTunnelManager creates a new TCP tunnel manager
func NewTCPTunnelManager(config *Config, server *TCPTunnelServer) *TCPTunnelManager {
	tm := &TCPTunnelManager{
		server:  server,
		tunnels: make(map[string]*tcpTunnel),
		config:  config,
	}

	// Initialize tunnels from config
	for tunnelName := range config.Tunnels {
		tm.tunnels[tunnelName] = &tcpTunnel{
			name:      tunnelName,
			endpoints: make(map[string][]*TCPEndpoint),
		}
	}

	// Link server to manager
	if server != nil {
		server.SetTunnelManager(tm)
	}

	return tm
}

// RegisterEndpoint registers an endpoint with the tunnel manager
func (tm *TCPTunnelManager) RegisterEndpoint(ep *TCPEndpoint) {
	tm.mu.Lock()
	tunnel, exists := tm.tunnels[ep.TunnelName]
	if !exists {
		tunnel = &tcpTunnel{
			name:      ep.TunnelName,
			endpoints: make(map[string][]*TCPEndpoint),
		}
		tm.tunnels[ep.TunnelName] = tunnel
	}
	tm.mu.Unlock()

	tunnel.mu.Lock()
	existing := len(tunnel.endpoints[ep.EndpointName])
	if existing > 0 {
		log.Printf("[TCP TUNNEL] Duplicate endpoint name detected: tunnel='%s' endpoint='%s' existing=%d new_id=%s remote=%s",
			ep.TunnelName, ep.EndpointName, existing, ep.ID, ep.RemoteAddr)
	}
	tunnel.endpoints[ep.EndpointName] = append(tunnel.endpoints[ep.EndpointName], ep)
	tunnel.mu.Unlock()
}

// UnregisterEndpoint removes an endpoint from the tunnel manager
func (tm *TCPTunnelManager) UnregisterEndpoint(ep *TCPEndpoint) {
	tm.mu.RLock()
	tunnel, exists := tm.tunnels[ep.TunnelName]
	tm.mu.RUnlock()

	if !exists {
		return
	}

	tunnel.mu.Lock()
	endpoints := tunnel.endpoints[ep.EndpointName]
	for i, e := range endpoints {
		if e.ID == ep.ID {
			tunnel.endpoints[ep.EndpointName] = append(endpoints[:i], endpoints[i+1:]...)
			break
		}
	}
	if len(tunnel.endpoints[ep.EndpointName]) == 0 {
		delete(tunnel.endpoints, ep.EndpointName)
	}
	tunnel.mu.Unlock()
}

// GetEndpoint returns a scored endpoint for the given tunnel/endpoint name.
// Strategy: least-connections candidate set + weighted-random by EWMA latency/health.
func (tm *TCPTunnelManager) GetEndpoint(tunnelName, endpointName string) (*TCPEndpoint, error) {
	tm.mu.RLock()
	tunnel, exists := tm.tunnels[tunnelName]
	tm.mu.RUnlock()

	if !exists {
		return nil, errors.New("tunnel not found")
	}

	tunnel.mu.RLock()
	endpoints := append([]*TCPEndpoint(nil), tunnel.endpoints[endpointName]...)
	tunnel.mu.RUnlock()

	if len(endpoints) == 0 {
		return nil, errors.New("no endpoints available")
	}

	selected := tm.selectEndpoint(endpoints)
	if selected == nil {
		return nil, errors.New("no endpoints available")
	}
	return selected, nil
}

// GetRandomEndpointFromTunnels returns one selected endpoint from candidate tunnels.
func (tm *TCPTunnelManager) GetRandomEndpointFromTunnels(tunnelNames []string) (string, string, error) {
	var candidates []*TCPEndpoint

	for _, tunnelName := range tunnelNames {
		tm.mu.RLock()
		tunnel, exists := tm.tunnels[tunnelName]
		tm.mu.RUnlock()
		if !exists {
			continue
		}

		tunnel.mu.RLock()
		for _, endpoints := range tunnel.endpoints {
			candidates = append(candidates, endpoints...)
		}
		tunnel.mu.RUnlock()
	}

	selected := tm.selectEndpoint(candidates)
	if selected == nil {
		return "", "", errors.New("no available endpoints in any tunnel")
	}
	return selected.TunnelName, selected.EndpointName, nil
}

type endpointCandidate struct {
	ep      *TCPEndpoint
	active  int64
	latency time.Duration
	health  float64
	score   float64
}

func (tm *TCPTunnelManager) selectEndpoint(endpoints []*TCPEndpoint) *TCPEndpoint {
	if len(endpoints) == 0 {
		return nil
	}

	candidates := make([]endpointCandidate, 0, len(endpoints))
	minActive := int64(^uint64(0) >> 1)

	for _, ep := range endpoints {
		if ep == nil || !ep.IsOnline() {
			continue
		}
		active, latency, health := ep.GetSchedulingSnapshot()
		if latency <= 0 {
			latency = 80 * time.Millisecond
		}
		if health <= 0 {
			health = 0.1
		}
		if active < minActive {
			minActive = active
		}

		latMs := float64(latency.Milliseconds())
		if latMs < 1 {
			latMs = 1
		}
		latWeight := 1.0 / (1.0 + latMs/25.0)
		loadWeight := 1.0 / (1.0 + float64(active))
		score := health * (0.65*latWeight + 0.35*loadWeight)
		if score <= 0 {
			score = 0.01
		}

		candidates = append(candidates, endpointCandidate{
			ep:      ep,
			active:  active,
			latency: latency,
			health:  health,
			score:   score,
		})
	}

	if len(candidates) == 0 {
		return nil
	}

	// Least-connections set (allow +1 for tie smoothing), then weighted random.
	leastLoaded := make([]endpointCandidate, 0, len(candidates))
	for _, c := range candidates {
		if c.active <= minActive+1 {
			leastLoaded = append(leastLoaded, c)
		}
	}
	if len(leastLoaded) == 0 {
		leastLoaded = candidates
	}

	total := 0.0
	for _, c := range leastLoaded {
		total += c.score
	}
	if total <= 0 {
		return leastLoaded[rand.Intn(len(leastLoaded))].ep
	}

	target := rand.Float64() * total
	acc := 0.0
	for _, c := range leastLoaded {
		acc += c.score
		if target <= acc {
			return c.ep
		}
	}
	return leastLoaded[len(leastLoaded)-1].ep
}

func (tm *TCPTunnelManager) MeasureEndpointLatency(tunnelName, endpointName string) (time.Duration, error) {
	ep, err := tm.GetEndpoint(tunnelName, endpointName)
	if err != nil {
		return 0, err
	}
	_, latency, _ := ep.GetSchedulingSnapshot()
	if latency <= 0 {
		return 0, errors.New("latency data not ready")
	}
	return latency, nil
}

// FindTunnelForEndpoint finds the tunnel containing the given endpoint
func (tm *TCPTunnelManager) FindTunnelForEndpoint(endpointName string) (string, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	for tunnelName, tunnel := range tm.tunnels {
		tunnel.mu.RLock()
		_, exists := tunnel.endpoints[endpointName]
		tunnel.mu.RUnlock()
		if exists {
			return tunnelName, true
		}
	}

	return "", false
}

// SendProxyConnect establishes a TCP proxy connection through the tunnel
func (tm *TCPTunnelManager) SendProxyConnect(ctx context.Context, tunnelName, endpointName string, host string, port int, useTLS bool, clientConn interface{}, clientIP string) (<-chan struct{}, error) {
	ep, err := tm.GetEndpoint(tunnelName, endpointName)
	if err != nil {
		return nil, err
	}

	// Try to cast to net.Conn
	if nc, ok := clientConn.(interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		Close() error
	}); ok {
		return ep.CreateProxyConnection(ctx, host, port, useTLS, &simpleNetConn{nc}, clientIP)
	}

	return nil, errors.New("invalid client connection type")
}

// simpleNetConn wraps a minimal connection interface to implement net.Conn
type simpleNetConn struct {
	conn interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		Close() error
	}
}

func (s *simpleNetConn) Read(b []byte) (int, error)         { return s.conn.Read(b) }
func (s *simpleNetConn) Write(b []byte) (int, error)        { return s.conn.Write(b) }
func (s *simpleNetConn) Close() error                       { return s.conn.Close() }
func (s *simpleNetConn) LocalAddr() net.Addr                { return nil }
func (s *simpleNetConn) RemoteAddr() net.Addr               { return nil }
func (s *simpleNetConn) SetDeadline(t time.Time) error      { return nil }
func (s *simpleNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (s *simpleNetConn) SetWriteDeadline(t time.Time) error { return nil }

// SendRequestStream sends an HTTP request via the tunnel and returns a streaming response
func (tm *TCPTunnelManager) SendRequestStream(ctx context.Context, tunnelName, endpointName string, reqPayload *RequestPayload) (io.ReadCloser, []byte, error) {
	ep, err := tm.GetEndpoint(tunnelName, endpointName)
	if err != nil {
		return nil, nil, err
	}

	if reqPayload == nil {
		return nil, nil, errors.New("request payload is nil")
	}

	sourceIP := normalizeTCPTunnelLogValue(reqPayload.SourceIP)
	targetAddr := extractTCPTunnelTargetAddr(reqPayload.URL)
	logPrefix := buildTCPTunnelRoutePrefix(sourceIP, ep.EndpointName, ep.ID, targetAddr)

	if len(reqPayload.HeaderData) == 0 && len(reqPayload.Data) > 0 {
		reqPayload.HeaderData = append([]byte(nil), reqPayload.Data...)
	}

	requestID := generateRequestID()

	// Create pipe for streaming response
	pipeReader, pipeWriter := io.Pipe()

	// Register pending request
	pending := &tcpPendingRequest{
		responseChan: make(chan *TunnelMessage, 512),
		pipeWriter:   pipeWriter,
		sourceIP:     sourceIP,
		targetAddr:   targetAddr,
	}

	cleanupPending := func() {
		ep.mu.Lock()
		delete(ep.pendingRequests, requestID)
		ep.mu.Unlock()
	}

	ep.mu.Lock()
	ep.pendingRequests[requestID] = pending
	ep.mu.Unlock()

	ep.MarkRequestStart()
	requestStartedAt := time.Now()
	var doneFlag int32
	reportRequestDone := func(doneErr error) {
		if atomic.CompareAndSwapInt32(&doneFlag, 0, 1) {
			ep.MarkRequestDone(time.Since(requestStartedAt), doneErr)
		}
	}
	fail := func(sendErr error) (io.ReadCloser, []byte, error) {
		cleanupPending()
		pipeWriter.CloseWithError(sendErr)
		reportRequestDone(sendErr)
		return nil, nil, sendErr
	}

	if len(reqPayload.HeaderData) == 0 {
		return fail(errors.New("missing request header bytes"))
	}
	encryptedHeader, err := ep.KeyManager.Encrypt(reqPayload.HeaderData)
	if err != nil {
		return fail(err)
	}

	if err := ep.SendJSON(MsgTypeRequestStart, RequestStartPayloadTCP{
		ID:     requestID,
		URL:    reqPayload.URL,
		Header: encryptedHeader,
	}); err != nil {
		return fail(err)
	}

	if reqPayload.Body != nil {
		defer reqPayload.Body.Close()
		buf := make([]byte, httpStreamChunkSize)
		for {
			select {
			case <-ctx.Done():
				_ = ep.SendJSON(MsgTypeRequestEnd, RequestEndPayloadTCP{
					ID:    requestID,
					Error: ctx.Err().Error(),
				})
				return fail(ctx.Err())
			default:
			}

			n, readErr := reqPayload.Body.Read(buf)
			if n > 0 {
				encryptedChunk, encErr := ep.KeyManager.Encrypt(buf[:n])
				if encErr != nil {
					_ = ep.SendJSON(MsgTypeRequestEnd, RequestEndPayloadTCP{
						ID:    requestID,
						Error: "encrypt request chunk failed",
					})
					return fail(encErr)
				}

				payload, payloadErr := BuildScopedBinaryPayload(requestID, encryptedChunk)
				if payloadErr != nil {
					_ = ep.SendJSON(MsgTypeRequestEnd, RequestEndPayloadTCP{
						ID:    requestID,
						Error: payloadErr.Error(),
					})
					return fail(payloadErr)
				}

				if err := ep.Send(&TunnelMessage{
					Type:    MsgTypeRequestChunkBin,
					Payload: payload,
				}); err != nil {
					_ = ep.SendJSON(MsgTypeRequestEnd, RequestEndPayloadTCP{
						ID:    requestID,
						Error: err.Error(),
					})
					return fail(err)
				}
			}

			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				_ = ep.SendJSON(MsgTypeRequestEnd, RequestEndPayloadTCP{
					ID:    requestID,
					Error: readErr.Error(),
				})
				return fail(readErr)
			}
		}
	}

	if err := ep.SendJSON(MsgTypeRequestEnd, RequestEndPayloadTCP{ID: requestID}); err != nil {
		return fail(err)
	}

	// Wait for response header
	util.DebugLog("%s [TCP TUNNEL] Waiting for response header for request %s", logPrefix, requestID)
	var headerBytes []byte
	select {
	case msg, ok := <-pending.responseChan:
		if !ok || msg == nil {
			err := errors.New("endpoint disconnected while waiting for response header")
			util.DebugLog("%s [TCP TUNNEL] %v for request %s", logPrefix, err, requestID)
			return fail(err)
		}
		util.DebugLog("%s [TCP TUNNEL] Received message type %d for request %s", logPrefix, msg.Type, requestID)
		if msg.Type == MsgTypeResponseHeader {
			var header ResponseHeaderPayloadTCP
			if err := msg.ParseJSON(&header); err != nil {
				util.DebugLog("%s [TCP TUNNEL] Failed to parse response header for %s: %v", logPrefix, requestID, err)
				return fail(err)
			}
			headerBytes, err = ep.KeyManager.Decrypt(header.Header)
			if err != nil {
				util.DebugLog("%s [TCP TUNNEL] Failed to decrypt response header for %s: %v", logPrefix, requestID, err)
				return fail(err)
			}
			util.DebugLog("%s [TCP TUNNEL] Successfully received and decrypted response header for %s (%d bytes)", logPrefix, requestID, len(headerBytes))
		} else if msg.Type == MsgTypeResponseEnd {
			var end ResponseEndPayloadTCP
			if err := msg.ParseJSON(&end); err != nil {
				util.DebugLog("%s [TCP TUNNEL] Failed to parse response end for %s: %v", logPrefix, requestID, err)
				return fail(err)
			}
			errMsg := "request failed at endpoint"
			if end.Error != "" {
				errMsg = end.Error
			}
			util.DebugLog("%s [TCP TUNNEL] Received response end for %s immediately: %s", logPrefix, requestID, errMsg)
			return fail(errors.New(errMsg))
		} else {
			util.DebugLog("%s [TCP TUNNEL] Unexpected response type %d for %s", logPrefix, msg.Type, requestID)
			return fail(errors.New("unexpected response type"))
		}
	case <-ctx.Done():
		util.DebugLog("%s [TCP TUNNEL] Context cancelled while waiting for response header for %s", logPrefix, requestID)
		return fail(ctx.Err())
	}

	// Start goroutine to handle response chunks
	util.DebugLog("%s [TCP TUNNEL] Starting response streaming goroutine for %s", logPrefix, requestID)
	go func() {
		var streamErr error
		defer func() {
			util.DebugLog("%s [TCP TUNNEL] Response streaming goroutine finished for %s", logPrefix, requestID)
			// Clean up pending request after goroutine completes
			ep.mu.Lock()
			delete(ep.pendingRequests, requestID)
			ep.mu.Unlock()
			if streamErr != nil {
				pipeWriter.CloseWithError(streamErr)
			} else {
				pipeWriter.Close()
			}
			reportRequestDone(streamErr)
		}()
		for msg := range pending.responseChan {
			if msg == nil {
				streamErr = errors.New("endpoint disconnected")
				return
			}
			debugLogTCPTunnelThrottled(
				pending.sourceIP,
				ep.EndpointName,
				ep.ID,
				pending.targetAddr,
				tcpTunnelEventKey("received_chunk_type", msg.Type),
				"%s [TCP TUNNEL] Received chunk message type %d for %s",
				logPrefix,
				msg.Type,
				requestID,
			)
			switch msg.Type {
			case MsgTypeResponseChunkBin:
				scopeID, encryptedChunk, err := ParseScopedBinaryPayload(msg.Payload)
				if err != nil {
					streamErr = err
					return
				}
				if scopeID != requestID {
					continue
				}
				decryptedChunk, err := ep.KeyManager.Decrypt(encryptedChunk)
				if err != nil {
					streamErr = err
					return
				}
				if err := writeAllToPipe(pipeWriter, decryptedChunk); err != nil {
					streamErr = err
					return
				}
			case MsgTypeResponseEnd:
				var end ResponseEndPayloadTCP
				if err := msg.ParseJSON(&end); err != nil {
					streamErr = err
					return
				}
				if end.Error != "" {
					streamErr = errors.New(end.Error)
				}
				return
			default:
				streamErr = fmt.Errorf("unsupported response stream message type=%d", msg.Type)
				return
			}
		}
		util.DebugLog("%s [TCP TUNNEL] Response channel closed for %s", logPrefix, requestID)
		streamErr = errors.New("response channel closed unexpectedly")
	}()

	return pipeReader, headerBytes, nil
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

// GetEndpointsInfo returns information about endpoints in a tunnel
func (tm *TCPTunnelManager) GetEndpointsInfo(tunnelName string, statsCol *stats.StatsCollector) map[string]*EndpointInfo {
	tm.mu.RLock()
	tunnel, exists := tm.tunnels[tunnelName]
	tm.mu.RUnlock()

	if !exists {
		return nil
	}

	info := make(map[string]*EndpointInfo)
	tunnel.mu.RLock()
	for endpointName, endpoints := range tunnel.endpoints {
		if len(endpoints) > 0 {
			ep := endpoints[0]

			// Get per-endpoint statistics from stats.StatsCollector
			var endpointStats *stats.PublicMetrics
			if statsCol != nil {
				endpointKey := tunnelName + ":" + endpointName
				endpointStats = statsCol.GetMetricsForKey(&statsCol.EndpointStats, endpointKey)
			}

			info[endpointName] = &EndpointInfo{
				Name:             ep.EndpointName,
				RemoteAddr:       ep.RemoteAddr,
				OnlineTime:       ep.OnlineTime,
				LastActivityTime: ep.LastActivityTime,
				Stats:            endpointStats,
			}
		}
	}
	tunnel.mu.RUnlock()

	return info
}

// Stop stops the tunnel manager
func (tm *TCPTunnelManager) Stop() {
	if tm.server != nil {
		tm.server.Stop()
	}
}

// SendConfigUpdate sends a config update message to a connected endpoint
func (tm *TCPTunnelManager) SendConfigUpdate(tunnelName, endpointName string, payload []byte) error {
	ep, err := tm.GetEndpoint(tunnelName, endpointName)
	if err != nil {
		return err
	}

	tm.mu.RLock()
	configVersion := int64(0)
	if tm.config != nil {
		configVersion = tm.config.Version
	}
	tm.mu.RUnlock()

	protectedPayload, err := security.WrapControlPlanePayload(ep.KeyManager, MsgTypeConfigUpdate, payload, configVersion, ep.ControlOut)
	if err != nil {
		return err
	}

	msg := &TunnelMessage{
		Type:    MsgTypeConfigUpdate,
		Payload: protectedPayload,
	}
	return ep.Conn.WriteMessage(msg)
}

// GetAllOnlineEndpoints returns a list of all online endpoints
func (tm *TCPTunnelManager) GetAllOnlineEndpoints() []EndpointInfo {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var onlineEndpoints []EndpointInfo
	for _, tunnel := range tm.tunnels {
		tunnel.mu.RLock()
		for _, endpoints := range tunnel.endpoints {
			for _, ep := range endpoints {
				if ep.IsOnline() {
					// Construct EndpointInfo
					info := EndpointInfo{
						ID:               ep.ID,
						Name:             ep.EndpointName,
						TunnelName:       tunnel.name,
						RemoteAddr:       ep.RemoteAddr,
						OnlineTime:       ep.OnlineTime,
						LastActivityTime: ep.LastActivityTime,
						// Latency:     ep.Latency, // Latency not available in TCPEndpoint
						Stats: ep.Stats,
					}
					onlineEndpoints = append(onlineEndpoints, info)
				}
			}
		}
		tunnel.mu.RUnlock()
	}
	return onlineEndpoints
}
