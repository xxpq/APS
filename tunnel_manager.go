package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	pb "aps/tunnelpb"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TunnelManager manages all active tunnel connections from endpoints
type TunnelManager struct {
	mu               sync.RWMutex
	tunnels          map[string]*Tunnel            // tunnelName -> Tunnel
	pendingIndex     map[string]*pendingIndexEntry // requestID -> entry for O(1) lookup
	proxyConnections map[string]*proxyConnection   // connectionID -> proxyConnection for TCP proxy
	config           *Config
	statsCollector   *StatsCollector // 统一的统计收集器
}

// pendingIndexEntry 用于快速定位请求对应的stream和pending信息
type pendingIndexEntry struct {
	stream   *EndpointStream
	pending  *pendingRequest
	password string
}

// proxyConnection represents an active TCP proxy connection through the tunnel
type proxyConnection struct {
	connID     string
	conn       net.Conn        // The client-side connection (browser -> APS)
	stream     *EndpointStream // The gRPC stream to endpoint
	connectAck chan error      // Channel to signal connection result
	closed     bool
	mu         sync.Mutex
}

// Tunnel represents a named tunnel with multiple endpoint connections
type Tunnel struct {
	mu       sync.RWMutex
	name     string
	streams  map[string]*StreamPool // endpointName -> StreamPool
	password string
}

// StreamPool manages a pool of gRPC streams for a single endpoint name
type StreamPool struct {
	mu        sync.RWMutex
	streams   map[string]*EndpointStream // streamId -> EndpointStream
	nextIndex int                        // For round-robin
	name      string
}

// pendingRequest represents a request awaiting a streamed response.
type pendingRequest struct {
	responseChan chan *pb.Response // Channel to receive response parts
	pipeWriter   *io.PipeWriter    // Writer to stream body chunks
}

// EndpointStream represents a single gRPC bidirectional stream from an endpoint client
type EndpointStream struct {
	ID               string
	Stream           pb.TunnelService_EstablishServer
	Mu               sync.Mutex
	PendingRequests  map[string]*pendingRequest
	RemoteAddr       string
	OnlineTime       time.Time
	LastActivityTime time.Time
	Stats            *Metrics
}

func NewTunnelManager(config *Config, statsCollector *StatsCollector) *TunnelManager {
	tm := &TunnelManager{
		tunnels:          make(map[string]*Tunnel),
		pendingIndex:     make(map[string]*pendingIndexEntry),
		proxyConnections: make(map[string]*proxyConnection),
		config:           config,
		statsCollector:   statsCollector,
	}
	if config.Tunnels != nil {
		for name, tConfig := range config.Tunnels {
			tm.tunnels[name] = &Tunnel{
				name:     name,
				streams:  make(map[string]*StreamPool),
				password: tConfig.Password,
			}
		}
	}
	return tm
}

// SetStatsCollector 设置统计收集器（用于延迟初始化）
func (tm *TunnelManager) SetStatsCollector(statsCollector *StatsCollector) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.statsCollector = statsCollector
}

// UpdateTunnels dynamically updates the tunnel list from a new configuration.
func (tm *TunnelManager) UpdateTunnels(newConfig *Config) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	log.Println("[TunnelManager] Updating tunnels based on new configuration...")

	newTunnelsMap := make(map[string]bool)
	if newConfig.Tunnels != nil {
		for name := range newConfig.Tunnels {
			newTunnelsMap[name] = true
		}
	}

	// Remove tunnels that are no longer in the config
	for name := range tm.tunnels {
		if !newTunnelsMap[name] {
			log.Printf("[TunnelManager] Removing tunnel '%s' as it is no longer in the configuration.", name)
			// This will prevent new connections, and existing ones will fail eventually.
			delete(tm.tunnels, name)
		}
	}

	// Add new tunnels and update existing ones
	if newConfig.Tunnels != nil {
		for name, tConfig := range newConfig.Tunnels {
			if existingTunnel, exists := tm.tunnels[name]; !exists {
				// This is a new tunnel
				log.Printf("[TunnelManager] Adding new tunnel: %s", name)
				tm.tunnels[name] = &Tunnel{
					name:     name,
					streams:  make(map[string]*StreamPool),
					password: tConfig.Password,
				}
			} else {
				// Tunnel already exists, just update the password if it has changed
				if existingTunnel.password != tConfig.Password {
					log.Printf("[TunnelManager] Updating password for tunnel: %s", name)
					existingTunnel.password = tConfig.Password
				}
			}
		}
	}
	log.Printf("[TunnelManager] Tunnels updated. Total tunnels now: %d", len(tm.tunnels))
}

// RegisterEndpointStream validates a new stream and adds it to the appropriate pool.
func (tm *TunnelManager) RegisterEndpointStream(tunnelName, endpointName, password string, stream pb.TunnelService_EstablishServer, remoteAddr string) (*EndpointStream, error) {
	tm.mu.RLock()
	tunnel, exists := tm.tunnels[tunnelName]
	tm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("tunnel '%s' not found", tunnelName)
	}
	if tunnel.password != "" && tunnel.password != password {
		return nil, errors.New("invalid tunnel password")
	}

	endpointStream := &EndpointStream{
		ID:              generateRequestID(),
		Stream:          stream,
		PendingRequests: make(map[string]*pendingRequest),
		// 设置连接时的基本信息
		RemoteAddr:       remoteAddr, // 使用传入的远程地址
		OnlineTime:       time.Now(),
		LastActivityTime: time.Now(),
		// 初始化统计信息 - 修复初始值设置
		Stats: &Metrics{
			ResponseTime: TimeMetric{Min: -1},   // -1 表示未初始化
			BytesSent:    NumericMetric{Min: 0}, // 正确的初始值
			BytesRecv:    NumericMetric{Min: 0}, // 正确的初始值
		},
	}

	tunnel.mu.Lock()
	pool, exists := tunnel.streams[endpointName]
	if !exists {
		pool = &StreamPool{
			streams: make(map[string]*EndpointStream),
			name:    endpointName,
		}
		tunnel.streams[endpointName] = pool
	}
	pool.AddStream(endpointStream)
	tunnel.mu.Unlock()

	return endpointStream, nil
}

// UnregisterEndpointStream removes a stream from its pool.
func (tm *TunnelManager) UnregisterEndpointStream(tunnelName, endpointName, streamID string) {
	tm.mu.RLock()
	tunnel, exists := tm.tunnels[tunnelName]
	tm.mu.RUnlock()
	if !exists {
		return
	}

	tunnel.mu.Lock()
	defer tunnel.mu.Unlock()
	pool, exists := tunnel.streams[endpointName]
	if !exists {
		return
	}
	pool.RemoveStream(streamID)
	if pool.Size() == 0 {
		delete(tunnel.streams, endpointName)
		log.Printf("[GRPC] Endpoint pool for '%s' is now empty and has been removed.", endpointName)
	}
}

// HandleIncomingMessage processes a message received from an endpoint stream.
// 使用全局索引进行O(1)查找，避免三重嵌套锁遍历
func (tm *TunnelManager) HandleIncomingMessage(msg *pb.EndpointToServer) {
	// Handle response messages (existing logic)
	if resp := msg.GetResponse(); resp != nil {
		tm.handleResponse(resp)
		return
	}

	// Handle proxy connection acknowledgement
	if ack := msg.GetProxyConnectAck(); ack != nil {
		tm.handleProxyConnectAck(ack)
		return
	}

	// Handle proxy data from endpoint
	if data := msg.GetProxyData(); data != nil {
		tm.handleProxyData(data)
		return
	}

	// Handle proxy close from endpoint
	if close := msg.GetProxyClose(); close != nil {
		tm.handleProxyClose(close)
		return
	}
}

// handleResponse handles Response messages (refactored from HandleIncomingMessage)
func (tm *TunnelManager) handleResponse(resp *pb.Response) {
	requestID := resp.GetId()

	// 使用全局索引直接查找 - O(1)复杂度
	tm.mu.RLock()
	entry, ok := tm.pendingIndex[requestID]
	tm.mu.RUnlock()

	if !ok {
		// 请求可能已经被取消或超时清理
		return
	}

	pending := entry.pending
	stream := entry.stream
	password := entry.password

	// 更新活动时间
	stream.Mu.Lock()
	stream.LastActivityTime = time.Now()
	stream.Mu.Unlock()

	switch content := resp.Content.(type) {
	case *pb.Response_Header:
		// This is the first part of a stream, pass it to the waiting channel.
		select {
		case pending.responseChan <- resp:
		default:
			log.Printf("[STREAM %s] Warning: response channel full, header dropped", requestID)
		}
	case *pb.Response_Chunk:
		// This is a body chunk, decrypt and write to the pipe.
		decryptedChunk, err := decrypt(content.Chunk.GetData(), password)
		if err != nil {
			log.Printf("[STREAM %s] Error decrypting chunk: %v", requestID, err)
			pending.pipeWriter.CloseWithError(err)
			return
		}
		if _, err := pending.pipeWriter.Write(decryptedChunk); err != nil {
			log.Printf("[STREAM %s] Error writing to pipe: %v", requestID, err)
			pending.pipeWriter.CloseWithError(err)
			return
		}
	case *pb.Response_End:
		// End of stream.
		if content.End.GetError() != "" {
			err := errors.New(content.End.GetError())
			log.Printf("[STREAM %s] Received stream error from endpoint: %v", requestID, err)
			pending.pipeWriter.CloseWithError(err)
		} else {
			pending.pipeWriter.Close()
		}
		// 清理全局索引
		tm.mu.Lock()
		delete(tm.pendingIndex, requestID)
		tm.mu.Unlock()
		// 清理stream本地映射
		stream.Mu.Lock()
		delete(stream.PendingRequests, requestID)
		stream.Mu.Unlock()
	case *pb.Response_Error:
		// Handle non-streaming error for backward compatibility or immediate errors
		select {
		case pending.responseChan <- resp:
		default:
			log.Printf("[STREAM %s] Warning: response channel full, error dropped", requestID)
		}
		// 清理全局索引
		tm.mu.Lock()
		delete(tm.pendingIndex, requestID)
		tm.mu.Unlock()
		// 清理stream本地映射
		stream.Mu.Lock()
		delete(stream.PendingRequests, requestID)
		stream.Mu.Unlock()
	}
}

// handleProxyConnectAck handles ProxyConnectAck from endpoint
func (tm *TunnelManager) handleProxyConnectAck(ack *pb.ProxyConnectAck) {
	connID := ack.GetConnectionId()

	tm.mu.RLock()
	proxyConn, ok := tm.proxyConnections[connID]
	tm.mu.RUnlock()

	if !ok {
		log.Printf("[PROXY %s] Connection not found for ack", connID)
		return
	}

	if ack.GetSuccess() {
		log.Printf("[PROXY %s] Connection established successfully", connID)
		proxyConn.connectAck <- nil
	} else {
		errMsg := ack.GetError()
		log.Printf("[PROXY %s] Connection failed: %s", connID, errMsg)
		proxyConn.connectAck <- errors.New(errMsg)
	}
}

// handleProxyData handles ProxyData from endpoint
func (tm *TunnelManager) handleProxyData(data *pb.ProxyData) {
	connID := data.GetConnectionId()

	tm.mu.RLock()
	proxyConn, ok := tm.proxyConnections[connID]
	tm.mu.RUnlock()

	if !ok {
		log.Printf("[PROXY %s] Connection not found for data", connID)
		return
	}

	proxyConn.mu.Lock()
	if proxyConn.closed {
		proxyConn.mu.Unlock()
		return
	}
	proxyConn.mu.Unlock()

	// Write data to client connection
	_, err := proxyConn.conn.Write(data.GetData())
	if err != nil {
		log.Printf("[PROXY %s] Write to client error: %v", connID, err)
		tm.closeProxyConnection(connID, "write error")
	}
}

// handleProxyClose handles ProxyClose from endpoint
func (tm *TunnelManager) handleProxyClose(close *pb.ProxyClose) {
	connID := close.GetConnectionId()
	reason := close.GetReason()
	log.Printf("[PROXY %s] Received close from endpoint: %s", connID, reason)
	tm.closeProxyConnection(connID, reason)
}

// closeProxyConnection closes a proxy connection and cleans up
func (tm *TunnelManager) closeProxyConnection(connID string, reason string) {
	tm.mu.Lock()
	proxyConn, ok := tm.proxyConnections[connID]
	if ok {
		delete(tm.proxyConnections, connID)
	}
	tm.mu.Unlock()

	if ok && proxyConn != nil {
		proxyConn.mu.Lock()
		proxyConn.closed = true
		proxyConn.mu.Unlock()

		if proxyConn.conn != nil {
			proxyConn.conn.Close()
		}
	}
}

// FindTunnelForEndpoint searches all tunnels to find the tunnel name for a given endpoint name.
func (tm *TunnelManager) FindTunnelForEndpoint(endpointName string) (string, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	for tunnelName, tunnel := range tm.tunnels {
		tunnel.mu.RLock()
		// Check if the endpoint pool exists in this tunnel
		if pool, exists := tunnel.streams[endpointName]; exists && pool.Size() > 0 {
			tunnel.mu.RUnlock()
			return tunnelName, true
		}
		tunnel.mu.RUnlock()
	}
	return "", false
}

// GetRandomEndpointFromTunnels selects a random tunnel from the provided list,
// then selects a random endpoint from that tunnel.
func (tm *TunnelManager) GetRandomEndpointFromTunnels(tunnelNames []string) (string, string, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	if len(tunnelNames) == 0 {
		return "", "", errors.New("no tunnel names provided")
	}

	// Create a new slice and shuffle it to avoid modifying the original slice
	shuffledTunnels := make([]string, len(tunnelNames))
	copy(shuffledTunnels, tunnelNames)
	rand.Shuffle(len(shuffledTunnels), func(i, j int) {
		shuffledTunnels[i], shuffledTunnels[j] = shuffledTunnels[j], shuffledTunnels[i]
	})

	for _, tunnelName := range shuffledTunnels {
		tunnel, exists := tm.tunnels[tunnelName]
		if !exists {
			continue // Try next tunnel if this one doesn't exist
		}

		tunnel.mu.RLock()
		if len(tunnel.streams) == 0 {
			tunnel.mu.RUnlock()
			continue // No endpoints in this tunnel, try next
		}

		// Collect available endpoint names that have active streams
		endpointNames := make([]string, 0, len(tunnel.streams))
		for name, pool := range tunnel.streams {
			if pool.Size() > 0 {
				endpointNames = append(endpointNames, name)
			}
		}
		tunnel.mu.RUnlock()

		if len(endpointNames) > 0 {
			// Pick a random endpoint
			randomEndpointName := endpointNames[rand.Intn(len(endpointNames))]
			return tunnelName, randomEndpointName, nil
		}
	}

	return "", "", fmt.Errorf("no available endpoints in any of the specified tunnels: %v", tunnelNames)
}

// EndpointInfo holds basic info and a reference to the stats for an endpoint.
// This is an internal structure to pass data out of the manager.
type EndpointInfo struct {
	Name             string
	RemoteAddr       string
	OnlineTime       time.Time
	LastActivityTime time.Time
	Stats            *Metrics
}

// MeasureEndpointLatency sends a lightweight ping request to measure RTT for a specific endpoint.
func (tm *TunnelManager) MeasureEndpointLatency(tunnelName, endpointName string) (time.Duration, error) {
	// This method is now more complex due to streaming. For now, we can return a fixed value
	// or implement a lightweight ping/pong later.
	// Returning a fixed value as a placeholder.
	return 50 * time.Millisecond, nil
}

// GetEndpointsInfo returns a snapshot of basic info and stats for all endpoints in a tunnel.
func (tm *TunnelManager) GetEndpointsInfo(tunnelName string) map[string]*EndpointInfo {
	tm.mu.RLock()
	tunnel, exists := tm.tunnels[tunnelName]
	tm.mu.RUnlock()
	if !exists {
		return nil
	}

	info := make(map[string]*EndpointInfo)

	tunnel.mu.RLock()
	for endpointName, pool := range tunnel.streams {
		pool.mu.RLock()
		for _, stream := range pool.streams {
			stream.Mu.Lock()
			info[endpointName] = &EndpointInfo{
				Name:             endpointName,
				RemoteAddr:       stream.RemoteAddr,
				OnlineTime:       stream.OnlineTime,
				LastActivityTime: stream.LastActivityTime,
				Stats:            stream.Stats,
			}
			stream.Mu.Unlock()
			break // Only show info for one stream per endpoint name for simplicity
		}
		pool.mu.RUnlock()
	}
	tunnel.mu.RUnlock()
	return info
}

// SendRequestStream sends a request and returns an io.ReadCloser for streaming the response.
func (tm *TunnelManager) SendRequestStream(ctx context.Context, tunnelName, endpointName string, reqPayload *RequestPayload) (io.ReadCloser, []byte, error) {
	tm.mu.RLock()
	tunnel, exists := tm.tunnels[tunnelName]
	tm.mu.RUnlock()
	if !exists {
		return nil, nil, status.Errorf(codes.NotFound, "tunnel '%s' not found", tunnelName)
	}

	tunnel.mu.RLock()
	pool, exists := tunnel.streams[endpointName]
	if !exists || pool.Size() == 0 {
		tunnel.mu.RUnlock()
		return nil, nil, status.Errorf(codes.Unavailable, "endpoint '%s' is not connected to tunnel '%s'", endpointName, tunnelName)
	}
	stream := pool.GetStream()
	tunnel.mu.RUnlock()

	if stream == nil {
		return nil, nil, status.Errorf(codes.Unavailable, "no available stream for endpoint '%s'", endpointName)
	}

	requestID := generateRequestID()

	encryptedData, err := encrypt(reqPayload.Data, tunnel.password)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "failed to encrypt request: %v", err)
	}

	req := &pb.ServerToEndpoint{
		Id: requestID,
		Payload: &pb.ServerToEndpoint_Request{
			Request: &pb.Request{
				Url:  reqPayload.URL,
				Data: encryptedData,
			},
		},
	}

	pipeReader, pipeWriter := io.Pipe()
	pending := &pendingRequest{
		responseChan: make(chan *pb.Response, 100), // 增大缓冲区避免通道阻塞
		pipeWriter:   pipeWriter,
	}

	// 注册到全局索引（用于O(1)查找）和stream本地映射
	tm.mu.Lock()
	tm.pendingIndex[requestID] = &pendingIndexEntry{
		stream:   stream,
		pending:  pending,
		password: tunnel.password,
	}
	tm.mu.Unlock()

	stream.Mu.Lock()
	stream.PendingRequests[requestID] = pending
	stream.Mu.Unlock()

	// Goroutine to clean up the pending request if the context is canceled.
	go func() {
		<-ctx.Done()
		// 清理全局索引
		tm.mu.Lock()
		delete(tm.pendingIndex, requestID)
		tm.mu.Unlock()
		// 清理stream本地映射
		stream.Mu.Lock()
		if _, ok := stream.PendingRequests[requestID]; ok {
			pipeWriter.CloseWithError(ctx.Err())
			delete(stream.PendingRequests, requestID)
		}
		stream.Mu.Unlock()
	}()

	if err := stream.Stream.Send(req); err != nil {
		pipeWriter.CloseWithError(err)
		// 清理全局索引
		tm.mu.Lock()
		delete(tm.pendingIndex, requestID)
		tm.mu.Unlock()
		// 清理stream本地映射
		stream.Mu.Lock()
		delete(stream.PendingRequests, requestID)
		stream.Mu.Unlock()
		return nil, nil, status.Errorf(codes.Aborted, "failed to send request to endpoint: %v", err)
	}

	// Wait for the initial response (header or error)
	select {
	case initialResp := <-pending.responseChan:
		if errContent := initialResp.GetError(); errContent != "" {
			return nil, nil, errors.New(errContent)
		}
		header := initialResp.GetHeader()
		if header == nil {
			return nil, nil, errors.New("invalid initial response from endpoint: expected header")
		}
		decryptedHeader, err := decrypt(header.GetHeader(), tunnel.password)
		if err != nil {
			return nil, nil, status.Errorf(codes.Internal, "failed to decrypt response header: %v", err)
		}
		return pipeReader, decryptedHeader, nil
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

// SendProxyConnect establishes a TCP proxy connection through the tunnel.
// The clientConn is the connection from client (browser) to APS.
// Returns when connection is established or fails.
func (tm *TunnelManager) SendProxyConnect(ctx context.Context, tunnelName, endpointName string, host string, port int, useTLS bool, clientConn net.Conn) error {
	tm.mu.RLock()
	tunnel, exists := tm.tunnels[tunnelName]
	tm.mu.RUnlock()
	if !exists {
		return status.Errorf(codes.NotFound, "tunnel '%s' not found", tunnelName)
	}

	tunnel.mu.RLock()
	pool, exists := tunnel.streams[endpointName]
	if !exists || pool.Size() == 0 {
		tunnel.mu.RUnlock()
		return status.Errorf(codes.Unavailable, "endpoint '%s' is not connected to tunnel '%s'", endpointName, tunnelName)
	}
	stream := pool.GetStream()
	tunnel.mu.RUnlock()

	if stream == nil {
		return status.Errorf(codes.Unavailable, "no available stream for endpoint '%s'", endpointName)
	}

	connID := generateRequestID()

	// Create proxy connection entry
	proxyConn := &proxyConnection{
		connID:     connID,
		conn:       clientConn,
		stream:     stream,
		connectAck: make(chan error, 1),
		closed:     false,
	}

	// Register the proxy connection
	tm.mu.Lock()
	tm.proxyConnections[connID] = proxyConn
	tm.mu.Unlock()

	// Send ProxyConnect to endpoint
	connectMsg := &pb.ServerToEndpoint{
		Id: connID,
		Payload: &pb.ServerToEndpoint_ProxyConnect{
			ProxyConnect: &pb.ProxyConnect{
				ConnectionId: connID,
				Host:         host,
				Port:         int32(port),
				Tls:          useTLS,
			},
		},
	}

	stream.Mu.Lock()
	err := stream.Stream.Send(connectMsg)
	stream.Mu.Unlock()

	if err != nil {
		tm.closeProxyConnection(connID, "send error")
		return status.Errorf(codes.Aborted, "failed to send proxy connect: %v", err)
	}

	// Wait for connection acknowledgement
	select {
	case err := <-proxyConn.connectAck:
		if err != nil {
			tm.closeProxyConnection(connID, "connect failed")
			return err
		}
	case <-ctx.Done():
		tm.closeProxyConnection(connID, "context cancelled")
		return ctx.Err()
	case <-time.After(30 * time.Second):
		tm.closeProxyConnection(connID, "connect timeout")
		return errors.New("proxy connect timeout")
	}

	// Connection established, start reading from client and forwarding to endpoint
	go tm.proxyClientReadLoop(connID, stream)

	return nil
}

// proxyClientReadLoop reads data from client connection and sends to endpoint
func (tm *TunnelManager) proxyClientReadLoop(connID string, stream *EndpointStream) {
	tm.mu.RLock()
	proxyConn, ok := tm.proxyConnections[connID]
	tm.mu.RUnlock()

	if !ok {
		return
	}

	defer func() {
		log.Printf("[PROXY %s] Client read loop ended", connID)

		// Send close to endpoint
		stream.Mu.Lock()
		stream.Stream.Send(&pb.ServerToEndpoint{
			Id: connID,
			Payload: &pb.ServerToEndpoint_ProxyClose{
				ProxyClose: &pb.ProxyClose{
					ConnectionId: connID,
					Reason:       "client connection closed",
				},
			},
		})
		stream.Mu.Unlock()

		tm.closeProxyConnection(connID, "client closed")
	}()

	buf := make([]byte, 32*1024) // 32KB buffer
	for {
		proxyConn.mu.Lock()
		closed := proxyConn.closed
		proxyConn.mu.Unlock()
		if closed {
			return
		}

		n, err := proxyConn.conn.Read(buf)
		if n > 0 {
			// Send data to endpoint
			dataMsg := &pb.ServerToEndpoint{
				Id: connID,
				Payload: &pb.ServerToEndpoint_ProxyData{
					ProxyData: &pb.ProxyData{
						ConnectionId: connID,
						Data:         buf[:n],
					},
				},
			}

			stream.Mu.Lock()
			sendErr := stream.Stream.Send(dataMsg)
			stream.Mu.Unlock()

			if sendErr != nil {
				log.Printf("[PROXY %s] Send to endpoint error: %v", connID, sendErr)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[PROXY %s] Client read error: %v", connID, err)
			}
			return
		}
	}
}

// AddStream adds a stream to the pool
func (p *StreamPool) AddStream(stream *EndpointStream) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.streams[stream.ID] = stream
}

// RemoveStream removes a stream from the pool
func (p *StreamPool) RemoveStream(streamID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.streams, streamID)
}

// GetStream selects a stream from the pool using round-robin
func (p *StreamPool) GetStream() *EndpointStream {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.streams) == 0 {
		return nil
	}

	streams := make([]*EndpointStream, 0, len(p.streams))
	for _, s := range p.streams {
		streams = append(streams, s)
	}

	if p.nextIndex >= len(streams) {
		p.nextIndex = 0
	}

	stream := streams[p.nextIndex]
	p.nextIndex++

	return stream
}

// Size returns the number of streams in the pool
func (p *StreamPool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.streams)
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

// RequestPayload is used by http handlers to pass request data to the tunnel manager.
type RequestPayload struct {
	URL  string
	Data []byte
}

// Cleanup 清理隧道管理器资源
func (tm *TunnelManager) Cleanup() {
	log.Println("[TUNNEL] Cleaning up tunnel manager")
	// 这里可以添加清理逻辑，如关闭所有连接等
}

// GetPoolStats 获取连接池统计信息
func (tm *TunnelManager) GetPoolStats() map[string]interface{} {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["type"] = "grpc"
	stats["tunnels"] = len(tm.tunnels)

	tunnelStats := make(map[string]interface{})
	for name, tunnel := range tm.tunnels {
		tunnel.mu.RLock()
		endpointCount := len(tunnel.streams)
		streamCount := 0
		for _, pool := range tunnel.streams {
			streamCount += pool.Size()
		}
		tunnel.mu.RUnlock()

		tunnelStats[name] = map[string]interface{}{
			"endpoints": endpointCount,
			"streams":   streamCount,
		}
	}
	stats["tunnel_details"] = tunnelStats

	return stats
}
