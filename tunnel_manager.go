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
	"sync"
	"time"

	pb "aps/tunnelpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TunnelManager manages all active tunnel connections from endpoints
type TunnelManager struct {
	mu      sync.RWMutex
	tunnels map[string]*Tunnel // tunnelName -> Tunnel
	config  *Config
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

// EndpointStream represents a single gRPC bidirectional stream from an endpoint client
type EndpointStream struct {
	ID              string
	Stream          pb.TunnelService_EstablishServer
	Mu              sync.Mutex
	PendingRequests map[string]chan *pb.Response
	RemoteAddr      string
	OnlineTime      time.Time
	LastActivityTime time.Time
	Stats           *Metrics
}

func NewTunnelManager(config *Config) *TunnelManager {
	tm := &TunnelManager{
		tunnels: make(map[string]*Tunnel),
		config:  config,
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
		PendingRequests: make(map[string]chan *pb.Response),
		// 设置连接时的基本信息
		RemoteAddr:       remoteAddr, // 使用传入的远程地址
		OnlineTime:       time.Now(),
		LastActivityTime: time.Now(),
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
func (tm *TunnelManager) HandleIncomingMessage(msg *pb.EndpointToServer) {
	if resp := msg.GetResponse(); resp != nil {
		// Find the correct stream and pending request channel
		tm.mu.RLock()
		defer tm.mu.RUnlock()
		for _, tunnel := range tm.tunnels {
			tunnel.mu.RLock()
			for _, pool := range tunnel.streams {
				pool.mu.RLock()
				for _, stream := range pool.streams {
					stream.Mu.Lock()
					if ch, ok := stream.PendingRequests[resp.Id]; ok {
						ch <- resp
						delete(stream.PendingRequests, resp.Id)
					}
					// 更新最后活动时间 - 每次消息传输时刷新
					stream.LastActivityTime = time.Now()
					stream.Mu.Unlock()
				}
				pool.mu.RUnlock()
			}
			tunnel.mu.RUnlock()
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
	tm.mu.RLock()
	tunnel, exists := tm.tunnels[tunnelName]
	tm.mu.RUnlock()
	if !exists {
		return 0, fmt.Errorf("tunnel '%s' not found", tunnelName)
	}

	tunnel.mu.RLock()
	pool, exists := tunnel.streams[endpointName]
	if !exists || pool.Size() == 0 {
		tunnel.mu.RUnlock()
		return 0, fmt.Errorf("endpoint '%s' is not connected to tunnel '%s'", endpointName, tunnelName)
	}
	stream := pool.GetStream()
	tunnel.mu.RUnlock()

	if stream == nil {
		return 0, fmt.Errorf("no available stream for endpoint '%s'", endpointName)
	}

	// Use a simple ping payload
	pingPayload := &RequestPayload{
		URL:  "aps://ping",
		Data: []byte("ping"),
	}

	start := time.Now()
	_, err := tm.SendRequest(context.Background(), tunnelName, endpointName, pingPayload)
	if err != nil {
		return 0, err
	}
	return time.Since(start), nil
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

// SendRequest sends a request to an endpoint and waits for a response.
func (tm *TunnelManager) SendRequest(ctx context.Context, tunnelName, endpointName string, reqPayload *RequestPayload) ([]byte, error) {
	tm.mu.RLock()
	tunnel, exists := tm.tunnels[tunnelName]
	tm.mu.RUnlock()
	if !exists {
		return nil, status.Errorf(codes.NotFound, "tunnel '%s' not found", tunnelName)
	}

	tunnel.mu.RLock()
	pool, exists := tunnel.streams[endpointName]
	if !exists || pool.Size() == 0 {
		tunnel.mu.RUnlock()
		return nil, status.Errorf(codes.Unavailable, "endpoint '%s' is not connected to tunnel '%s'", endpointName, tunnelName)
	}
	stream := pool.GetStream()
	tunnel.mu.RUnlock()

	if stream == nil {
		return nil, status.Errorf(codes.Unavailable, "no available stream for endpoint '%s'", endpointName)
	}

	requestID := generateRequestID()

	encryptedData, err := encrypt(reqPayload.Data, tunnel.password)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to encrypt request: %v", err)
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

	respCh := make(chan *pb.Response, 1)
	stream.Mu.Lock()
	stream.PendingRequests[requestID] = respCh
	stream.Mu.Unlock()

	defer func() {
		stream.Mu.Lock()
		delete(stream.PendingRequests, requestID)
		stream.Mu.Unlock()
	}()

	if err := stream.Stream.Send(req); err != nil {
		return nil, status.Errorf(codes.Aborted, "failed to send request to endpoint: %v", err)
	}

	select {
	case resp := <-respCh:
		if resp.GetError() != "" {
			return nil, errors.New(resp.GetError())
		}
		decryptedData, err := decrypt(resp.GetData(), tunnel.password)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to decrypt response: %v", err)
		}
		return decryptedData, nil
	case <-ctx.Done():
		// Notify endpoint of cancellation
		cancelMsg := &pb.ServerToEndpoint{
			Id:      requestID,
			Payload: &pb.ServerToEndpoint_Cancel{Cancel: &pb.Cancel{}},
		}
		_ = stream.Stream.Send(cancelMsg) // Best effort send
		return nil, ctx.Err()
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