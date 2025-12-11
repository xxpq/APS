package main

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
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

// GetEndpoint returns a random endpoint for the given tunnel/endpoint name
func (tm *TCPTunnelManager) GetEndpoint(tunnelName, endpointName string) (*TCPEndpoint, error) {
	tm.mu.RLock()
	tunnel, exists := tm.tunnels[tunnelName]
	tm.mu.RUnlock()

	if !exists {
		return nil, errors.New("tunnel not found")
	}

	tunnel.mu.RLock()
	endpoints := tunnel.endpoints[endpointName]
	tunnel.mu.RUnlock()

	if len(endpoints) == 0 {
		return nil, errors.New("no endpoints available")
	}

	// Simple round-robin / random selection (for now just return first)
	return endpoints[0], nil
}

// GetRandomEndpointFromTunnels returns a random endpoint from the given tunnels
func (tm *TCPTunnelManager) GetRandomEndpointFromTunnels(tunnelNames []string) (string, string, error) {
	for _, tunnelName := range tunnelNames {
		tm.mu.RLock()
		tunnel, exists := tm.tunnels[tunnelName]
		tm.mu.RUnlock()

		if !exists {
			continue
		}

		tunnel.mu.RLock()
		for endpointName, endpoints := range tunnel.endpoints {
			if len(endpoints) > 0 {
				tunnel.mu.RUnlock()
				return tunnelName, endpointName, nil
			}
		}
		tunnel.mu.RUnlock()
	}

	return "", "", errors.New("no available endpoints in any tunnel")
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

	requestID := generateRequestID()

	// Create pipe for streaming response
	pipeReader, pipeWriter := io.Pipe()

	// Register pending request
	pending := &tcpPendingRequest{
		responseChan: make(chan *TunnelMessage, 100), // Increased from 10 to 100
		pipeWriter:   pipeWriter,
	}

	ep.mu.Lock()
	ep.pendingRequests[requestID] = pending
	ep.mu.Unlock()

	// Encrypt request data
	encryptedData, err := encrypt(reqPayload.Data, tm.config.Tunnels[tunnelName].Password)
	if err != nil {
		pipeWriter.Close()
		return nil, nil, err
	}

	// Send request to endpoint
	if err := ep.SendJSON(MsgTypeRequest, RequestPayloadTCP{
		ID:   requestID,
		URL:  reqPayload.URL,
		Data: encryptedData,
	}); err != nil {
		pipeWriter.Close()
		return nil, nil, err
	}

	// Wait for response header
	DebugLog("[TCP TUNNEL] Waiting for response header for request %s", requestID)
	var headerBytes []byte
	select {
	case msg := <-pending.responseChan:
		DebugLog("[TCP TUNNEL] Received message type %d for request %s", msg.Type, requestID)
		if msg.Type == MsgTypeResponseHeader {
			var header ResponseHeaderPayloadTCP
			if err := msg.ParseJSON(&header); err != nil {
				DebugLog("[TCP TUNNEL] Failed to parse response header for %s: %v", requestID, err)
				pipeWriter.CloseWithError(err)
				return nil, nil, err
			}
			headerBytes, err = decrypt(header.Header, tm.config.Tunnels[tunnelName].Password)
			if err != nil {
				DebugLog("[TCP TUNNEL] Failed to decrypt response header for %s: %v", requestID, err)
				pipeWriter.CloseWithError(err)
				return nil, nil, err
			}
			DebugLog("[TCP TUNNEL] Successfully received and decrypted response header for %s (%d bytes)", requestID, len(headerBytes))
		} else {
			DebugLog("[TCP TUNNEL] Unexpected response type %d for %s", msg.Type, requestID)
			pipeWriter.CloseWithError(errors.New("unexpected response type"))
			return nil, nil, errors.New("unexpected response type")
		}
	case <-ctx.Done():
		DebugLog("[TCP TUNNEL] Context cancelled while waiting for response header for %s", requestID)
		pipeWriter.CloseWithError(ctx.Err())
		return nil, nil, ctx.Err()
	}

	// Start goroutine to handle response chunks
	DebugLog("[TCP TUNNEL] Starting response streaming goroutine for %s", requestID)
	go func() {
		defer func() {
			DebugLog("[TCP TUNNEL] Response streaming goroutine finished for %s", requestID)
			// Clean up pending request after goroutine completes
			ep.mu.Lock()
			delete(ep.pendingRequests, requestID)
			ep.mu.Unlock()
			pipeWriter.Close()

		}()
		for {
			select {
			case msg, ok := <-pending.responseChan:
				if !ok {
					DebugLog("[TCP TUNNEL] Response channel closed for %s", requestID)
					return
				}
				DebugLog("[TCP TUNNEL] Received chunk message type %d for %s", msg.Type, requestID)
				switch msg.Type {
				case MsgTypeResponseChunk:
					var chunk ResponseChunkPayloadTCP
					if err := msg.ParseJSON(&chunk); err != nil {
						pipeWriter.CloseWithError(err)
						return
					}
					decryptedChunk, err := decrypt(chunk.Data, tm.config.Tunnels[tunnelName].Password)
					if err != nil {
						pipeWriter.CloseWithError(err)
						return
					}
					// Write with retry for transient failures
					written := 0
					for written < len(decryptedChunk) {
						n, err := pipeWriter.Write(decryptedChunk[written:])
						written += n
						if err != nil {
							return
						}
					}
				case MsgTypeResponseEnd:
					var end ResponseEndPayloadTCP
					if err := msg.ParseJSON(&end); err != nil {
						pipeWriter.CloseWithError(err)
						return
					}
					if end.Error != "" {
						pipeWriter.CloseWithError(errors.New(end.Error))
					}
					return
				}
			}
		}
	}()

	return pipeReader, headerBytes, nil
}

// GetEndpointsInfo returns information about endpoints in a tunnel
func (tm *TCPTunnelManager) GetEndpointsInfo(tunnelName string) map[string]*EndpointInfo {
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
			info[endpointName] = &EndpointInfo{
				Name:             ep.EndpointName,
				RemoteAddr:       ep.RemoteAddr,
				OnlineTime:       ep.OnlineTime,
				LastActivityTime: ep.LastActivityTime,
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
