package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// handleWebSocket handles WebSocket upgrade requests and proxies the connection.
func (p *MapRemoteProxy) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	p.stats.IncTotalRequests()
	p.stats.IncActiveConnections()
	defer p.stats.DecActiveConnections()

	var (
		bytesSent uint64
		bytesRecv uint64
		isError   bool
		ruleKey   string
		userKey   string
		tunnelKey string
		proxyKey  string
	)

	originalURL := p.buildOriginalURL(r)

	// Calculate log prefix with IP and location
	clientIP := r.RemoteAddr
	host, _, err := net.SplitHostPort(clientIP)
	if err != nil {
		host = clientIP
	}
	locationTag := formatLocationTagHTTP(clientIP)
	logPrefix := fmt.Sprintf("[%s]%s", host, locationTag)

	// log.Printf("%s[WS] Starting WebSocket request for %s", logPrefix, originalURL)

	// Defer the consolidated stats recording
	defer func() {
		responseTime := time.Since(startTime)
		p.stats.AddBytesSent(bytesSent)
		p.stats.AddBytesRecv(bytesRecv)
		p.stats.Record(RecordData{
			RuleKey:      ruleKey,
			UserKey:      userKey,
			ServerKey:    p.serverName,
			TunnelKey:    tunnelKey,
			ProxyKey:     proxyKey,
			BytesSent:    bytesSent,
			BytesRecv:    bytesRecv,
			ResponseTime: responseTime,
			IsError:      isError,
			Protocol:     "http", // WebSocket is HTTP upgrade
			StatusCode:   101,    // WebSocket upgrade status code
			ClientIP:     getClientIP(r),
		})
		log.Printf("%s[WS] WebSocket request finished for %s. Duration: %v, Sent: %d, Recv: %d, Error: %v",
			logPrefix, originalURL, responseTime, bytesSent, bytesRecv, isError)
	}()

	// Auth check
	_, user, username := p.checkAuth(r, nil) // Mapping will be checked later
	if user != nil {
		userKey = username
	}

	// Use the existing mapping logic to find the target backend and the specific mapping rule
	targetURL, matched, mapping, matchedFromURL := p.mapRequest(r)
	if !matched {
		isError = true
		log.Printf("%s[WS] No mapping found for %s", logPrefix, originalURL)
		http.Error(w, "No mapping found for WebSocket request", http.StatusBadGateway)
		return
	}
	// Log in the requested format: [IP][Location][WS] Source -> Target (MAPPED)
	log.Printf("%s[WS] %s -> %s (MAPPED)", logPrefix, originalURL, targetURL)

	// Populate keys for stats
	if mapping != nil {
		ruleKey = matchedFromURL
		if len(mapping.tunnelNames) > 0 {
			tunnelKey = mapping.tunnelNames[0]
		}
		if len(mapping.proxyNames) > 0 {
			proxyKey = mapping.proxyNames[0]
		}
	}

	// Change the scheme from http/https to ws/wss
	targetWsURL, err := url.Parse(targetURL)
	if err != nil {
		isError = true
		log.Printf("[WS] Error parsing target URL %s: %v", targetURL, err)
		http.Error(w, "Invalid target URL", http.StatusInternalServerError)
		return
	}
	if targetWsURL.Scheme == "https" {
		targetWsURL.Scheme = "wss"
	} else if targetWsURL.Scheme == "http" {
		targetWsURL.Scheme = "ws"
	}
	DebugLog("%s[WS] Target WebSocket URL: %s", logPrefix, targetWsURL.String())

	// Check if we need to route through tunnel
	var tunnelName, endpointName string
	isTunnelRequest := false

	if mapping != nil && len(mapping.endpointNames) > 0 {
		isTunnelRequest = true
		randomEndpoint := mapping.endpointNames[0] // Just use the first one for now
		if len(mapping.endpointNames) > 1 {
			randomEndpoint = mapping.endpointNames[time.Now().UnixNano()%int64(len(mapping.endpointNames))]
		}

		foundTunnel, ok := p.tunnelManager.FindTunnelForEndpoint(randomEndpoint)
		if !ok {
			isError = true
			log.Printf("[WS] Endpoint '%s' not found in any active tunnel", randomEndpoint)
			http.Error(w, "Endpoint not found", http.StatusBadGateway)
			return
		}
		tunnelName = foundTunnel
		endpointName = randomEndpoint
		tunnelKey = tunnelName
		DebugLog("%s[WS] Will route WebSocket through tunnel '%s' to endpoint '%s'", logPrefix, tunnelName, endpointName)
	} else if mapping != nil && len(mapping.tunnelNames) > 0 {
		isTunnelRequest = true
		foundTunnel, foundEndpoint, err := p.tunnelManager.GetRandomEndpointFromTunnels(mapping.tunnelNames)
		if err != nil {
			isError = true
			log.Printf("%s[WS] %v", logPrefix, err)
			http.Error(w, "Tunnel error", http.StatusBadGateway)
			return
		}

		tunnelName = foundTunnel
		endpointName = foundEndpoint
		tunnelKey = tunnelName
		DebugLog("%s[WS] Will route WebSocket through tunnel '%s' to endpoint '%s'", logPrefix, tunnelName, endpointName)
	}

	var serverConn *websocket.Conn

	if isTunnelRequest {
		// Route WebSocket through tunnel using TCP proxy
		DebugLog("%s[WS] Routing WebSocket to %s through tunnel", logPrefix, targetWsURL.String())

		// Determine host and port
		host := targetWsURL.Hostname()
		portStr := targetWsURL.Port()
		port := 80
		if portStr != "" {
			fmt.Sscanf(portStr, "%d", &port)
		} else if targetWsURL.Scheme == "wss" {
			port = 443
		}

		// Endpoint is a pure TCP proxy (like SOCKS5) - it just forwards raw bytes
		// APS handles all TLS/protocol logic
		// The useTLS field is ignored by endpoint, but we still use correct scheme for logging
		useTLS := targetWsURL.Scheme == "wss"

		// Create a pipe for the proxy connection
		// We need to use net.Pipe() to create an in-memory connection
		clientSide, serverSide := newWebSocketProxyPipe()

		// Wrap clientSide with logging to debug handshake issues
		clientSide = loggingConn{Conn: clientSide, name: "ClientSide"}

		// Start the proxy connection through tunnel
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		// Get client IP for security audit logging
		clientIP := r.RemoteAddr
		DebugLog("%s[WS] Sending ProxyConnect to tunnel %s for %s:%d (TLS=%v)", logPrefix, tunnelName, host, port, useTLS)
		_, err = p.tunnelManager.SendProxyConnect(ctx, tunnelName, endpointName, host, port, useTLS, serverSide, clientIP)
		if err != nil {
			isError = true
			log.Printf("%s[WS] Failed to establish proxy connection through tunnel: %v", logPrefix, err)
			clientSide.Close()
			serverSide.Close()
			http.Error(w, "Failed to establish tunnel connection", http.StatusBadGateway)
			return
		}

		DebugLog("%s[WS] Proxy connection established through tunnel to %s:%d", logPrefix, host, port)

		// Now we need to perform WebSocket handshake over the proxy connection
		// Build the WebSocket handshake request
		wsPath := targetWsURL.Path
		if targetWsURL.RawQuery != "" {
			wsPath += "?" + targetWsURL.RawQuery
		}
		if wsPath == "" {
			wsPath = "/"
		}

		// APS handles TLS - WebSocket dialer does TLS handshake over the raw TCP tunnel
		dialer := websocket.Dialer{
			NetDial: func(network, addr string) (net.Conn, error) {
				return clientSide, nil
			},
			HandshakeTimeout: 15 * time.Second, // Add timeout
		}
		// Only add TLSClientConfig for wss:// connections
		// IMPORTANT: ServerName strategy:
		// - For valid certificates: use original hostname for SNI (browser expects this)
		// - For invalid/self-signed certificates (insecure mode): use target hostname or IP
		//   This avoids SNI mismatch errors with certificates like ESXi's "localhost.localdomain"
		if useTLS {
			// Check if insecure mode is enabled in mapping config
			insecureMode := false
			if mapping != nil {
				toConfig := mapping.GetToConfig()
				if toConfig != nil && toConfig.Insecure != nil && *toConfig.Insecure {
					insecureMode = true
				}
			}

			// Choose appropriate ServerName based on mode
			serverName := ""
			if insecureMode {
				// In insecure mode, use target host (may be IP or hostname from cert)
				// This works better with self-signed certificates
				serverName = host
			} else {
				// In secure mode, use original hostname for proper SNI
				serverName = r.Host
				if colonIdx := strings.Index(serverName, ":"); colonIdx != -1 {
					serverName = serverName[:colonIdx]
				}
			}

			dialer.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: insecureMode,
				ServerName:         serverName,
			}
			DebugLog("%s[WS] TLS config: ServerName=%s, InsecureSkipVerify=%v", logPrefix, serverName, insecureMode)
		}

		// Copy relevant headers from original request
		serverHeader := http.Header{}

		// Headers to forward
		headersToForward := []string{
			"Authorization",
			"Cookie",
			"Origin",
			"Sec-WebSocket-Protocol",
			// "Sec-WebSocket-Extensions", // Handled by Dialer, duplicate not allowed
			"User-Agent",
			"Accept-Language",
			"Accept-Encoding",
			"Cache-Control",
			"Pragma",
		}

		for _, h := range headersToForward {
			if val := r.Header.Get(h); val != "" {
				serverHeader.Set(h, val)
			}
		}

		// If Origin is missing (e.g. non-browser client), construct one or leave empty?
		// Browser always sends Origin. Postman might not?
		// If we don't have Origin, we might want to synthesize it like before,
		// but if we have it, we should definitely use the original one to pass CORS checks if they check against the public domain.
		if serverHeader.Get("Origin") == "" {
			targetOrigin := fmt.Sprintf("%s://%s", targetWsURL.Scheme, targetWsURL.Host)
			if targetWsURL.Scheme == "wss" {
				targetOrigin = fmt.Sprintf("https://%s", targetWsURL.Host)
			} else if targetWsURL.Scheme == "ws" {
				targetOrigin = fmt.Sprintf("http://%s", targetWsURL.Host)
			}
			serverHeader.Set("Origin", targetOrigin)
		}

		// IMPORTANT: Set Host header to original host if available
		// This preserves the SNI/VirtualHost expectation of the backend
		if r.Host != "" {
			serverHeader.Set("Host", r.Host)
		}

		DebugLog("%s[WS] Dialing backend WebSocket: %s", logPrefix, targetWsURL.String())
		for k, v := range serverHeader {
			DebugLog("%s[WS] Header %s: %s", logPrefix, k, v)
		}

		serverConn, _, err = dialer.Dial(targetWsURL.String(), serverHeader)
		if err != nil {
			isError = true
			log.Printf("%s[WS] Failed to complete WebSocket handshake through tunnel: %v", logPrefix, err)
			clientSide.Close()
			http.Error(w, "Failed to connect to backend", http.StatusBadGateway)
			return
		}

		DebugLog("%s[WS] WebSocket handshake with backend successful", logPrefix)

		// Capture negotiated subprotocol
		negotiatedProtocol := serverConn.Subprotocol()
		DebugLog("%s[WS] Negotiated subprotocol: %s", logPrefix, negotiatedProtocol)

	} else {
		// Direct connection (original behavior)
		serverHeader := http.Header{}
		copyHeaders(serverHeader, r.Header)

		// Check if insecure is set
		dialer := websocket.DefaultDialer
		if mapping != nil {
			toConfig := mapping.GetToConfig()
			if toConfig != nil && toConfig.Insecure != nil && *toConfig.Insecure {
				dialer = &websocket.Dialer{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}
			}
		}

		DebugLog("%s[WS] Dialing backend WebSocket directly: %s", logPrefix, targetWsURL.String())
		serverConn, _, err = dialer.Dial(targetWsURL.String(), serverHeader)
		if err != nil {
			isError = true
			log.Printf("%s[WS] Failed to dial server %s: %v", logPrefix, targetWsURL.String(), err)
			http.Error(w, "Failed to connect to backend", http.StatusBadGateway)
			return
		}

		// Capture negotiated subprotocol for direct connection too
		negotiatedProtocol := serverConn.Subprotocol()
		DebugLog("%s[WS] Negotiated subprotocol (direct): %s", logPrefix, negotiatedProtocol)

		// We need to pass this to upgrader, but we need a variable accessible outside if/else
		// Refactoring to declare upgradeHeader outside
	}
	defer serverConn.Close()

	DebugLog("%s[WS] Backend connection established. Upgrading client connection...", logPrefix)

	// Prepare upgrade headers
	upgradeHeader := http.Header{}
	if serverConn.Subprotocol() != "" {
		upgradeHeader.Set("Sec-WebSocket-Protocol", serverConn.Subprotocol())
	}

	// Upgrade the client connection using the global upgrader from utils.go
	// We do this AFTER establishing the backend connection to ensure we don't upgrade if backend is unavailable
	clientConn, err := upgrader.Upgrade(w, r, upgradeHeader)
	if err != nil {
		isError = true
		log.Printf("%s[WS] Failed to upgrade client connection: %v", logPrefix, err)
		return
	}
	defer clientConn.Close()

	DebugLog("%s[WS] Client connection upgraded. Starting proxy loops...", logPrefix)

	var wsConfig *WebSocketConfig
	if mapping != nil {
		fromConfig := mapping.GetFromConfig()
		if fromConfig != nil {
			wsConfig = fromConfig.WebSocket
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine to proxy messages from client to server
	go func() {
		defer wg.Done()
		var rules []WebSocketMessageConfig
		if wsConfig != nil {
			rules = wsConfig.InterceptClientMessages
		}
		DebugLog("%s[WS] Starting Client->Server loop", logPrefix)
		n := proxyWebSocketMessages(clientConn, serverConn, "C->S", rules)
		DebugLog("%s[WS] Client->Server loop finished. Bytes: %d", logPrefix, n)
		atomic.AddUint64(&bytesRecv, n)
	}()

	// Goroutine to proxy messages from server to client
	go func() {
		defer wg.Done()
		var rules []WebSocketMessageConfig
		if wsConfig != nil {
			rules = wsConfig.InterceptServerMessages
		}
		DebugLog("%s[WS] Starting Server->Client loop", logPrefix)
		n := proxyWebSocketMessages(serverConn, clientConn, "S->C", rules)
		DebugLog("%s[WS] Server->Client loop finished. Bytes: %d", logPrefix, n)
		atomic.AddUint64(&bytesSent, n)
	}()

	wg.Wait()
	DebugLog("%s[WS] Connection closed for %s", logPrefix, originalURL)
}

// proxyWebSocketMessages reads messages from the source, processes them, and writes to the destination.
// It returns the total number of bytes successfully written to the destination.
func proxyWebSocketMessages(src, dest *websocket.Conn, direction string, rules []WebSocketMessageConfig) uint64 {
	var bytesTransferred uint64
	for {
		msgType, msg, err := src.ReadMessage()
		if err != nil {
			// Log ALL errors for debugging
			DebugLog("[WS] %s: Error reading message: %v", direction, err)
			break
		}

		processedMsg, drop := processWebSocketMessage(msg, direction, rules)
		if drop {
			continue // Skip writing the message
		}

		err = dest.WriteMessage(msgType, processedMsg)
		if err != nil {
			DebugLog("[WS] %s: Error writing message: %v", direction, err)
			break
		}
		bytesTransferred += uint64(len(processedMsg))
	}
	return bytesTransferred
}

// processWebSocketMessage applies interception rules to a single WebSocket message.
func processWebSocketMessage(msg []byte, direction string, rules []WebSocketMessageConfig) ([]byte, bool) {
	if len(rules) == 0 {
		return msg, false
	}

	originalMsgStr := string(msg)
	modifiedMsg := msg
	drop := false

	for _, rule := range rules {
		if rule.Match != "" {
			re, err := compileRegex(rule.Match)
			if err != nil {
				log.Printf("[WS] %s: Invalid regex in rule: %v", direction, err)
				continue
			}

			if re.Match(modifiedMsg) {
				if rule.Log {
					log.Printf("[WS INTERCEPT %s] Matched message: %s", direction, originalMsgStr)
				}
				if rule.Drop {
					log.Printf("[WS INTERCEPT %s] Dropping message based on rule.", direction)
					drop = true
					break
				}
				if len(rule.Replace) > 0 {
					tempBody := string(modifiedMsg)
					for key, value := range rule.Replace {
						replaceRe, err := compileRegex(key)
						if err != nil {
							log.Printf("[WS] %s: Invalid replace regex: %v", direction, err)
							continue
						}
						tempBody = replaceRe.ReplaceAllString(tempBody, value)
					}
					modifiedMsg = []byte(tempBody)
					log.Printf("[WS INTERCEPT %s] Message modified: %s -> %s", direction, originalMsgStr, string(modifiedMsg))
				}
			}
		}
	}

	return modifiedMsg, drop
}

// loggingConn wraps a net.Conn to log Read/Write operations
type loggingConn struct {
	net.Conn
	name string
}

func (c loggingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		// Log first few bytes to identify packet type (TLS record, HTTP, etc)
		prefix := ""
		if n > 0 {
			prefix = fmt.Sprintf("[%x]", b[0])
		}
		DebugLog("[WS] %s: Read %d bytes %s", c.name, n, prefix)
	}
	if err != nil && err != io.EOF {
		DebugLog("[WS] %s: Read error: %v", c.name, err)
	}
	return n, err
}

func (c loggingConn) Write(b []byte) (int, error) {
	DebugLog("[WS] %s: Writing %d bytes", c.name, len(b))
	return c.Conn.Write(b)
}

// newWebSocketProxyPipe creates a bidirectional connection pair
// for WebSocket proxy through tunnel. Returns clientSide and serverSide connections.
// We use a local TCP loopback instead of net.Pipe() because net.Pipe() is synchronous
// and unbuffered, which causes deadlocks with crypto/tls handshakes that expect buffering.
func newWebSocketProxyPipe() (net.Conn, net.Conn) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Printf("[WS] Failed to create loopback listener: %v", err)
		return net.Pipe() // Fallback
	}

	type connRes struct {
		c net.Conn
		e error
	}
	ch := make(chan connRes)

	go func() {
		c, e := listener.Accept()
		ch <- connRes{c, e}
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		listener.Close()
		log.Printf("[WS] Failed to dial loopback: %v", err)
		return net.Pipe()
	}

	res := <-ch
	listener.Close()
	if res.e != nil {
		client.Close()
		log.Printf("[WS] Failed to accept loopback: %v", res.e)
		return net.Pipe()
	}

	return client, res.c
}
