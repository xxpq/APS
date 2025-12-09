package main

import (
	"log"
	"net/http"
	"net/url"
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
	log.Printf("[WS] Handling WebSocket request for %s", originalURL)

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
		})
	}()

	// Check if this is a tunnel WebSocket connection
	if r.URL.Path == "/.tunnel" {
		p.handleTunnelWebSocket(w, r)
		return
	}

	// Auth check
	_, user, username := p.checkAuth(r, nil) // Mapping will be checked later
	if user != nil {
		userKey = username
	}

	// Use the existing mapping logic to find the target backend and the specific mapping rule
	targetURL, matched, mapping, matchedFromURL := p.mapRequest(r)
	if !matched {
		isError = true
		log.Printf("[WS] No mapping found for %s", originalURL)
		http.Error(w, "No mapping found for WebSocket request", http.StatusBadGateway)
		return
	}

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
	} else {
		targetWsURL.Scheme = "ws"
	}

	// Upgrade the client connection using the global upgrader from utils.go
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		isError = true
		log.Printf("[WS] Failed to upgrade client connection: %v", err)
		return
	}
	defer clientConn.Close()

	log.Printf("[WS] Client connection upgraded for %s", originalURL)

	// Dial the server connection
	serverHeader := http.Header{}
	copyHeaders(serverHeader, r.Header)

	serverConn, _, err := websocket.DefaultDialer.Dial(targetWsURL.String(), serverHeader)
	if err != nil {
		isError = true
		log.Printf("[WS] Failed to dial server %s: %v", targetWsURL.String(), err)
		return
	}
	defer serverConn.Close()

	log.Printf("[WS] Connection established to backend %s", targetWsURL.String())

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
		n := proxyWebSocketMessages(clientConn, serverConn, "C->S", rules)
		atomic.AddUint64(&bytesRecv, n)
	}()

	// Goroutine to proxy messages from server to client
	go func() {
		defer wg.Done()
		var rules []WebSocketMessageConfig
		if wsConfig != nil {
			rules = wsConfig.InterceptServerMessages
		}
		n := proxyWebSocketMessages(serverConn, clientConn, "S->C", rules)
		atomic.AddUint64(&bytesSent, n)
	}()

	wg.Wait()
	log.Printf("[WS] Connection closed for %s", originalURL)
}

// proxyWebSocketMessages reads messages from the source, processes them, and writes to the destination.
// It returns the total number of bytes successfully written to the destination.
func proxyWebSocketMessages(src, dest *websocket.Conn, direction string, rules []WebSocketMessageConfig) uint64 {
	var bytesTransferred uint64
	for {
		msgType, msg, err := src.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[WS] %s: Error reading message: %v", direction, err)
			}
			break
		}

		processedMsg, drop := processWebSocketMessage(msg, direction, rules)
		if drop {
			continue // Skip writing the message
		}

		err = dest.WriteMessage(msgType, processedMsg)
		if err != nil {
			log.Printf("[WS] %s: Error writing message: %v", direction, err)
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

// handleTunnelWebSocket handles WebSocket connections for tunnel communication
func (p *MapRemoteProxy) handleTunnelWebSocket(w http.ResponseWriter, r *http.Request) {
	log.Printf("[WS] Handling tunnel WebSocket connection")

	// Get tunnel and endpoint information from headers
	tunnelName := r.Header.Get("X-Tunnel-Name")
	endpointName := r.Header.Get("X-Endpoint-Name")
	// tunnelPassword := r.Header.Get("X-Tunnel-Password") // Not used here, but passed to wsManager
	apsVersion := r.Header.Get("X-Aps-Tunnel")

	if tunnelName == "" || endpointName == "" {
		log.Printf("[WS] Missing required headers for tunnel connection")
		http.Error(w, "Missing required headers", http.StatusBadRequest)
		return
	}

	log.Printf("[WS] Tunnel connection request: tunnel=%s, endpoint=%s, version=%s", tunnelName, endpointName, apsVersion)

	// Check if we have a hybrid tunnel manager that can handle WebSocket connections
	if hybridTM, ok := p.tunnelManager.(*HybridTunnelManager); ok && hybridTM.wsManager != nil {
		// Delegate to the WebSocket pool manager
		hybridTM.wsManager.HandleWebSocketUpgrade(w, r)
	} else {
		log.Printf("[WS] WebSocket manager not available for tunnel connection")
		http.Error(w, "WebSocket tunnel not available", http.StatusServiceUnavailable)
	}
}