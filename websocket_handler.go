package main

import (
	"log"
	"net/http"
	"net/url"
	"sync"

	"github.com/gorilla/websocket"
)

// handleWebSocket handles WebSocket upgrade requests and proxies the connection.
func (p *MapRemoteProxy) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	p.stats.IncTotalRequests()
	p.stats.IncActiveConnections()
	defer p.stats.DecActiveConnections()

	originalURL := p.buildOriginalURL(r)
	log.Printf("[WS] Handling WebSocket request for %s", originalURL)

	// Use the existing mapping logic to find the target backend and the specific mapping rule
	targetURL, matched, mapping := p.mapRequest(r)
	if !matched {
		log.Printf("[WS] No mapping found for %s", originalURL)
		http.Error(w, "No mapping found for WebSocket request", http.StatusBadGateway)
		return
	}

	// Change the scheme from http/https to ws/wss
	targetWsURL, err := url.Parse(targetURL)
	if err != nil {
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
		log.Printf("[WS] Failed to upgrade client connection: %v", err)
		return
	}
	defer clientConn.Close()

	log.Printf("[WS] Client connection upgraded for %s", originalURL)

	// Dial the server connection
	// We need to forward headers from the original request
	serverHeader := http.Header{}
	copyHeaders(serverHeader, r.Header) // Use global copyHeaders from utils.go

	serverConn, _, err := websocket.DefaultDialer.Dial(targetWsURL.String(), serverHeader)
	if err != nil {
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
		proxyWebSocketMessages(clientConn, serverConn, "C->S", rules)
	}()

	// Goroutine to proxy messages from server to client
	go func() {
		defer wg.Done()
		var rules []WebSocketMessageConfig
		if wsConfig != nil {
			rules = wsConfig.InterceptServerMessages
		}
		proxyWebSocketMessages(serverConn, clientConn, "S->C", rules)
	}()

	wg.Wait()
	log.Printf("[WS] Connection closed for %s", originalURL)
}

// proxyWebSocketMessages reads messages from the source, processes them, and writes to the destination.
func proxyWebSocketMessages(src, dest *websocket.Conn, direction string, rules []WebSocketMessageConfig) {
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
	}
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
			re, err := compileRegex(rule.Match) // Use global compileRegex from utils.go
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
					break // No need to process other rules if it's dropped
				}
				if len(rule.Replace) > 0 {
					tempBody := string(modifiedMsg)
					for key, value := range rule.Replace {
						replaceRe, err := compileRegex(key) // Use global compileRegex from utils.go
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