package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// PortMapper manages local port listeners that forward traffic to remote endpoints
type PortMapper struct {
	mappings   []PortMappingConfig
	listeners  map[int]net.Listener
	tunnelConn *TunnelConn // Connection to APS for forwarding
	mu         sync.RWMutex
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

// PortForwardConnection represents an active port forwarding connection
type PortForwardConnection struct {
	LocalConn    net.Conn
	ConnectionID string
	Mapping      PortMappingConfig
	Done         chan struct{}
}

// NewPortMapper creates a new port mapper instance
func NewPortMapper(mappings []PortMappingConfig) *PortMapper {
	return &PortMapper{
		mappings:  mappings,
		listeners: make(map[int]net.Listener),
		stopCh:    make(chan struct{}),
	}
}

// SetTunnelConn sets the tunnel connection for forwarding traffic
func (pm *PortMapper) SetTunnelConn(tc *TunnelConn) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.tunnelConn = tc
}

// Start starts all port listeners based on the configured mappings
func (pm *PortMapper) Start() error {
	for _, mapping := range pm.mappings {
		if err := pm.startListener(mapping); err != nil {
			log.Printf("[PORT-MAP] Failed to start listener on port %d: %v", mapping.LocalPort, err)
			// Continue with other mappings even if one fails
		}
	}
	return nil
}

// startListener starts a listener for a specific port mapping
func (pm *PortMapper) startListener(mapping PortMappingConfig) error {
	addr := fmt.Sprintf("0.0.0.0:%d", mapping.LocalPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	pm.mu.Lock()
	pm.listeners[mapping.LocalPort] = listener
	pm.mu.Unlock()

	log.Printf("[PORT-MAP] Listening on port %d -> %s via endpoint %s",
		mapping.LocalPort, mapping.RemoteTarget, mapping.TargetEndpoint)

	pm.wg.Add(1)
	go pm.acceptLoop(listener, mapping)

	return nil
}

// acceptLoop accepts connections and forwards them
func (pm *PortMapper) acceptLoop(listener net.Listener, mapping PortMappingConfig) {
	defer pm.wg.Done()

	for {
		select {
		case <-pm.stopCh:
			return
		default:
		}

		// Set accept deadline to allow checking stopCh
		if tcpListener, ok := listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// Check if we're shutting down
			select {
			case <-pm.stopCh:
				return
			default:
				log.Printf("[PORT-MAP] Accept error on port %d: %v", mapping.LocalPort, err)
				continue
			}
		}

		go pm.handleConnection(conn, mapping)
	}
}

// handleConnection handles a single forwarded connection
func (pm *PortMapper) handleConnection(conn net.Conn, mapping PortMappingConfig) {
	defer conn.Close()

	pm.mu.RLock()
	tc := pm.tunnelConn
	pm.mu.RUnlock()

	if tc == nil {
		log.Printf("[PORT-MAP] No tunnel connection available for forwarding")
		return
	}

	clientAddr := conn.RemoteAddr().String()
	log.Printf("[PORT-MAP] New connection from %s on port %d -> %s via endpoint %s",
		clientAddr, mapping.LocalPort, mapping.RemoteTarget, mapping.TargetEndpoint)

	log.Printf("[PORT-MAP] Using APS tunnel for %s", mapping.TargetEndpoint)
	pm.handleTunnelStreamForward(conn, tc, mapping, clientAddr)
}

// handleTunnelStreamForward forwards connection via APS tunnel SMUX stream
func (pm *PortMapper) handleTunnelStreamForward(localConn net.Conn, tc *TunnelConn, mapping PortMappingConfig, clientIP string) {
	// Get access to the tunnel's SMUX session
	// This requires the tunnel connection to also have a Session field
	// For now, we'll fall back to message-based forwarding
	// TODO: Implement tunnel stream forwarding after refactoring TunnelConn

	// Generate connection ID
	connectionID := generateConnectionID()

	// Request proxy connection through APS to the target endpoint
	if err := pm.requestPortForward(tc, connectionID, mapping, clientIP); err != nil {
		log.Printf("[PORT-MAP] Failed to request port forward: %v", err)
		return
	}

	// Store the connection for data forwarding
	storePortForwardConnection(connectionID, localConn)
	defer removePortForwardConnection(connectionID)

	// Wait for connection acknowledgment and handle data transfer
	<-getPortForwardDoneChan(connectionID)
}

// requestPortForward sends a port forward request through the tunnel
func (pm *PortMapper) requestPortForward(tc *TunnelConn, connectionID string, mapping PortMappingConfig, clientIP string) error {
	payload := PortForwardRequestPayload{
		ConnectionID:   connectionID,
		TargetEndpoint: mapping.TargetEndpoint,
		RemoteTarget:   mapping.RemoteTarget,
		ClientIP:       clientIP,
	}

	return tc.SendJSON(MsgTypePortForwardRequest, payload)
}

// Stop stops all port listeners
func (pm *PortMapper) Stop() {
	close(pm.stopCh)

	pm.mu.Lock()
	for port, listener := range pm.listeners {
		listener.Close()
		log.Printf("[PORT-MAP] Stopped listener on port %d", port)
	}
	pm.listeners = make(map[int]net.Listener)
	pm.mu.Unlock()

	pm.wg.Wait()
}

// UpdateMappings updates the port mappings (hot reload support)
func (pm *PortMapper) UpdateMappings(newMappings []PortMappingConfig) {
	pm.mu.Lock()

	// Find ports to remove
	newPorts := make(map[int]bool)
	for _, m := range newMappings {
		newPorts[m.LocalPort] = true
	}

	// Stop listeners for removed ports
	for port, listener := range pm.listeners {
		if !newPorts[port] {
			listener.Close()
			delete(pm.listeners, port)
			log.Printf("[PORT-MAP] Removed listener on port %d", port)
		}
	}
	pm.mu.Unlock()

	// Start listeners for new ports
	for _, mapping := range newMappings {
		pm.mu.RLock()
		_, exists := pm.listeners[mapping.LocalPort]
		pm.mu.RUnlock()

		if !exists {
			if err := pm.startListener(mapping); err != nil {
				log.Printf("[PORT-MAP] Failed to start new listener on port %d: %v", mapping.LocalPort, err)
			}
		}
	}

	pm.mu.Lock()
	pm.mappings = newMappings
	pm.mu.Unlock()
}

// PortForwardRequestPayload is sent by endpoint to request port forwarding
type PortForwardRequestPayload struct {
	ConnectionID   string `json:"connection_id"`
	TargetEndpoint string `json:"target_endpoint"` // Which endpoint to forward to
	RemoteTarget   string `json:"remote_target"`   // IP:Port on target endpoint's network
	ClientIP       string `json:"client_ip"`       // Original client IP
}

// PortForwardResponsePayload is sent back with connection result
type PortForwardResponsePayload struct {
	ConnectionID string `json:"connection_id"`
	Success      bool   `json:"success"`
	Error        string `json:"error,omitempty"`
}

// Port forward connection storage
var (
	portForwardConns   = make(map[string]*PortForwardConnection)
	portForwardConnsMu sync.RWMutex
)

func storePortForwardConnection(id string, conn net.Conn) {
	portForwardConnsMu.Lock()
	portForwardConns[id] = &PortForwardConnection{
		LocalConn:    conn,
		ConnectionID: id,
		Done:         make(chan struct{}),
	}
	portForwardConnsMu.Unlock()
}

func getPortForwardConnection(id string) (*PortForwardConnection, bool) {
	portForwardConnsMu.RLock()
	defer portForwardConnsMu.RUnlock()
	conn, ok := portForwardConns[id]
	return conn, ok
}

func removePortForwardConnection(id string) {
	portForwardConnsMu.Lock()
	if conn, ok := portForwardConns[id]; ok {
		close(conn.Done)
		delete(portForwardConns, id)
	}
	portForwardConnsMu.Unlock()
}

func getPortForwardDoneChan(id string) <-chan struct{} {
	portForwardConnsMu.RLock()
	defer portForwardConnsMu.RUnlock()
	if conn, ok := portForwardConns[id]; ok {
		return conn.Done
	}
	// Return closed channel if not found
	ch := make(chan struct{})
	close(ch)
	return ch
}

// handlePortForwardData handles incoming data for port forwarded connections
func handlePortForwardData(connectionID string, data []byte) {
	pfc, ok := getPortForwardConnection(connectionID)
	if !ok {
		log.Printf("[PORT-MAP] Connection %s not found for data", connectionID)
		return
	}

	_, err := pfc.LocalConn.Write(data)
	if err != nil {
		log.Printf("[PORT-MAP] Write error for connection %s: %v", connectionID, err)
		removePortForwardConnection(connectionID)
	}
}

// handlePortForwardClose handles close of port forwarded connections
func handlePortForwardClose(connectionID string) {
	removePortForwardConnection(connectionID)
}

// generateConnectionID generates a unique connection ID
func generateConnectionID() string {
	return fmt.Sprintf("pf-%d-%d", time.Now().UnixNano(), time.Now().Nanosecond())
}

// startPortForwardReadLoop starts reading from local connection and forwarding to tunnel
func startPortForwardReadLoop(tc *TunnelConn, connectionID string, localConn net.Conn) {
	buf := make([]byte, 64*1024)
	for {
		n, err := localConn.Read(buf)
		if n > 0 {
			// Send data through tunnel
			if sendErr := tc.SendJSON(MsgTypePortForwardData, PortForwardDataPayload{
				ConnectionID: connectionID,
				Data:         buf[:n],
			}); sendErr != nil {
				log.Printf("[PORT-MAP] Failed to send data for %s: %v", connectionID, sendErr)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[PORT-MAP] Read error for %s: %v", connectionID, err)
			}
			// Notify tunnel of close
			tc.SendJSON(MsgTypePortForwardClose, PortForwardClosePayload{
				ConnectionID: connectionID,
			})
			return
		}
	}
}

// PortForwardDataPayload carries port forward data
type PortForwardDataPayload struct {
	ConnectionID string `json:"connection_id"`
	Data         []byte `json:"data"`
}

// PortForwardClosePayload signals port forward close
type PortForwardClosePayload struct {
	ConnectionID string `json:"connection_id"`
	Reason       string `json:"reason,omitempty"`
}

// handlePortForwardResponse handles response to a port forward request
func handlePortForwardResponse(tc *TunnelConn, msg *TunnelMessage) {
	var payload PortForwardResponsePayload
	if err := msg.ParseJSON(&payload); err != nil {
		log.Printf("[PORT-MAP] Failed to parse port forward response: %v", err)
		return
	}

	pfc, ok := getPortForwardConnection(payload.ConnectionID)
	if !ok {
		log.Printf("[PORT-MAP] Connection %s not found for response", payload.ConnectionID)
		return
	}

	if !payload.Success {
		log.Printf("[PORT-MAP] Port forward failed for %s: %s", payload.ConnectionID, payload.Error)
		removePortForwardConnection(payload.ConnectionID)
		return
	}

	log.Printf("[PORT-MAP] Port forward established for %s", payload.ConnectionID)

	// Start reading from local connection and forwarding to tunnel
	go startPortForwardReadLoop(tc, payload.ConnectionID, pfc.LocalConn)
}

// handlePortForwardDataMsg handles incoming data for port forwarded connections
func handlePortForwardDataMsg(msg *TunnelMessage) {
	var payload PortForwardDataPayload
	if err := msg.ParseJSON(&payload); err != nil {
		log.Printf("[PORT-MAP] Failed to parse port forward data: %v", err)
		return
	}

	handlePortForwardData(payload.ConnectionID, payload.Data)
}

// handlePortForwardCloseMsg handles close of port forwarded connections
func handlePortForwardCloseMsg(msg *TunnelMessage) {
	var payload PortForwardClosePayload
	if err := msg.ParseJSON(&payload); err != nil {
		log.Printf("[PORT-MAP] Failed to parse port forward close: %v", err)
		return
	}

	log.Printf("[PORT-MAP] Connection %s closed: %s", payload.ConnectionID, payload.Reason)
	handlePortForwardClose(payload.ConnectionID)
}
