package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	gatewayProtocolVersion = "APS-GW/1"
	gatewayCommandConnect  = "CONNECT"
	gatewayCommandGrid     = "GRID"
	gatewayDiscoverMagic   = "APS-GW-DISCOVER/1"
	gatewayAnnounceMagic   = "APS-GW-ANNOUNCE/1"
	gatewayPeerMagic       = "APS-GW-PEER/1"

	defaultGatewayDiscoverPort = 37990
	defaultGatewayHopLimit     = 8
	maxGatewayHopLimit         = 32

	gatewayPeerBroadcastInterval = 5 * time.Second
	gatewayPeerRouteTTL          = 45 * time.Second
	maxGatewayPeerEntries        = 128
	maxGatewayRouteEntries       = 256
	maxGatewayAnnounceEntries    = 32
)

type gatewayPeerInfo struct {
	NodeID   string
	Addr     string
	LastSeen time.Time
}

type gatewayTargetRoute struct {
	Target        string
	NextHopNodeID string
	NextHopAddr   string
	Hop           int
	LastSeen      time.Time
}

type gatewayPeerMetric struct {
	SuccessCount int
	FailureCount int
	RTTEwmaMs    float64
	JitterEwmaMs float64
	LastRTTMs    float64
	UpdatedAt    time.Time
}

type gatewayRouteCandidate struct {
	NextHopNodeID string
	NextHopAddr   string
	Hop           int
	LastSeen      time.Time
	Cost          float64
}

type gatewayConnectMeta struct {
	Token        string
	OriginNodeID string
	Path         []string
	HopLimit     int
}

type gatewayRuntimeState struct {
	mu            sync.Mutex
	started       bool
	listenAddr    string
	nodeID        string
	token         string
	discoverPort  int
	listener      net.Listener
	discoveryConn *net.UDPConn
	peers         map[string]gatewayPeerInfo
	peerMetrics   map[string]gatewayPeerMetric
	targetRoutes  map[string]gatewayTargetRoute
	directTargets map[string]struct{}
}

var endpointGatewayRuntime = gatewayRuntimeState{
	peers:         make(map[string]gatewayPeerInfo),
	peerMetrics:   make(map[string]gatewayPeerMetric),
	targetRoutes:  make(map[string]gatewayTargetRoute),
	directTargets: make(map[string]struct{}),
}

func ensureGatewayRuntime(connCtx ImmutableConnectionContext) {
	listenAddr := strings.TrimSpace(connCtx.GatewayListen)
	if listenAddr == "" {
		return
	}
	if connCtx.GatewayDiscoverPort <= 0 {
		connCtx.GatewayDiscoverPort = defaultGatewayDiscoverPort
	}

	nodeID := normalizeGatewayNodeID(connCtx.ConfigID)
	if nodeID == "" {
		nodeID = normalizeGatewayNodeID(connCtx.EndpointName)
	}
	token := strings.TrimSpace(connCtx.GatewayToken)
	directTarget := normalizeGatewayAddress(connCtx.ServerAddress)

	endpointGatewayRuntime.mu.Lock()
	if directTarget != "" {
		endpointGatewayRuntime.directTargets[directTarget] = struct{}{}
	}
	if endpointGatewayRuntime.started {
		if nodeID != "" {
			endpointGatewayRuntime.nodeID = nodeID
		}
		endpointGatewayRuntime.token = token
		if connCtx.GatewayDiscoverPort > 0 {
			endpointGatewayRuntime.discoverPort = connCtx.GatewayDiscoverPort
		}
		endpointGatewayRuntime.mu.Unlock()
		return
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		endpointGatewayRuntime.mu.Unlock()
		log.Printf("[GATEWAY] Failed to listen on %s: %v", listenAddr, err)
		return
	}

	endpointGatewayRuntime.started = true
	endpointGatewayRuntime.listenAddr = ln.Addr().String()
	endpointGatewayRuntime.nodeID = nodeID
	endpointGatewayRuntime.token = token
	endpointGatewayRuntime.discoverPort = connCtx.GatewayDiscoverPort
	endpointGatewayRuntime.listener = ln
	discoverPort := endpointGatewayRuntime.discoverPort
	listenAddr = endpointGatewayRuntime.listenAddr
	endpointGatewayRuntime.mu.Unlock()

	log.Printf("[GATEWAY] Relay listener started on %s", listenAddr)
	go acceptGatewayRelayLoop(ln, listenAddr)

	if discoverPort > 0 {
		discoveryConn, discoverErr := net.ListenUDP("udp4", &net.UDPAddr{Port: discoverPort})
		if discoverErr != nil {
			log.Printf("[GATEWAY] Failed to start discovery responder on UDP/%d: %v", discoverPort, discoverErr)
			return
		}

		endpointGatewayRuntime.mu.Lock()
		endpointGatewayRuntime.discoveryConn = discoveryConn
		endpointGatewayRuntime.mu.Unlock()

		log.Printf("[GATEWAY] Discovery responder started on UDP/%d", discoverPort)
		go serveGatewayDiscovery(discoveryConn, listenAddr, discoverPort)
		go broadcastGatewayPresence(discoveryConn, discoverPort, listenAddr)
	}
}

func resolveGatewayAddress(connCtx ImmutableConnectionContext) string {
	if addr := normalizeGatewayAddress(connCtx.GatewayAddress); addr != "" {
		if !isLocalGatewayAddress(addr) {
			return addr
		}
	}

	if connCtx.GatewayDiscovery && connCtx.GatewayDiscoverPort > 0 {
		if discovered, err := discoverGatewayAddress(connCtx.GatewayDiscoverPort, strings.TrimSpace(connCtx.GatewayToken)); err == nil {
			if discovered != "" && !isLocalGatewayAddress(discovered) {
				return discovered
			}
		}
	}

	selfNode := normalizeGatewayNodeID(connCtx.ConfigID)
	if selfNode == "" {
		selfNode = normalizeGatewayNodeID(connCtx.EndpointName)
	}
	if routeAddr, _ := selectGatewayRoute(connCtx.ServerAddress, nil, selfNode); routeAddr != "" {
		return routeAddr
	}

	return ""
}

func acceptGatewayRelayLoop(listener net.Listener, listenAddr string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return
		}
		go handleGatewayRelayConnection(conn, listenAddr)
	}
}

func handleGatewayRelayConnection(clientConn net.Conn, listenAddr string) {
	defer clientConn.Close()

	_ = clientConn.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(clientConn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) >= 2 && fields[0] == gatewayProtocolVersion && strings.EqualFold(fields[1], gatewayCommandGrid) {
		handleGatewayGridConnection(clientConn, reader, line)
		return
	}

	targetAddr, meta, parseErr := parseGatewayConnectLine(line)
	if parseErr != nil {
		_, _ = io.WriteString(clientConn, "ERR invalid request\n")
		return
	}

	runtimeToken, runtimeNodeID := currentGatewayIdentity()
	if runtimeToken != "" && strings.TrimSpace(meta.Token) != runtimeToken {
		_, _ = io.WriteString(clientConn, "ERR unauthorized\n")
		return
	}
	if err := validateGatewayRelayRequest(targetAddr, listenAddr, runtimeNodeID, meta); err != nil {
		_, _ = io.WriteString(clientConn, "ERR loop detected\n")
		return
	}

	relayMeta := meta
	if runtimeNodeID != "" {
		relayMeta.Path = appendGatewayPath(relayMeta.Path, runtimeNodeID)
	}
	if relayMeta.Token == "" {
		relayMeta.Token = runtimeToken
	}

	upstreamConn, err := net.DialTimeout("tcp", targetAddr, 15*time.Second)
	if err != nil {
		if relayMeta.HopLimit <= 1 {
			_, _ = io.WriteString(clientConn, "ERR hop limit exceeded\n")
			return
		}

		candidates := selectGatewayRouteCandidates(targetAddr, relayMeta.Path, runtimeNodeID, 3)
		if len(candidates) == 0 {
			_, _ = io.WriteString(clientConn, "ERR dial upstream failed\n")
			return
		}
		var forwarded bool
		for _, candidate := range candidates {
			forwardMeta := relayMeta
			forwardMeta.HopLimit--
			log.Printf("[GATEWAY] Forward target=%s via peer node=%s addr=%s hop=%d cost=%.3f", targetAddr, candidate.NextHopNodeID, candidate.NextHopAddr, forwardMeta.HopLimit, candidate.Cost)
			started := time.Now()
			upstreamConn, err = dialTunnelServerViaGatewayWithMeta(candidate.NextHopAddr, targetAddr, forwardMeta)
			recordGatewayPeerDialResult(candidate.NextHopNodeID, time.Since(started), err == nil)
			if err == nil {
				forwarded = true
				break
			}
		}
		if !forwarded {
			_, _ = io.WriteString(clientConn, "ERR dial upstream failed\n")
			return
		}
	}
	defer upstreamConn.Close()

	_, _ = io.WriteString(clientConn, "OK\n")
	_ = clientConn.SetDeadline(time.Time{})

	clientReaderConn := net.Conn(clientConn)
	if buffered := reader.Buffered(); buffered > 0 {
		prefix, peekErr := reader.Peek(buffered)
		if peekErr == nil && len(prefix) > 0 {
			clientReaderConn = &prefixedConn{
				Conn:   clientConn,
				prefix: append([]byte(nil), prefix...),
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstreamConn, clientReaderConn)
		_ = upstreamConn.SetReadDeadline(time.Now())
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, upstreamConn)
		_ = clientConn.SetReadDeadline(time.Now())
	}()
	wg.Wait()
}

func handleGatewayGridConnection(clientConn net.Conn, reader *bufio.Reader, line string) {
	meta, parseErr := parseGatewayGridLine(line)
	if parseErr != nil {
		_, _ = io.WriteString(clientConn, "ERR invalid request\n")
		return
	}

	runtimeToken, runtimeNodeID := currentGatewayIdentity()
	if runtimeToken != "" && strings.TrimSpace(meta.Token) != runtimeToken {
		_, _ = io.WriteString(clientConn, "ERR unauthorized\n")
		return
	}
	if err := validateGatewayGridRequest(runtimeNodeID, meta); err != nil {
		_, _ = io.WriteString(clientConn, "ERR loop detected\n")
		return
	}

	_, _ = io.WriteString(clientConn, "OK\n")
	_ = clientConn.SetDeadline(time.Time{})

	gridConn := net.Conn(clientConn)
	if buffered := reader.Buffered(); buffered > 0 {
		prefix, peekErr := reader.Peek(buffered)
		if peekErr == nil && len(prefix) > 0 {
			gridConn = &prefixedConn{
				Conn:   clientConn,
				prefix: append([]byte(nil), prefix...),
			}
		}
	}

	handleEndpointGridTransitConnection(gridConn)
}

func parseGatewayConnectLine(line string) (targetAddr string, meta gatewayConnectMeta, err error) {
	fields, err := parseGatewayCommandFields(line, gatewayCommandConnect, 3)
	meta = gatewayConnectMeta{HopLimit: defaultGatewayHopLimit}
	if err != nil {
		return "", meta, err
	}

	targetAddr = normalizeGatewayAddress(fields[2])
	if targetAddr == "" {
		return "", meta, errors.New("target addr is required")
	}
	if _, _, splitErr := net.SplitHostPort(targetAddr); splitErr != nil {
		return "", meta, fmt.Errorf("invalid target addr: %w", splitErr)
	}

	meta = parseGatewayMetaFields(fields[3:])
	if meta.HopLimit <= 0 {
		return "", meta, errors.New("hop limit exceeded")
	}
	return targetAddr, meta, nil
}

func parseGatewayGridLine(line string) (gatewayConnectMeta, error) {
	fields, err := parseGatewayCommandFields(line, gatewayCommandGrid, 2)
	if err != nil {
		return gatewayConnectMeta{HopLimit: defaultGatewayHopLimit}, err
	}
	meta := parseGatewayMetaFields(fields[2:])
	if meta.HopLimit <= 0 {
		return meta, errors.New("hop limit exceeded")
	}
	return meta, nil
}

func parseGatewayCommandFields(line string, command string, minFields int) ([]string, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < minFields {
		return nil, errors.New("invalid gateway command")
	}
	if fields[0] != gatewayProtocolVersion || !strings.EqualFold(fields[1], command) {
		return nil, errors.New("unsupported gateway request")
	}
	return fields, nil
}

func parseGatewayMetaFields(fields []string) gatewayConnectMeta {
	meta := gatewayConnectMeta{HopLimit: defaultGatewayHopLimit}
	for _, raw := range fields {
		part := strings.TrimSpace(raw)
		if part == "" {
			continue
		}

		eq := strings.IndexByte(part, '=')
		if eq <= 0 {
			if meta.Token == "" {
				meta.Token = part
			}
			continue
		}

		key := strings.ToLower(strings.TrimSpace(part[:eq]))
		value := decodeGatewayField(strings.TrimSpace(part[eq+1:]))
		switch key {
		case "token":
			meta.Token = value
		case "origin":
			meta.OriginNodeID = normalizeGatewayNodeID(value)
		case "path":
			meta.Path = parseGatewayPath(value)
		case "hop":
			if hop, convErr := strconv.Atoi(strings.TrimSpace(value)); convErr == nil {
				meta.HopLimit = hop
			}
		}
	}

	meta.Path = normalizeGatewayPath(meta.Path)
	if meta.OriginNodeID == "" && len(meta.Path) > 0 {
		meta.OriginNodeID = meta.Path[0]
	}
	if meta.HopLimit > maxGatewayHopLimit {
		meta.HopLimit = maxGatewayHopLimit
	}
	return meta
}

func validateGatewayRelayRequest(targetAddr, listenAddr, nodeID string, meta gatewayConnectMeta) error {
	if meta.HopLimit <= 0 {
		return errors.New("hop limit exceeded")
	}
	if sameGatewayAddress(targetAddr, listenAddr) {
		return errors.New("self-loop target")
	}

	selfNode := normalizeGatewayNodeID(nodeID)
	if selfNode != "" {
		if normalizeGatewayNodeID(meta.OriginNodeID) == selfNode {
			return errors.New("origin loop")
		}
		if gatewayPathContains(meta.Path, selfNode) {
			return errors.New("path loop")
		}
	}
	return nil
}

func validateGatewayGridRequest(nodeID string, meta gatewayConnectMeta) error {
	if meta.HopLimit <= 0 {
		return errors.New("hop limit exceeded")
	}
	selfNode := normalizeGatewayNodeID(nodeID)
	if selfNode == "" {
		return nil
	}
	if normalizeGatewayNodeID(meta.OriginNodeID) == selfNode {
		return errors.New("origin loop")
	}
	if gatewayPathContains(meta.Path, selfNode) {
		return errors.New("path loop")
	}
	return nil
}

func dialTunnelServerViaGateway(gatewayAddr, targetAddr, token, originNodeID string) (net.Conn, error) {
	meta := gatewayConnectMeta{
		Token:        strings.TrimSpace(token),
		OriginNodeID: normalizeGatewayNodeID(originNodeID),
		HopLimit:     defaultGatewayHopLimit,
	}
	if meta.OriginNodeID != "" {
		meta.Path = []string{meta.OriginNodeID}
	}
	return dialTunnelServerViaGatewayWithMeta(gatewayAddr, targetAddr, meta)
}

func dialTunnelServerViaGatewayWithMeta(gatewayAddr, targetAddr string, meta gatewayConnectMeta) (net.Conn, error) {
	gatewayAddr = normalizeGatewayAddress(gatewayAddr)
	if gatewayAddr == "" {
		return nil, errors.New("gateway address is required")
	}
	targetAddr = normalizeGatewayAddress(targetAddr)
	if targetAddr == "" {
		return nil, errors.New("target address is required")
	}
	if sameGatewayAddress(gatewayAddr, targetAddr) {
		return nil, errors.New("gateway and target are identical")
	}

	if meta.HopLimit <= 0 {
		meta.HopLimit = defaultGatewayHopLimit
	}
	if meta.HopLimit > maxGatewayHopLimit {
		meta.HopLimit = maxGatewayHopLimit
	}
	meta.Path = normalizeGatewayPath(meta.Path)

	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	conn, err := dialer.Dial("tcp", gatewayAddr)
	if err != nil {
		return nil, err
	}

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	connectLine := buildGatewayConnectLine(targetAddr, meta)
	if _, err := io.WriteString(conn, connectLine); err != nil {
		_ = conn.Close()
		return nil, err
	}

	reader := bufio.NewReader(conn)
	respLine, err := reader.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	respLine = strings.TrimSpace(respLine)
	if !strings.HasPrefix(respLine, "OK") {
		_ = conn.Close()
		return nil, fmt.Errorf("gateway rejected connect: %s", respLine)
	}

	_ = conn.SetDeadline(time.Time{})
	buffered := reader.Buffered()
	if buffered == 0 {
		return conn, nil
	}
	prefixBytes, err := reader.Peek(buffered)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	prefix := make([]byte, len(prefixBytes))
	copy(prefix, prefixBytes)
	return &prefixedConn{Conn: conn, prefix: prefix}, nil
}

func dialGatewayPeerGrid(nodeID string) (net.Conn, error) {
	nodeID = normalizeGatewayNodeID(nodeID)
	if nodeID == "" {
		return nil, errors.New("peer node id is required")
	}

	endpointGatewayRuntime.mu.Lock()
	peer, ok := endpointGatewayRuntime.peers[nodeID]
	token := strings.TrimSpace(endpointGatewayRuntime.token)
	origin := normalizeGatewayNodeID(endpointGatewayRuntime.nodeID)
	endpointGatewayRuntime.mu.Unlock()

	if !ok || strings.TrimSpace(peer.Addr) == "" {
		return nil, fmt.Errorf("gateway peer %s not discovered", nodeID)
	}

	meta := gatewayConnectMeta{
		Token:        token,
		OriginNodeID: origin,
		HopLimit:     defaultGatewayHopLimit,
	}
	if origin != "" {
		meta.Path = []string{origin}
	}
	started := time.Now()
	conn, err := dialGatewayGridWithMeta(peer.Addr, meta)
	recordGatewayPeerDialResult(nodeID, time.Since(started), err == nil)
	return conn, err
}

func dialGatewayGridWithMeta(peerAddr string, meta gatewayConnectMeta) (net.Conn, error) {
	peerAddr = normalizeGatewayAddress(peerAddr)
	if peerAddr == "" {
		return nil, errors.New("peer address is required")
	}

	if meta.HopLimit <= 0 {
		meta.HopLimit = defaultGatewayHopLimit
	}
	if meta.HopLimit > maxGatewayHopLimit {
		meta.HopLimit = maxGatewayHopLimit
	}
	meta.Path = normalizeGatewayPath(meta.Path)

	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	conn, err := dialer.Dial("tcp", peerAddr)
	if err != nil {
		return nil, err
	}

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.WriteString(conn, buildGatewayGridLine(meta)); err != nil {
		_ = conn.Close()
		return nil, err
	}

	reader := bufio.NewReader(conn)
	respLine, err := reader.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	respLine = strings.TrimSpace(respLine)
	if !strings.HasPrefix(respLine, "OK") {
		_ = conn.Close()
		return nil, fmt.Errorf("gateway rejected grid transit: %s", respLine)
	}

	_ = conn.SetDeadline(time.Time{})
	buffered := reader.Buffered()
	if buffered == 0 {
		return conn, nil
	}
	prefixBytes, err := reader.Peek(buffered)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	prefix := make([]byte, len(prefixBytes))
	copy(prefix, prefixBytes)
	return &prefixedConn{Conn: conn, prefix: prefix}, nil
}

func buildGatewayConnectLine(targetAddr string, meta gatewayConnectMeta) string {
	parts := []string{
		gatewayProtocolVersion,
		gatewayCommandConnect,
		normalizeGatewayAddress(targetAddr),
	}
	if token := strings.TrimSpace(meta.Token); token != "" {
		parts = append(parts, "token="+encodeGatewayField(token))
	}
	if origin := normalizeGatewayNodeID(meta.OriginNodeID); origin != "" {
		parts = append(parts, "origin="+encodeGatewayField(origin))
	}
	if len(meta.Path) > 0 {
		parts = append(parts, "path="+encodeGatewayField(strings.Join(normalizeGatewayPath(meta.Path), ",")))
	}
	hop := meta.HopLimit
	if hop <= 0 {
		hop = defaultGatewayHopLimit
	}
	parts = append(parts, "hop="+strconv.Itoa(hop))
	return strings.Join(parts, " ") + "\n"
}

func buildGatewayGridLine(meta gatewayConnectMeta) string {
	parts := []string{
		gatewayProtocolVersion,
		gatewayCommandGrid,
	}
	if token := strings.TrimSpace(meta.Token); token != "" {
		parts = append(parts, "token="+encodeGatewayField(token))
	}
	if origin := normalizeGatewayNodeID(meta.OriginNodeID); origin != "" {
		parts = append(parts, "origin="+encodeGatewayField(origin))
	}
	if len(meta.Path) > 0 {
		parts = append(parts, "path="+encodeGatewayField(strings.Join(normalizeGatewayPath(meta.Path), ",")))
	}
	hop := meta.HopLimit
	if hop <= 0 {
		hop = defaultGatewayHopLimit
	}
	parts = append(parts, "hop="+strconv.Itoa(hop))
	return strings.Join(parts, " ") + "\n"
}

func serveGatewayDiscovery(conn *net.UDPConn, listenAddr string, discoverPort int) {
	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		msg := strings.TrimSpace(string(buf[:n]))
		if msg == "" {
			continue
		}

		if strings.HasPrefix(msg, gatewayDiscoverMagic) {
			fields := strings.Fields(msg)
			token, _ := currentGatewayTokenAndNodeID()
			if token != "" {
				if len(fields) < 2 || strings.TrimSpace(fields[1]) != token {
					continue
				}
			}

			announceAddr := buildGatewayAnnounceAddr(listenAddr, remoteAddr.IP)
			resp := fmt.Sprintf("%s %s\n", gatewayAnnounceMagic, announceAddr)
			_, _ = conn.WriteToUDP([]byte(resp), remoteAddr)

			if peerLine := buildGatewayPeerAnnounceLine(listenAddr); peerLine != "" {
				_, _ = conn.WriteToUDP([]byte(peerLine+"\n"), remoteAddr)
			}
			continue
		}

		if strings.HasPrefix(msg, gatewayPeerMagic+" ") {
			if applyGatewayPeerAnnounce(msg, remoteAddr) {
				if peerLine := buildGatewayPeerAnnounceLine(listenAddr); peerLine != "" {
					_, _ = conn.WriteToUDP([]byte(peerLine+"\n"), remoteAddr)
				}
			}
		}
	}
}

func broadcastGatewayPresence(conn *net.UDPConn, discoverPort int, listenAddr string) {
	if discoverPort <= 0 {
		return
	}

	send := func() {
		peerLine := buildGatewayPeerAnnounceLine(listenAddr)
		if peerLine == "" {
			return
		}
		payload := []byte(peerLine + "\n")
		_, _ = conn.WriteToUDP(payload, &net.UDPAddr{IP: net.IPv4bcast, Port: discoverPort})
	}

	send()
	ticker := time.NewTicker(gatewayPeerBroadcastInterval)
	defer ticker.Stop()
	for range ticker.C {
		send()
		pruneGatewayState(time.Now())
	}
}

func buildGatewayPeerAnnounceLine(listenAddr string) string {
	listenAddr = normalizeGatewayAddress(listenAddr)
	if listenAddr == "" {
		return ""
	}

	endpointGatewayRuntime.mu.Lock()
	defer endpointGatewayRuntime.mu.Unlock()

	now := time.Now()
	pruneGatewayStateLocked(now)

	nodeID := normalizeGatewayNodeID(endpointGatewayRuntime.nodeID)
	if nodeID == "" {
		return ""
	}
	token := strings.TrimSpace(endpointGatewayRuntime.token)

	parts := []string{
		gatewayPeerMagic,
		"node=" + encodeGatewayField(nodeID),
		"addr=" + encodeGatewayField(listenAddr),
	}
	if token != "" {
		parts = append(parts, "token="+encodeGatewayField(token))
	}

	peerEntries := make([]string, 0, len(endpointGatewayRuntime.peers))
	for peerNodeID, peer := range endpointGatewayRuntime.peers {
		if peerNodeID == "" || peer.Addr == "" || peerNodeID == nodeID {
			continue
		}
		peerEntries = append(peerEntries, peerNodeID+"@"+peer.Addr)
		if len(peerEntries) >= maxGatewayAnnounceEntries {
			break
		}
	}
	if len(peerEntries) > 0 {
		parts = append(parts, "peers="+encodeGatewayField(strings.Join(peerEntries, ",")))
	}

	targetEntries := make([]string, 0, len(endpointGatewayRuntime.directTargets)+len(endpointGatewayRuntime.targetRoutes))
	directSeen := make(map[string]struct{}, len(endpointGatewayRuntime.directTargets))
	for target := range endpointGatewayRuntime.directTargets {
		if target == "" {
			continue
		}
		directSeen[target] = struct{}{}
		targetEntries = append(targetEntries, target+"@0")
		if len(targetEntries) >= maxGatewayAnnounceEntries {
			break
		}
	}
	if len(targetEntries) < maxGatewayAnnounceEntries {
		for target, route := range endpointGatewayRuntime.targetRoutes {
			if target == "" {
				continue
			}
			if _, exists := directSeen[target]; exists {
				continue
			}
			hop := route.Hop
			if hop <= 0 {
				hop = 1
			}
			targetEntries = append(targetEntries, target+"@"+strconv.Itoa(hop))
			if len(targetEntries) >= maxGatewayAnnounceEntries {
				break
			}
		}
	}
	if len(targetEntries) > 0 {
		parts = append(parts, "targets="+encodeGatewayField(strings.Join(targetEntries, ",")))
	}

	return strings.Join(parts, " ")
}

func applyGatewayPeerAnnounce(msg string, remoteAddr *net.UDPAddr) bool {
	fields := strings.Fields(strings.TrimSpace(msg))
	if len(fields) < 2 || fields[0] != gatewayPeerMagic {
		return false
	}

	kv := make(map[string]string, len(fields)-1)
	for _, field := range fields[1:] {
		eq := strings.IndexByte(field, '=')
		if eq <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(field[:eq]))
		value := decodeGatewayField(strings.TrimSpace(field[eq+1:]))
		kv[key] = value
	}

	nodeID := normalizeGatewayNodeID(kv["node"])
	peerAddr := normalizeGatewayAddress(kv["addr"])
	if peerAddr == "" && remoteAddr != nil {
		if _, port, err := net.SplitHostPort(strings.TrimSpace(kv["addr"])); err == nil {
			peerAddr = net.JoinHostPort(remoteAddr.IP.String(), port)
		}
	}
	if peerAddr == "" || nodeID == "" {
		return false
	}

	peerTargets := parseGatewayTargetEntries(kv["targets"])
	peerRoutes := parseGatewayPeerEntries(kv["peers"])

	now := time.Now()
	endpointGatewayRuntime.mu.Lock()
	defer endpointGatewayRuntime.mu.Unlock()

	pruneGatewayStateLocked(now)

	localToken := strings.TrimSpace(endpointGatewayRuntime.token)
	if localToken != "" && strings.TrimSpace(kv["token"]) != localToken {
		return false
	}

	selfNodeID := normalizeGatewayNodeID(endpointGatewayRuntime.nodeID)
	if selfNodeID != "" && nodeID == selfNodeID {
		return false
	}

	updated := upsertGatewayPeerLocked(nodeID, peerAddr, now)

	for _, target := range peerTargets {
		hop := target.Hop + 1
		if hop > maxGatewayHopLimit {
			continue
		}
		if upsertGatewayTargetRouteLocked(target.Target, nodeID, peerAddr, hop, now) {
			updated = true
		}
	}

	for _, peerRoute := range peerRoutes {
		if peerRoute.NodeID == "" || peerRoute.Addr == "" {
			continue
		}
		if selfNodeID != "" && peerRoute.NodeID == selfNodeID {
			continue
		}
		if upsertGatewayPeerLocked(peerRoute.NodeID, peerRoute.Addr, now) {
			updated = true
		}
	}

	return updated
}

func parseGatewayTargetEntries(raw string) []gatewayTargetRoute {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	items := strings.Split(raw, ",")
	out := make([]gatewayTargetRoute, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.Split(item, "@")
		if len(parts) != 2 {
			continue
		}
		target := normalizeGatewayAddress(parts[0])
		if target == "" {
			continue
		}
		hop, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			continue
		}
		if hop < 0 {
			hop = 0
		}
		out = append(out, gatewayTargetRoute{Target: target, Hop: hop})
	}
	return out
}

func parseGatewayPeerEntries(raw string) []gatewayPeerInfo {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	items := strings.Split(raw, ",")
	out := make([]gatewayPeerInfo, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, "@", 2)
		if len(parts) != 2 {
			continue
		}
		nodeID := normalizeGatewayNodeID(parts[0])
		addr := normalizeGatewayAddress(parts[1])
		if nodeID == "" || addr == "" {
			continue
		}
		out = append(out, gatewayPeerInfo{NodeID: nodeID, Addr: addr})
	}
	return out
}

func selectGatewayRoute(targetAddr string, path []string, selfNodeID string) (string, string) {
	candidates := selectGatewayRouteCandidates(targetAddr, path, selfNodeID, 1)
	if len(candidates) == 0 {
		return "", ""
	}
	return candidates[0].NextHopAddr, candidates[0].NextHopNodeID
}

func selectGatewayRouteCandidates(targetAddr string, path []string, selfNodeID string, limit int) []gatewayRouteCandidate {
	target := normalizeGatewayAddress(targetAddr)
	if limit <= 0 {
		limit = 1
	}
	now := time.Now()
	endpointGatewayRuntime.mu.Lock()
	defer endpointGatewayRuntime.mu.Unlock()

	pruneGatewayStateLocked(now)
	path = normalizeGatewayPath(path)
	selfNodeID = normalizeGatewayNodeID(selfNodeID)
	selfAddr := normalizeGatewayAddress(endpointGatewayRuntime.listenAddr)

	candidates := make([]gatewayRouteCandidate, 0, len(endpointGatewayRuntime.peers)+1)
	seen := make(map[string]struct{}, len(endpointGatewayRuntime.peers)+1)
	addCandidate := func(nodeID, addr string, hop int, lastSeen time.Time) {
		nodeID = normalizeGatewayNodeID(nodeID)
		addr = normalizeGatewayAddress(addr)
		if nodeID == "" || addr == "" {
			return
		}
		if sameGatewayAddress(addr, selfAddr) {
			return
		}
		if gatewayPathContains(path, nodeID) {
			return
		}
		if selfNodeID != "" && nodeID == selfNodeID {
			return
		}
		if _, exists := seen[nodeID]; exists {
			return
		}
		seen[nodeID] = struct{}{}
		metric := endpointGatewayRuntime.peerMetrics[nodeID]
		cost := gatewayRouteCost(hop, lastSeen, metric, now)
		candidates = append(candidates, gatewayRouteCandidate{
			NextHopNodeID: nodeID,
			NextHopAddr:   addr,
			Hop:           hop,
			LastSeen:      lastSeen,
			Cost:          cost,
		})
	}

	if target != "" {
		if route, exists := endpointGatewayRuntime.targetRoutes[target]; exists {
			addCandidate(route.NextHopNodeID, route.NextHopAddr, route.Hop, route.LastSeen)
		}
	}
	for peerNodeID, peer := range endpointGatewayRuntime.peers {
		addCandidate(peerNodeID, peer.Addr, 2, peer.LastSeen)
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Cost == candidates[j].Cost {
			if candidates[i].Hop == candidates[j].Hop {
				return candidates[i].NextHopNodeID < candidates[j].NextHopNodeID
			}
			return candidates[i].Hop < candidates[j].Hop
		}
		return candidates[i].Cost < candidates[j].Cost
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	return candidates
}

func gatewayRouteCost(hop int, lastSeen time.Time, metric gatewayPeerMetric, now time.Time) float64 {
	if hop <= 0 {
		hop = 1
	}
	rttMs := metric.RTTEwmaMs
	if rttMs <= 0 {
		rttMs = 35
	}
	jitterMs := metric.JitterEwmaMs
	if jitterMs < 0 {
		jitterMs = 0
	}
	lossPct := 0.0
	total := metric.SuccessCount + metric.FailureCount
	if total > 0 {
		lossPct = (float64(metric.FailureCount) / float64(total)) * 100.0
	}
	staleSeconds := 0.0
	if !lastSeen.IsZero() {
		age := now.Sub(lastSeen)
		if age > 0 {
			staleSeconds = age.Seconds()
		}
	}
	// Dijkstra-compatible local edge cost:
	// hop + latency + jitter + loss + stale penalty, lower is better.
	return float64(hop)*1.0 + rttMs*0.02 + jitterMs*0.05 + lossPct*2.0 + staleSeconds*0.03
}

func recordGatewayPeerDialResult(nodeID string, rtt time.Duration, success bool) {
	nodeID = normalizeGatewayNodeID(nodeID)
	if nodeID == "" {
		return
	}
	now := time.Now()
	rttMs := float64(rtt.Milliseconds())
	if rttMs <= 0 {
		rttMs = 1
	}
	endpointGatewayRuntime.mu.Lock()
	metric := endpointGatewayRuntime.peerMetrics[nodeID]
	if success {
		metric.SuccessCount++
		if metric.RTTEwmaMs <= 0 {
			metric.RTTEwmaMs = rttMs
			metric.JitterEwmaMs = 0
		} else {
			delta := absFloat64(metric.RTTEwmaMs - rttMs)
			metric.JitterEwmaMs = metric.JitterEwmaMs*0.7 + delta*0.3
			metric.RTTEwmaMs = metric.RTTEwmaMs*0.8 + rttMs*0.2
		}
		metric.LastRTTMs = rttMs
	} else {
		metric.FailureCount++
	}
	metric.UpdatedAt = now
	endpointGatewayRuntime.peerMetrics[nodeID] = metric
	endpointGatewayRuntime.mu.Unlock()
}

func absFloat64(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

func pruneGatewayState(now time.Time) {
	endpointGatewayRuntime.mu.Lock()
	pruneGatewayStateLocked(now)
	endpointGatewayRuntime.mu.Unlock()
}

func pruneGatewayStateLocked(now time.Time) {
	cutoff := now.Add(-gatewayPeerRouteTTL)
	for nodeID, peer := range endpointGatewayRuntime.peers {
		if peer.LastSeen.Before(cutoff) {
			delete(endpointGatewayRuntime.peers, nodeID)
			delete(endpointGatewayRuntime.peerMetrics, nodeID)
		}
	}
	for target, route := range endpointGatewayRuntime.targetRoutes {
		if route.LastSeen.Before(cutoff) {
			delete(endpointGatewayRuntime.targetRoutes, target)
		}
	}
	trimGatewayPeerMapLocked()
	trimGatewayRouteMapLocked()
}

func trimGatewayPeerMapLocked() {
	for len(endpointGatewayRuntime.peers) > maxGatewayPeerEntries {
		var oldestNode string
		var oldestTime time.Time
		for nodeID, peer := range endpointGatewayRuntime.peers {
			if oldestNode == "" || peer.LastSeen.Before(oldestTime) {
				oldestNode = nodeID
				oldestTime = peer.LastSeen
			}
		}
		if oldestNode == "" {
			break
		}
		delete(endpointGatewayRuntime.peers, oldestNode)
	}
}

func trimGatewayRouteMapLocked() {
	for len(endpointGatewayRuntime.targetRoutes) > maxGatewayRouteEntries {
		var oldestTarget string
		var oldestTime time.Time
		for target, route := range endpointGatewayRuntime.targetRoutes {
			if oldestTarget == "" || route.LastSeen.Before(oldestTime) {
				oldestTarget = target
				oldestTime = route.LastSeen
			}
		}
		if oldestTarget == "" {
			break
		}
		delete(endpointGatewayRuntime.targetRoutes, oldestTarget)
	}
}

func upsertGatewayPeerLocked(nodeID, addr string, now time.Time) bool {
	nodeID = normalizeGatewayNodeID(nodeID)
	addr = normalizeGatewayAddress(addr)
	if nodeID == "" || addr == "" {
		return false
	}
	if existing, ok := endpointGatewayRuntime.peers[nodeID]; ok {
		if existing.Addr == addr {
			existing.LastSeen = now
			endpointGatewayRuntime.peers[nodeID] = existing
			return false
		}
	}
	endpointGatewayRuntime.peers[nodeID] = gatewayPeerInfo{
		NodeID:   nodeID,
		Addr:     addr,
		LastSeen: now,
	}
	return true
}

func upsertGatewayTargetRouteLocked(target, nextHopNodeID, nextHopAddr string, hop int, now time.Time) bool {
	target = normalizeGatewayAddress(target)
	nextHopNodeID = normalizeGatewayNodeID(nextHopNodeID)
	nextHopAddr = normalizeGatewayAddress(nextHopAddr)
	if target == "" || nextHopNodeID == "" || nextHopAddr == "" {
		return false
	}
	if hop <= 0 {
		hop = 1
	}
	if hop > maxGatewayHopLimit {
		return false
	}
	if _, direct := endpointGatewayRuntime.directTargets[target]; direct {
		return false
	}

	existing, exists := endpointGatewayRuntime.targetRoutes[target]
	if exists {
		if existing.NextHopNodeID == nextHopNodeID {
			existing.NextHopAddr = nextHopAddr
			existing.Hop = hop
			existing.LastSeen = now
			endpointGatewayRuntime.targetRoutes[target] = existing
			return false
		}
		if existing.Hop < hop && now.Sub(existing.LastSeen) <= gatewayPeerRouteTTL/2 {
			return false
		}
	}

	endpointGatewayRuntime.targetRoutes[target] = gatewayTargetRoute{
		Target:        target,
		NextHopNodeID: nextHopNodeID,
		NextHopAddr:   nextHopAddr,
		Hop:           hop,
		LastSeen:      now,
	}
	return true
}

func invalidateGatewayNodeAndRoutes(nodeID string) int {
	nodeID = normalizeGatewayNodeID(nodeID)
	if nodeID == "" {
		return 0
	}
	removed := 0
	endpointGatewayRuntime.mu.Lock()
	if _, exists := endpointGatewayRuntime.peers[nodeID]; exists {
		delete(endpointGatewayRuntime.peers, nodeID)
		delete(endpointGatewayRuntime.peerMetrics, nodeID)
		removed++
	}
	for target, route := range endpointGatewayRuntime.targetRoutes {
		if normalizeGatewayNodeID(route.NextHopNodeID) == nodeID {
			delete(endpointGatewayRuntime.targetRoutes, target)
			removed++
		}
	}
	endpointGatewayRuntime.mu.Unlock()
	return removed
}

func currentGatewayTokenAndNodeID() (string, string) {
	endpointGatewayRuntime.mu.Lock()
	defer endpointGatewayRuntime.mu.Unlock()
	return strings.TrimSpace(endpointGatewayRuntime.token), normalizeGatewayNodeID(endpointGatewayRuntime.nodeID)
}

func currentGatewayIdentity() (string, string) {
	token, nodeID := currentGatewayTokenAndNodeID()
	return token, nodeID
}

func isLocalGatewayAddress(addr string) bool {
	addr = normalizeGatewayAddress(addr)
	if addr == "" {
		return false
	}
	endpointGatewayRuntime.mu.Lock()
	defer endpointGatewayRuntime.mu.Unlock()
	return sameGatewayAddress(addr, endpointGatewayRuntime.listenAddr)
}

func buildGatewayAnnounceAddr(listenAddr string, responderIP net.IP) string {
	listenAddr = strings.TrimSpace(listenAddr)
	if _, port, err := net.SplitHostPort(listenAddr); err == nil {
		if responderIP != nil && !responderIP.IsUnspecified() {
			return net.JoinHostPort(responderIP.String(), port)
		}
		return listenAddr
	}
	return listenAddr
}

func discoverGatewayAddress(discoverPort int, token string) (string, error) {
	if discoverPort <= 0 {
		return "", errors.New("invalid discovery port")
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return "", err
	}
	request := gatewayDiscoverMagic
	if strings.TrimSpace(token) != "" {
		request = request + " " + strings.TrimSpace(token)
	}
	request += "\n"
	_, err = conn.WriteToUDP([]byte(request), &net.UDPAddr{IP: net.IPv4bcast, Port: discoverPort})
	if err != nil {
		return "", err
	}

	buf := make([]byte, 4096)
	for {
		n, remoteAddr, readErr := conn.ReadFromUDP(buf)
		if readErr != nil {
			return "", readErr
		}
		resp := strings.TrimSpace(string(buf[:n]))
		if strings.HasPrefix(resp, gatewayAnnounceMagic+" ") {
			announceAddr := strings.TrimSpace(strings.TrimPrefix(resp, gatewayAnnounceMagic))
			if announceAddr == "" {
				continue
			}
			return normalizeGatewayAddress(announceAddr), nil
		}
		if strings.HasPrefix(resp, gatewayPeerMagic+" ") {
			_ = applyGatewayPeerAnnounce(resp, remoteAddr)
			continue
		}
	}
}

func normalizeGatewayAddress(addr string) string {
	return normalizeServerAddressForSession(strings.TrimSpace(addr))
}

func normalizeGatewayNodeID(id string) string {
	return strings.TrimSpace(id)
}

func parseGatewayPath(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	items := strings.Split(raw, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		nodeID := normalizeGatewayNodeID(item)
		if nodeID == "" {
			continue
		}
		out = append(out, nodeID)
	}
	return out
}

func normalizeGatewayPath(path []string) []string {
	if len(path) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(path))
	out := make([]string, 0, len(path))
	for _, nodeID := range path {
		n := normalizeGatewayNodeID(nodeID)
		if n == "" {
			continue
		}
		if _, exists := seen[n]; exists {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

func appendGatewayPath(path []string, nodeID string) []string {
	nodeID = normalizeGatewayNodeID(nodeID)
	if nodeID == "" {
		return normalizeGatewayPath(path)
	}
	if gatewayPathContains(path, nodeID) {
		return normalizeGatewayPath(path)
	}
	out := normalizeGatewayPath(path)
	out = append(out, nodeID)
	return out
}

func gatewayPathContains(path []string, nodeID string) bool {
	nodeID = normalizeGatewayNodeID(nodeID)
	if nodeID == "" {
		return false
	}
	for _, hop := range path {
		if normalizeGatewayNodeID(hop) == nodeID {
			return true
		}
	}
	return false
}

func sameGatewayAddress(a, b string) bool {
	na := normalizeGatewayAddress(a)
	nb := normalizeGatewayAddress(b)
	if na == "" || nb == "" {
		return false
	}
	return strings.EqualFold(na, nb)
}

func encodeGatewayField(v string) string {
	return url.QueryEscape(strings.TrimSpace(v))
}

func decodeGatewayField(v string) string {
	decoded, err := url.QueryUnescape(strings.TrimSpace(v))
	if err != nil {
		return strings.TrimSpace(v)
	}
	return strings.TrimSpace(decoded)
}
