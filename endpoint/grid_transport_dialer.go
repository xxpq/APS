package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	neturl "net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

type quicStreamConn struct {
	conn   *quic.Conn
	stream *quic.Stream
}

func (q *quicStreamConn) Read(p []byte) (int, error)         { return q.stream.Read(p) }
func (q *quicStreamConn) Write(p []byte) (int, error)        { return q.stream.Write(p) }
func (q *quicStreamConn) LocalAddr() net.Addr                { return q.conn.LocalAddr() }
func (q *quicStreamConn) RemoteAddr() net.Addr               { return q.conn.RemoteAddr() }
func (q *quicStreamConn) SetDeadline(t time.Time) error      { return q.stream.SetDeadline(t) }
func (q *quicStreamConn) SetReadDeadline(t time.Time) error  { return q.stream.SetReadDeadline(t) }
func (q *quicStreamConn) SetWriteDeadline(t time.Time) error { return q.stream.SetWriteDeadline(t) }

func (q *quicStreamConn) Close() error {
	_ = q.stream.Close()
	return q.conn.CloseWithError(0, "")
}

type gridDialAttempt struct {
	name string
	addr string
	run  func(ctx context.Context) (net.Conn, error)
}

type gridDialResult struct {
	name string
	addr string
	conn net.Conn
	err  error
	rtt  time.Duration
}

const gridMaxICEAttemptCandidates = 3

type gridICEProbeTarget struct {
	addr           string
	network        string
	candidateType  string
	role           string
	remotePriority uint64
	localPriority  uint64
}

func dialGridBackendWithPolicy(finalHost string, finalPort int, finalTLS bool, payload ProxyConnectPayload) (net.Conn, string, error) {
	finalHost = strings.TrimSpace(finalHost)
	if finalHost == "" || finalPort <= 0 {
		return nil, "", errors.New("invalid final target")
	}

	enableQUIC := payload.GridEnableQUIC
	enableTCP := payload.GridEnableTCP
	enableICE := payload.GridEnableICE
	parallel := payload.GridParallel

	if !enableQUIC && !enableTCP {
		enableTCP = true
	}
	attemptTimeout := gridDialAttemptTimeout()
	selectionWindow := gridDialSelectionWindow()
	qosPolicy := gridDialQoSPolicy()

	attempts := make([]gridDialAttempt, 0, 4)
	if enableICE {
		iceCandidates := append([]string(nil), payload.GridICECandidates...)
		iceCandidates = append(iceCandidates, currentEndpointGridICESessionCandidates()...)
		if len(iceCandidates) == 0 {
			iceCandidates = []string{net.JoinHostPort(finalHost, strconv.Itoa(finalPort))}
		}
		iceCandidates = dedupeGridDialCandidates(iceCandidates)
		candidatePorts := gridCandidatePorts(finalPort)
		if upnpCandidates := gridUPnPCandidatesForPorts(candidatePorts); len(upnpCandidates) > 0 {
			iceCandidates = append(iceCandidates, upnpCandidates...)
		}
		turnUser, turnPass := currentEndpointGridICESessionAuth()
		iceTargetsByAddr := make(map[string]gridICEProbeTarget, len(iceCandidates)*2)
		addICETarget := func(host string, port int, network string, candidateType string, remotePriority uint64, role string) {
			host = strings.TrimSpace(host)
			if host == "" || port <= 0 {
				return
			}
			addr := net.JoinHostPort(host, strconv.Itoa(port))
			target := gridICEProbeTarget{
				addr:           addr,
				network:        normalizeGridICETransport(network),
				candidateType:  normalizeGridICECandidateType(candidateType),
				role:           normalizeGridICERole(role),
				remotePriority: remotePriority,
				localPriority:  gridICELocalPriority(candidateType, role),
			}
			if target.remotePriority == 0 {
				target.remotePriority = gridICEDefaultPriority(target.candidateType)
			}
			if target.localPriority == 0 {
				target.localPriority = gridICEDefaultPriority(target.candidateType)
			}
			if existing, exists := iceTargetsByAddr[addr]; exists {
				existingScore := gridICEProbeResultScore(existing, false, 0)
				targetScore := gridICEProbeResultScore(target, false, 0)
				if targetScore > existingScore {
					iceTargetsByAddr[addr] = target
				}
				return
			}
			iceTargetsByAddr[addr] = target
		}
		for _, candidate := range iceCandidates {
			if turnServer, ok := parseGridTURNServerCandidate(candidate, turnUser, turnPass); ok {
				relayCandidates := discoverEndpointGridTURNCandidates([]string{candidate}, turnServer.Username, turnServer.Password, candidatePorts, gridICEProbeTimeout())
				for _, relayCandidate := range relayCandidates {
					descriptor, parsed := parseGridICECandidateDescriptor(relayCandidate, finalPort)
					if !parsed {
						continue
					}
					addICETarget(descriptor.host, descriptor.port, turnServer.Network, "relay", gridICEDefaultPriority("relay"), "relay")
				}
				continue
			}
			if stunHost, stunPort, ok := parseGridSTUNServerCandidate(candidate); ok {
				mappedHost, mappedPort, stunErr := discoverGridSTUNMappedAddress(net.JoinHostPort(stunHost, strconv.Itoa(stunPort)), gridICEProbeTimeout())
				if stunErr == nil && mappedHost != "" {
					ports := append([]int{mappedPort}, candidatePorts...)
					ports = normalizeGridCandidatePorts(ports)
					for _, port := range ports {
						addICETarget(mappedHost, port, "udp", "srflx", gridICEDefaultPriority("srflx"), "peer")
					}
				}
				continue
			}
			host, candidatePort, ok := parseGridICECandidate(candidate, finalPort)
			if !ok {
				continue
			}
			descriptor, _ := parseGridICECandidateDescriptor(candidate, finalPort)
			ports := append([]int{candidatePort}, candidatePorts...)
			ports = normalizeGridCandidatePorts(ports)
			for _, port := range ports {
				addICETarget(host, port, descriptor.transport, descriptor.candidateType, descriptor.priority, descriptor.role)
			}
		}
		iceTargets := make([]gridICEProbeTarget, 0, len(iceTargetsByAddr))
		for _, target := range iceTargetsByAddr {
			iceTargets = append(iceTargets, target)
		}
		iceAttemptAddrs := orderGridICEProbeTargetsByConnectivity(iceTargets, gridICEProbeTimeout())
		if len(iceAttemptAddrs) > gridMaxICEAttemptCandidates {
			iceAttemptAddrs = iceAttemptAddrs[:gridMaxICEAttemptCandidates]
		}
		for _, addr := range iceAttemptAddrs {
			addr := addr
			attempts = append(attempts, gridDialAttempt{
				name: "ice",
				addr: addr,
				run: func(ctx context.Context) (net.Conn, error) {
					d := &net.Dialer{}
					return d.DialContext(ctx, "tcp", addr)
				},
			})
		}
	}

	if enableQUIC && finalTLS {
		addr := net.JoinHostPort(finalHost, strconv.Itoa(finalPort))
		attempts = append(attempts, gridDialAttempt{
			name: "quic",
			addr: addr,
			run: func(ctx context.Context) (net.Conn, error) {
				return dialGridQUIC(ctx, finalHost, finalPort)
			},
		})
	}

	if enableTCP {
		addr := net.JoinHostPort(finalHost, strconv.Itoa(finalPort))
		attempts = append(attempts, gridDialAttempt{
			name: "tcp",
			addr: addr,
			run: func(ctx context.Context) (net.Conn, error) {
				d := &net.Dialer{}
				return d.DialContext(ctx, "tcp", addr)
			},
		})
	}

	if len(attempts) == 0 {
		return nil, "", errors.New("no transport attempts available")
	}

	if !parallel || len(attempts) == 1 {
		var lastErr error
		for _, attempt := range attempts {
			ctx, cancel := context.WithTimeout(context.Background(), attemptTimeout)
			started := time.Now()
			conn, err := attempt.run(ctx)
			cancel()
			if err == nil {
				DebugLog("[GRID-DIAL] selected transport=%s addr=%s rtt_ms=%d policy=%s", attempt.name, attempt.addr, time.Since(started).Milliseconds(), qosPolicy)
				return conn, attempt.name, nil
			}
			lastErr = err
		}
		return nil, "", fmt.Errorf("all transport attempts failed: %w", lastErr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	results := make(chan gridDialResult, len(attempts))
	for _, attempt := range attempts {
		attempt := attempt
		go func() {
			runCtx, runCancel := context.WithTimeout(ctx, attemptTimeout)
			defer runCancel()
			started := time.Now()
			conn, err := attempt.run(runCtx)
			results <- gridDialResult{name: attempt.name, addr: attempt.addr, conn: conn, err: err, rtt: time.Since(started)}
		}()
	}

	var (
		lastErr   error
		successes []gridDialResult
		received  int
		firstAt   time.Time
	)
	for received < len(attempts) {
		res := <-results
		received++
		if res.err == nil && res.conn != nil {
			successes = append(successes, res)
			if firstAt.IsZero() {
				firstAt = time.Now()
				if qosPolicy == "latency" {
					break
				}
			}
			if !firstAt.IsZero() && time.Since(firstAt) >= selectionWindow {
				break
			}
			continue
		}
		lastErr = res.err
	}
	if len(successes) == 0 {
		return nil, "", fmt.Errorf("all parallel transport attempts failed: %w", lastErr)
	}

	cancel()
	winner := selectBestGridDialResult(successes, qosPolicy)
	DebugLog("[GRID-DIAL] selected transport=%s addr=%s rtt_ms=%d policy=%s", winner.name, winner.addr, winner.rtt.Milliseconds(), qosPolicy)

	for _, res := range successes {
		if res.conn != nil && res.conn != winner.conn {
			_ = res.conn.Close()
		}
	}

	go func() {
		remaining := len(attempts) - received
		for i := 0; i < remaining; i++ {
			res := <-results
			if res.err == nil && res.conn != nil {
				if res.conn != winner.conn {
					_ = res.conn.Close()
				}
			}
		}
	}()

	return winner.conn, winner.name, nil
}

func dedupeGridDialCandidates(candidates []string) []string {
	if len(candidates) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(candidates))
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		c := strings.TrimSpace(candidate)
		if c == "" {
			continue
		}
		if _, exists := seen[c]; exists {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

type gridICECandidateDescriptor struct {
	host          string
	port          int
	transport     string
	candidateType string
	priority      uint64
	role          string
}

func parseGridICECandidate(candidate string, defaultPort int) (string, int, bool) {
	descriptor, ok := parseGridICECandidateDescriptor(candidate, defaultPort)
	if !ok {
		return "", 0, false
	}
	return descriptor.host, descriptor.port, true
}

func parseGridICECandidateDescriptor(candidate string, defaultPort int) (gridICECandidateDescriptor, bool) {
	candidate = strings.TrimSpace(strings.TrimPrefix(candidate, "a="))
	if candidate == "" {
		return gridICECandidateDescriptor{}, false
	}

	descriptor := gridICECandidateDescriptor{
		transport:     "tcp",
		candidateType: "host",
		role:          "peer",
	}

	lowerCandidate := strings.ToLower(candidate)
	if strings.HasPrefix(lowerCandidate, "candidate:") {
		fields := strings.Fields(candidate)
		// RFC 5245 candidate format:
		// candidate:<foundation> <component-id> <transport> <priority> <connection-address> <port> typ ...
		if len(fields) >= 6 {
			descriptor.host = strings.TrimSpace(fields[4])
			descriptor.transport = normalizeGridICETransport(strings.TrimSpace(fields[2]))
			port, convErr := strconv.Atoi(strings.TrimSpace(fields[5]))
			if convErr == nil && descriptor.host != "" && port > 0 {
				descriptor.port = port
			}
			if prio, err := strconv.ParseUint(strings.TrimSpace(fields[3]), 10, 64); err == nil {
				descriptor.priority = prio
			}
			for idx := 6; idx+1 < len(fields); idx++ {
				key := strings.ToLower(strings.TrimSpace(fields[idx]))
				value := strings.TrimSpace(fields[idx+1])
				switch key {
				case "typ":
					descriptor.candidateType = value
					idx++
				case "role":
					descriptor.role = value
					idx++
				}
			}
			descriptor.candidateType = normalizeGridICECandidateType(descriptor.candidateType)
			descriptor.role = normalizeGridICERole(descriptor.role)
			if descriptor.priority == 0 {
				descriptor.priority = gridICEDefaultPriority(descriptor.candidateType)
			}
			return descriptor, descriptor.host != "" && descriptor.port > 0
		}
	}

	if strings.Contains(candidate, "://") {
		if parsed, err := neturl.Parse(candidate); err == nil {
			descriptor.host = strings.TrimSpace(parsed.Hostname())
			if descriptor.host == "" {
				return gridICECandidateDescriptor{}, false
			}
			if p := strings.TrimSpace(parsed.Port()); p != "" {
				port, convErr := strconv.Atoi(p)
				if convErr != nil || port <= 0 {
					return gridICECandidateDescriptor{}, false
				}
				descriptor.port = port
			} else {
				descriptor.port = defaultPort
			}
			descriptor.transport = normalizeGridICETransport(strings.TrimSpace(parsed.Query().Get("transport")))
			if descriptor.transport == "" || descriptor.transport == "tcp" {
				switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
				case "udp":
					descriptor.transport = "udp"
				case "stun", "stuns":
					descriptor.transport = "udp"
				case "turn":
					if strings.EqualFold(strings.TrimSpace(parsed.Query().Get("transport")), "udp") {
						descriptor.transport = "udp"
					}
				}
			}
			query := parsed.Query()
			if v := strings.TrimSpace(query.Get("priority")); v != "" {
				if prio, err := strconv.ParseUint(v, 10, 64); err == nil {
					descriptor.priority = prio
				}
			}
			if descriptor.priority == 0 {
				if v := strings.TrimSpace(query.Get("prio")); v != "" {
					if prio, err := strconv.ParseUint(v, 10, 64); err == nil {
						descriptor.priority = prio
					}
				}
			}
			if typ := strings.TrimSpace(query.Get("type")); typ != "" {
				descriptor.candidateType = typ
			} else if typ := strings.TrimSpace(query.Get("typ")); typ != "" {
				descriptor.candidateType = typ
			} else {
				switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
				case "turn", "turns":
					descriptor.candidateType = "relay"
					descriptor.role = "relay"
				case "stun":
					descriptor.candidateType = "srflx"
				}
			}
			if role := strings.TrimSpace(query.Get("role")); role != "" {
				descriptor.role = role
			}
			descriptor.candidateType = normalizeGridICECandidateType(descriptor.candidateType)
			descriptor.role = normalizeGridICERole(descriptor.role)
			if descriptor.priority == 0 {
				descriptor.priority = gridICEDefaultPriority(descriptor.candidateType)
			}
			return descriptor, descriptor.port > 0
		}
	}

	host, portStr, err := net.SplitHostPort(candidate)
	if err == nil {
		port, convErr := strconv.Atoi(portStr)
		if convErr != nil || port <= 0 {
			return gridICECandidateDescriptor{}, false
		}
		descriptor.host = strings.Trim(strings.TrimSpace(host), "[]")
		descriptor.port = port
		descriptor.transport = "tcp"
		descriptor.candidateType = normalizeGridICECandidateType(descriptor.candidateType)
		descriptor.role = normalizeGridICERole(descriptor.role)
		descriptor.priority = gridICEDefaultPriority(descriptor.candidateType)
		return descriptor, descriptor.host != ""
	}

	descriptor.host = strings.TrimSpace(candidate)
	descriptor.port = defaultPort
	descriptor.transport = "tcp"
	descriptor.candidateType = normalizeGridICECandidateType(descriptor.candidateType)
	descriptor.role = normalizeGridICERole(descriptor.role)
	descriptor.priority = gridICEDefaultPriority(descriptor.candidateType)
	return descriptor, descriptor.host != "" && descriptor.port > 0
}

func dialGridQUIC(ctx context.Context, host string, port int) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3", "aps-grid"},
		ServerName:         host,
	}
	quicConn, err := quic.DialAddr(ctx, addr, tlsCfg, &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	stream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		_ = quicConn.CloseWithError(0, "open stream failed")
		return nil, err
	}
	return &quicStreamConn{conn: quicConn, stream: stream}, nil
}

func gridDialQoSPolicy() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("APS_GRID_QOS_POLICY"))) {
	case "latency":
		return "latency"
	case "reliability":
		return "reliability"
	default:
		return "balanced"
	}
}

func gridDialAttemptTimeout() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("APS_GRID_DIAL_TIMEOUT_MS")); raw != "" {
		if ms, err := strconv.Atoi(raw); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return 8 * time.Second
}

func gridDialSelectionWindow() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("APS_GRID_SELECTION_WINDOW_MS")); raw != "" {
		if ms, err := strconv.Atoi(raw); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return 180 * time.Millisecond
}

func gridICEProbeTimeout() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("APS_GRID_ICE_PROBE_TIMEOUT_MS")); raw != "" {
		if ms, err := strconv.Atoi(raw); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return 700 * time.Millisecond
}

func gridCandidatePorts(defaultPort int) []int {
	ports := []int{defaultPort, 443, 8443, 3478, 5349}
	ports = append(ports, parseGridPortList(os.Getenv("APS_GRID_ICE_PORTS"))...)
	return normalizeGridCandidatePorts(ports)
}

func parseGridPortList(raw string) []int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	items := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	out := make([]int, 0, len(items))
	for _, item := range items {
		if item == "" {
			continue
		}
		port, err := strconv.Atoi(strings.TrimSpace(item))
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		out = append(out, port)
	}
	return out
}

func normalizeGridCandidatePorts(ports []int) []int {
	if len(ports) == 0 {
		return nil
	}
	seen := make(map[int]struct{}, len(ports))
	out := make([]int, 0, len(ports))
	for _, port := range ports {
		if port <= 0 || port > 65535 {
			continue
		}
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	return out
}

func selectBestGridDialResult(results []gridDialResult, qosPolicy string) gridDialResult {
	if len(results) == 0 {
		return gridDialResult{}
	}
	best := results[0]
	bestScore := gridDialQoSScore(best, qosPolicy)
	for i := 1; i < len(results); i++ {
		score := gridDialQoSScore(results[i], qosPolicy)
		if score > bestScore {
			best = results[i]
			bestScore = score
		}
	}
	return best
}

func gridDialQoSScore(res gridDialResult, qosPolicy string) float64 {
	rttMs := float64(res.rtt.Milliseconds())
	if rttMs <= 0 {
		rttMs = 1
	}
	transportScore := gridDialTransportReliabilityScore(res.name)
	switch qosPolicy {
	case "latency":
		return -rttMs
	case "reliability":
		return transportScore*1000 - rttMs
	default:
		return transportScore*200 - rttMs
	}
}

func gridDialTransportReliabilityScore(transport string) float64 {
	switch strings.TrimSpace(strings.ToLower(transport)) {
	case "tcp":
		return 1.00
	case "quic":
		return 0.96
	case "ice":
		return 0.90
	default:
		return 0.80
	}
}

func orderGridICEAddressesByConnectivity(addresses []string, probeTimeout time.Duration) []string {
	targets := make([]gridICEProbeTarget, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for _, addr := range addresses {
		normalized := strings.TrimSpace(addr)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		targets = append(targets, gridICEProbeTarget{
			addr:           normalized,
			network:        "tcp",
			candidateType:  "host",
			role:           "peer",
			remotePriority: gridICEDefaultPriority("host"),
			localPriority:  gridICEDefaultPriority("host"),
		})
	}
	return orderGridICEProbeTargetsByConnectivity(targets, probeTimeout)
}

func orderGridICEProbeTargetsByConnectivity(candidates []gridICEProbeTarget, probeTimeout time.Duration) []string {
	if len(candidates) <= 1 {
		if len(candidates) == 1 {
			return []string{candidates[0].addr}
		}
		return nil
	}
	type probeResult struct {
		target       gridICEProbeTarget
		rtt          time.Duration
		ok           bool
		pairPriority uint64
		score        float64
	}
	results := make([]probeResult, 0, len(candidates))
	resultsCh := make(chan probeResult, len(candidates))
	var wg sync.WaitGroup
	for _, target := range candidates {
		target := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, rtt := probeGridICEConnectivity(target, probeTimeout)
			if !ok {
				resultsCh <- probeResult{
					target:       target,
					ok:           false,
					pairPriority: gridICEPairPriority(target.localPriority, target.remotePriority, gridICEIsControlling()),
					score:        gridICEProbeResultScore(target, false, 0),
				}
				return
			}
			resultsCh <- probeResult{
				target:       target,
				ok:           true,
				rtt:          rtt,
				pairPriority: gridICEPairPriority(target.localPriority, target.remotePriority, gridICEIsControlling()),
				score:        gridICEProbeResultScore(target, true, rtt),
			}
		}()
	}
	wg.Wait()
	close(resultsCh)
	for res := range resultsCh {
		results = append(results, res)
	}
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].score == results[j].score {
			if results[i].ok != results[j].ok {
				return results[i].ok
			}
			if results[i].ok && results[i].rtt != results[j].rtt {
				return results[i].rtt < results[j].rtt
			}
			if results[i].pairPriority != results[j].pairPriority {
				return results[i].pairPriority > results[j].pairPriority
			}
			return results[i].target.addr < results[j].target.addr
		}
		return results[i].score > results[j].score
	})

	out := make([]string, 0, len(results))
	seenOut := make(map[string]struct{}, len(results))
	for _, res := range results {
		if _, exists := seenOut[res.target.addr]; exists {
			continue
		}
		seenOut[res.target.addr] = struct{}{}
		out = append(out, res.target.addr)
	}
	return out
}

func probeGridICEConnectivity(target gridICEProbeTarget, timeout time.Duration) (bool, time.Duration) {
	network := normalizeGridICETransport(target.network)
	start := time.Now()
	if network == "udp" {
		if probeGridICEUDP(target.addr, timeout) {
			return true, time.Since(start)
		}
		return false, 0
	}
	conn, err := net.DialTimeout("tcp", target.addr, timeout)
	if err != nil {
		return false, 0
	}
	_ = conn.Close()
	return true, time.Since(start)
}

func probeGridICEUDP(addr string, timeout time.Duration) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	target, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return false
	}
	conn, err := net.DialUDP("udp", nil, target)
	if err != nil {
		return false
	}
	defer conn.Close()
	if timeout <= 0 {
		timeout = 700 * time.Millisecond
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false
	}
	txID := make([]byte, 12)
	if _, err := rand.Read(txID); err != nil {
		return false
	}
	req := buildSTUNBindingRequest(txID)
	if _, err := conn.Write(req); err != nil {
		return false
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}
	_, _, parseErr := parseSTUNBindingResponse(buf[:n], txID)
	return parseErr == nil
}

func normalizeGridICECandidateType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "host":
		return "host"
	case "srflx", "server-reflexive":
		return "srflx"
	case "prflx", "peer-reflexive":
		return "prflx"
	case "relay", "relayed":
		return "relay"
	default:
		return "host"
	}
}

func normalizeGridICETransport(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "udp", "udp4", "udp6":
		return "udp"
	case "tcp", "tcp4", "tcp6", "":
		return "tcp"
	default:
		return "tcp"
	}
}

func normalizeGridICERole(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "relay", "aps":
		return "relay"
	case "gateway":
		return "gateway"
	case "local":
		return "local"
	case "peer", "":
		return "peer"
	default:
		return "peer"
	}
}

func gridICEDefaultPriority(candidateType string) uint64 {
	switch normalizeGridICECandidateType(candidateType) {
	case "host":
		return uint64(126 << 24)
	case "prflx":
		return uint64(110 << 24)
	case "srflx":
		return uint64(100 << 24)
	case "relay":
		return uint64(16 << 24)
	default:
		return uint64(80 << 24)
	}
}

func gridICELocalPriority(candidateType, role string) uint64 {
	base := gridICEDefaultPriority(candidateType)
	switch normalizeGridICERole(role) {
	case "local":
		base += uint64(8 << 20)
	case "relay":
		if base > uint64(4<<20) {
			base -= uint64(4 << 20)
		}
	}
	return base
}

func gridICEIsControlling() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("APS_GRID_ICE_ROLE"))) {
	case "controlled":
		return false
	default:
		return true
	}
}

func gridICEPairPriority(localPriority, remotePriority uint64, controlling bool) uint64 {
	if localPriority == 0 {
		localPriority = 1
	}
	if remotePriority == 0 {
		remotePriority = 1
	}
	minP := localPriority
	maxP := remotePriority
	if minP > maxP {
		minP, maxP = maxP, minP
	}
	tie := uint64(0)
	if controlling {
		if localPriority > remotePriority {
			tie = 1
		}
	} else if remotePriority > localPriority {
		tie = 1
	}
	return (minP << 32) + (maxP << 1) + tie
}

func gridICECandidateTypeWeight(candidateType string) float64 {
	switch normalizeGridICECandidateType(candidateType) {
	case "host":
		return 1.00
	case "prflx":
		return 0.93
	case "srflx":
		return 0.88
	case "relay":
		return 0.70
	default:
		return 0.80
	}
}

func gridICERoleWeight(role string) float64 {
	switch normalizeGridICERole(role) {
	case "local":
		return 1.00
	case "peer":
		return 0.95
	case "gateway":
		return 0.85
	case "relay":
		return 0.75
	default:
		return 0.85
	}
}

func gridICEProbeResultScore(target gridICEProbeTarget, reachable bool, rtt time.Duration) float64 {
	pairPriority := gridICEPairPriority(target.localPriority, target.remotePriority, gridICEIsControlling())
	pairScore := float64(pairPriority) / 1_000_000_000_000_000
	typeScore := gridICECandidateTypeWeight(target.candidateType) * 100
	roleScore := gridICERoleWeight(target.role) * 30
	if !reachable {
		return -1_000_000 + pairScore + typeScore + roleScore
	}
	rttMs := float64(rtt.Milliseconds())
	if rttMs <= 0 {
		rttMs = 1
	}
	return 1_000_000 + pairScore + typeScore + roleScore - rttMs
}
