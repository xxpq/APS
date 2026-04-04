package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	neturl "net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	turnAllocateRequestType uint16 = 0x0003
	turnAllocateSuccessType uint16 = 0x0103
	turnAllocateErrorType   uint16 = 0x0113
	turnRefreshRequestType  uint16 = 0x0004
	turnRefreshSuccessType  uint16 = 0x0104
	turnRefreshErrorType    uint16 = 0x0114

	turnAttrUsername           uint16 = 0x0006
	turnAttrMessageIntegrity   uint16 = 0x0008
	turnAttrErrorCode          uint16 = 0x0009
	turnAttrLifetime           uint16 = 0x000D
	turnAttrRealm              uint16 = 0x0014
	turnAttrNonce              uint16 = 0x0015
	turnAttrXORRelayedAddress  uint16 = 0x0016
	turnAttrRequestedTransport uint16 = 0x0019
	turnAttrFingerprint        uint16 = 0x8028

	turnTransportUDP byte = 17
	turnTransportTCP byte = 6
)

var errTURNStaleNonce = errors.New("turn stale nonce")

type turnServerCandidate struct {
	ServerAddr string
	ServerHost string
	Username   string
	Password   string
	Network    string
	UseTLS     bool
}

type turnCandidateTransport struct {
	network string
	useTLS  bool
}

type turnAttribute struct {
	Type  uint16
	Value []byte
}

type turnMessage struct {
	Type  uint16
	TxID  [12]byte
	Attrs map[uint16][]byte
}

type endpointTURNAllocation struct {
	key      string
	conn     net.Conn
	server   string
	isStream bool
	username string
	password string

	mu        sync.Mutex
	realm     string
	nonce     string
	relayIP   string
	relayPort int
	lifetime  time.Duration
	expires   time.Time
	closed    bool
}

var endpointTURNState = struct {
	mu      sync.Mutex
	entries map[string]*endpointTURNAllocation
}{
	entries: make(map[string]*endpointTURNAllocation),
}

func parseGridTURNServerCandidate(raw, defaultUsername, defaultPassword string) (turnServerCandidate, bool) {
	candidates := parseGridTURNServerCandidates(raw, defaultUsername, defaultPassword)
	if len(candidates) == 0 {
		return turnServerCandidate{}, false
	}
	return candidates[0], true
}

func parseGridTURNServerCandidates(raw, defaultUsername, defaultPassword string) []turnServerCandidate {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return nil
	}
	lower := strings.ToLower(candidate)
	if !strings.HasPrefix(lower, "turn:") && !strings.HasPrefix(lower, "turns:") {
		return nil
	}

	normalized := candidate
	if !strings.Contains(normalized, "://") {
		if idx := strings.Index(normalized, ":"); idx > 0 {
			normalized = normalized[:idx] + "://" + strings.TrimPrefix(normalized[idx+1:], "//")
		}
	}
	parsed, err := neturl.Parse(normalized)
	if err != nil {
		return nil
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme != "turn" && scheme != "turns" {
		return nil
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return nil
	}
	port := 3478
	if scheme == "turns" {
		port = 5349
	}
	if parsed.Port() != "" {
		p, convErr := strconv.Atoi(strings.TrimSpace(parsed.Port()))
		if convErr != nil || p <= 0 || p > 65535 {
			return nil
		}
		port = p
	}
	transport := strings.ToLower(strings.TrimSpace(parsed.Query().Get("transport")))

	transports := make([]turnCandidateTransport, 0, 2)
	addTransport := func(network string, useTLS bool) {
		for _, existing := range transports {
			if existing.network == network && existing.useTLS == useTLS {
				return
			}
		}
		transports = append(transports, turnCandidateTransport{network: network, useTLS: useTLS})
	}

	switch scheme {
	case "turns":
		switch transport {
		case "", "tcp":
			addTransport("tcp", true)
		default:
			return nil
		}
	default:
		switch transport {
		case "":
			// Prefer UDP first, then fallback to TCP when UDP is blocked/unstable.
			addTransport("udp", false)
			addTransport("tcp", false)
		case "udp":
			addTransport("udp", false)
		case "tcp":
			addTransport("tcp", false)
		default:
			return nil
		}
	}

	username := strings.TrimSpace(defaultUsername)
	password := strings.TrimSpace(defaultPassword)
	if parsed.User != nil {
		if u := strings.TrimSpace(parsed.User.Username()); u != "" {
			username = u
		}
		if p, ok := parsed.User.Password(); ok && strings.TrimSpace(p) != "" {
			password = strings.TrimSpace(p)
		}
	}
	if username == "" || password == "" {
		return nil
	}

	serverAddr := net.JoinHostPort(host, strconv.Itoa(port))
	out := make([]turnServerCandidate, 0, len(transports))
	for _, tp := range transports {
		out = append(out, turnServerCandidate{
			ServerAddr: serverAddr,
			ServerHost: host,
			Username:   username,
			Password:   password,
			Network:    tp.network,
			UseTLS:     tp.useTLS,
		})
	}
	return out
}

func discoverEndpointGridTURNCandidates(seedCandidates []string, defaultUsername, defaultPassword string, _ []int, timeout time.Duration) []string {
	if len(seedCandidates) == 0 {
		return nil
	}
	if timeout <= 0 {
		timeout = 1200 * time.Millisecond
	}
	type candidateResult struct {
		relay string
		score float64
	}
	parsedServers := make([]turnServerCandidate, 0, len(seedCandidates)*2)
	for _, raw := range seedCandidates {
		parsedServers = append(parsedServers, parseGridTURNServerCandidates(raw, defaultUsername, defaultPassword)...)
	}
	if len(parsedServers) == 0 {
		return nil
	}

	results := make(chan candidateResult, len(parsedServers))
	var wg sync.WaitGroup
	for _, server := range parsedServers {
		server := server
		wg.Add(1)
		go func() {
			defer wg.Done()
			started := time.Now()
			alloc, err := getOrCreateEndpointTURNAllocation(server, timeout)
			if err != nil || alloc == nil {
				return
			}
			relay := alloc.relayCandidate()
			if relay == "" {
				return
			}
			rttMs := float64(time.Since(started).Milliseconds())
			if rttMs <= 0 {
				rttMs = 1
			}
			transportWeight := 0.90
			switch strings.ToLower(strings.TrimSpace(server.Network)) {
			case "udp":
				transportWeight = 1.00
			case "tcp":
				transportWeight = 0.95
			}
			if server.UseTLS {
				transportWeight += 0.02
			}
			results <- candidateResult{
				relay: relay,
				score: transportWeight*1000 - rttMs,
			}
		}()
	}
	wg.Wait()
	close(results)

	collected := make([]candidateResult, 0, len(parsedServers))
	for res := range results {
		collected = append(collected, res)
	}
	sort.SliceStable(collected, func(i, j int) bool {
		if collected[i].score == collected[j].score {
			return collected[i].relay < collected[j].relay
		}
		return collected[i].score > collected[j].score
	})

	seen := make(map[string]struct{}, len(collected))
	out := make([]string, 0, len(collected))
	for _, res := range collected {
		if res.relay == "" {
			continue
		}
		if _, exists := seen[res.relay]; exists {
			continue
		}
		seen[res.relay] = struct{}{}
		out = append(out, res.relay)
	}
	return out
}

func getOrCreateEndpointTURNAllocation(server turnServerCandidate, timeout time.Duration) (*endpointTURNAllocation, error) {
	key := strings.Join([]string{
		server.ServerAddr,
		server.Username,
		server.Password,
		strings.ToLower(strings.TrimSpace(server.Network)),
		strconv.FormatBool(server.UseTLS),
	}, "|")
	now := time.Now()

	endpointTURNState.mu.Lock()
	if existing := endpointTURNState.entries[key]; existing != nil && existing.isUsable(now) {
		endpointTURNState.mu.Unlock()
		return existing, nil
	}
	endpointTURNState.mu.Unlock()

	created, err := createEndpointTURNAllocation(key, server, timeout)
	if err != nil {
		return nil, err
	}

	endpointTURNState.mu.Lock()
	if existing := endpointTURNState.entries[key]; existing != nil && existing.isUsable(now) {
		endpointTURNState.mu.Unlock()
		created.close()
		return existing, nil
	}
	endpointTURNState.entries[key] = created
	endpointTURNState.mu.Unlock()

	go created.refreshLoop()
	return created, nil
}

func createEndpointTURNAllocation(key string, server turnServerCandidate, timeout time.Duration) (*endpointTURNAllocation, error) {
	conn, isStream, err := dialTURNServer(server, timeout)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()

	if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	realm, nonce, err := turnAllocateChallenge(conn, isStream, timeout)
	if err != nil {
		return nil, err
	}
	relayIP, relayPort, lifetime, refreshedNonce, err := turnAllocateWithCredentials(conn, isStream, server.Username, server.Password, realm, nonce, timeout)
	if err != nil {
		return nil, err
	}
	if refreshedNonce != "" {
		nonce = refreshedNonce
	}
	if lifetime < 30*time.Second {
		lifetime = 120 * time.Second
	}
	_ = conn.SetDeadline(time.Time{})

	return &endpointTURNAllocation{
		key:       key,
		conn:      conn,
		server:    server.ServerAddr,
		isStream:  isStream,
		username:  server.Username,
		password:  server.Password,
		realm:     realm,
		nonce:     nonce,
		relayIP:   relayIP,
		relayPort: relayPort,
		lifetime:  lifetime,
		expires:   time.Now().Add(lifetime),
	}, nil
}

func dialTURNServer(server turnServerCandidate, timeout time.Duration) (net.Conn, bool, error) {
	network := strings.TrimSpace(strings.ToLower(server.Network))
	if network == "" {
		network = "udp"
	}
	dialTimeout := timeout
	if dialTimeout <= 0 {
		dialTimeout = 3 * time.Second
	}

	baseConn, err := net.DialTimeout(network, server.ServerAddr, dialTimeout)
	if err != nil {
		return nil, false, err
	}
	isStream := network == "tcp"
	if !server.UseTLS {
		return baseConn, isStream, nil
	}

	host := strings.TrimSpace(server.ServerHost)
	if host == "" {
		host, _, _ = net.SplitHostPort(server.ServerAddr)
		host = strings.Trim(strings.TrimSpace(host), "[]")
	}
	tlsConn := tls.Client(baseConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		NextProtos:         []string{"turn"},
		MinVersion:         tls.VersionTLS12,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(dialTimeout))
	if err := tlsConn.Handshake(); err != nil {
		_ = baseConn.Close()
		return nil, false, err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, true, nil
}

func turnAllocateChallenge(conn net.Conn, isStream bool, timeout time.Duration) (string, string, error) {
	var txID [12]byte
	if _, err := rand.Read(txID[:]); err != nil {
		return "", "", err
	}
	req := buildTURNMessage(turnAllocateRequestType, txID, []turnAttribute{
		{Type: turnAttrRequestedTransport, Value: []byte{turnTransportUDP, 0, 0, 0}},
	}, nil)
	if _, err := conn.Write(req); err != nil {
		return "", "", err
	}
	msg, err := readTURNMessage(conn, isStream, timeout)
	if err != nil {
		return "", "", err
	}
	if msg.Type == turnAllocateSuccessType {
		// server allows unauthenticated allocate, no realm/nonce required
		return "", "", nil
	}
	if msg.Type != turnAllocateErrorType {
		return "", "", fmt.Errorf("unexpected turn allocate challenge response type=%#x", msg.Type)
	}
	code, _ := parseTURNErrorCode(msg.Attrs[turnAttrErrorCode])
	if code != 401 && code != 438 {
		return "", "", fmt.Errorf("turn allocate challenge failed code=%d", code)
	}
	realm := strings.TrimSpace(string(msg.Attrs[turnAttrRealm]))
	nonce := strings.TrimSpace(string(msg.Attrs[turnAttrNonce]))
	if realm == "" || nonce == "" {
		return "", "", errors.New("turn challenge missing realm/nonce")
	}
	return realm, nonce, nil
}

func turnAllocateWithCredentials(conn net.Conn, isStream bool, username, password, realm, nonce string, timeout time.Duration) (string, int, time.Duration, string, error) {
	key := deriveTURNLongTermKey(username, realm, password)
	attempt := func(currentNonce string) (string, int, time.Duration, string, error) {
		var txID [12]byte
		if _, err := rand.Read(txID[:]); err != nil {
			return "", 0, 0, "", err
		}
		attrs := []turnAttribute{
			{Type: turnAttrRequestedTransport, Value: []byte{turnTransportUDP, 0, 0, 0}},
			{Type: turnAttrUsername, Value: []byte(username)},
			{Type: turnAttrRealm, Value: []byte(realm)},
			{Type: turnAttrNonce, Value: []byte(currentNonce)},
			{Type: turnAttrLifetime, Value: encodeTURNLifetime(300)},
		}
		req := buildTURNMessage(turnAllocateRequestType, txID, attrs, key)
		if _, err := conn.Write(req); err != nil {
			return "", 0, 0, "", err
		}
		msg, err := readTURNMessage(conn, isStream, timeout)
		if err != nil {
			return "", 0, 0, "", err
		}
		if msg.Type == turnAllocateSuccessType {
			relayIP, relayPort, err := parseTURNXORAddress(msg.Attrs[turnAttrXORRelayedAddress], msg.TxID)
			if err != nil {
				return "", 0, 0, "", err
			}
			life := decodeTURNLifetime(msg.Attrs[turnAttrLifetime])
			return relayIP, relayPort, life, currentNonce, nil
		}
		if msg.Type != turnAllocateErrorType {
			return "", 0, 0, "", fmt.Errorf("unexpected turn allocate response type=%#x", msg.Type)
		}
		code, _ := parseTURNErrorCode(msg.Attrs[turnAttrErrorCode])
		if code == 438 {
			newNonce := strings.TrimSpace(string(msg.Attrs[turnAttrNonce]))
			if newNonce == "" {
				return "", 0, 0, "", errors.New("turn stale nonce without nonce attribute")
			}
			return "", 0, 0, newNonce, errTURNStaleNonce
		}
		return "", 0, 0, "", fmt.Errorf("turn allocate failed code=%d", code)
	}

	relayIP, relayPort, lifetime, resultingNonce, err := attempt(nonce)
	if err == nil {
		return relayIP, relayPort, lifetime, resultingNonce, nil
	}
	if !errors.Is(err, errTURNStaleNonce) {
		return "", 0, 0, "", err
	}
	relayIP, relayPort, lifetime, resultingNonce, err = attempt(resultingNonce)
	return relayIP, relayPort, lifetime, resultingNonce, err
}

func (a *endpointTURNAllocation) relayCandidate() string {
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.relayIP == "" || a.relayPort <= 0 {
		return ""
	}
	return net.JoinHostPort(a.relayIP, strconv.Itoa(a.relayPort))
}

func (a *endpointTURNAllocation) isUsable(now time.Time) bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.closed && a.conn != nil && a.relayIP != "" && a.relayPort > 0 && now.Before(a.expires.Add(-20*time.Second))
}

func (a *endpointTURNAllocation) close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	conn := a.conn
	a.conn = nil
	a.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (a *endpointTURNAllocation) refreshLoop() {
	for {
		a.mu.Lock()
		if a.closed || a.conn == nil {
			a.mu.Unlock()
			return
		}
		interval := a.lifetime / 2
		if interval < 20*time.Second {
			interval = 20 * time.Second
		}
		a.mu.Unlock()

		timer := time.NewTimer(interval)
		<-timer.C

		if err := a.refresh(2 * time.Second); err != nil {
			a.close()
			endpointTURNState.mu.Lock()
			if current := endpointTURNState.entries[a.key]; current == a {
				delete(endpointTURNState.entries, a.key)
			}
			endpointTURNState.mu.Unlock()
			return
		}
	}
}

func (a *endpointTURNAllocation) refresh(timeout time.Duration) error {
	a.mu.Lock()
	if a.closed || a.conn == nil {
		a.mu.Unlock()
		return errors.New("allocation closed")
	}
	username := a.username
	password := a.password
	realm := a.realm
	nonce := a.nonce
	conn := a.conn
	isStream := a.isStream
	a.mu.Unlock()
	if username == "" || password == "" || realm == "" || nonce == "" {
		return errors.New("missing turn allocation auth")
	}

	key := deriveTURNLongTermKey(username, realm, password)
	sendRefresh := func(currentNonce string) (string, time.Duration, error) {
		var txID [12]byte
		if _, err := rand.Read(txID[:]); err != nil {
			return "", 0, err
		}
		attrs := []turnAttribute{
			{Type: turnAttrUsername, Value: []byte(username)},
			{Type: turnAttrRealm, Value: []byte(realm)},
			{Type: turnAttrNonce, Value: []byte(currentNonce)},
			{Type: turnAttrLifetime, Value: encodeTURNLifetime(300)},
		}
		req := buildTURNMessage(turnRefreshRequestType, txID, attrs, key)
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return "", 0, err
		}
		if _, err := conn.Write(req); err != nil {
			return "", 0, err
		}
		msg, err := readTURNMessage(conn, isStream, timeout)
		if err != nil {
			return "", 0, err
		}
		if msg.Type == turnRefreshSuccessType {
			return currentNonce, decodeTURNLifetime(msg.Attrs[turnAttrLifetime]), nil
		}
		if msg.Type != turnRefreshErrorType {
			return "", 0, fmt.Errorf("unexpected turn refresh response type=%#x", msg.Type)
		}
		code, _ := parseTURNErrorCode(msg.Attrs[turnAttrErrorCode])
		if code == 438 {
			newNonce := strings.TrimSpace(string(msg.Attrs[turnAttrNonce]))
			if newNonce == "" {
				return "", 0, errors.New("turn refresh stale nonce without nonce")
			}
			return newNonce, 0, errTURNStaleNonce
		}
		return "", 0, fmt.Errorf("turn refresh failed code=%d", code)
	}

	newNonce, life, err := sendRefresh(nonce)
	if errors.Is(err, errTURNStaleNonce) {
		newNonce, life, err = sendRefresh(newNonce)
	}
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		return err
	}
	if life <= 0 {
		life = a.lifetime
	}
	a.mu.Lock()
	a.nonce = newNonce
	a.lifetime = life
	a.expires = time.Now().Add(life)
	a.mu.Unlock()
	return nil
}

func deriveTURNLongTermKey(username, realm, password string) []byte {
	sum := md5.Sum([]byte(username + ":" + realm + ":" + password))
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out
}

func buildTURNMessage(msgType uint16, txID [12]byte, attrs []turnAttribute, integrityKey []byte) []byte {
	encoded := encodeTURNAttributes(attrs)
	if len(integrityKey) == 0 {
		msg := make([]byte, 20+len(encoded))
		binary.BigEndian.PutUint16(msg[0:2], msgType)
		binary.BigEndian.PutUint16(msg[2:4], uint16(len(encoded)))
		binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
		copy(msg[8:20], txID[:])
		copy(msg[20:], encoded)
		return msg
	}

	totalLen := len(encoded) + 4 + 20
	msg := make([]byte, 20+totalLen)
	binary.BigEndian.PutUint16(msg[0:2], msgType)
	binary.BigEndian.PutUint16(msg[2:4], uint16(totalLen))
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], txID[:])
	copy(msg[20:], encoded)
	offset := 20 + len(encoded)
	binary.BigEndian.PutUint16(msg[offset:offset+2], turnAttrMessageIntegrity)
	binary.BigEndian.PutUint16(msg[offset+2:offset+4], 20)
	mac := hmac.New(sha1.New, integrityKey)
	mac.Write(msg[:offset+4])
	sum := mac.Sum(nil)
	copy(msg[offset+4:offset+24], sum[:20])
	return msg
}

func encodeTURNAttributes(attrs []turnAttribute) []byte {
	if len(attrs) == 0 {
		return nil
	}
	total := 0
	for _, attr := range attrs {
		l := len(attr.Value)
		total += 4 + l
		if rem := l % 4; rem != 0 {
			total += 4 - rem
		}
	}
	out := make([]byte, total)
	offset := 0
	for _, attr := range attrs {
		l := len(attr.Value)
		binary.BigEndian.PutUint16(out[offset:offset+2], attr.Type)
		binary.BigEndian.PutUint16(out[offset+2:offset+4], uint16(l))
		copy(out[offset+4:offset+4+l], attr.Value)
		offset += 4 + l
		if rem := l % 4; rem != 0 {
			offset += 4 - rem
		}
	}
	return out
}

func readTURNMessage(conn net.Conn, isStream bool, timeout time.Duration) (*turnMessage, error) {
	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}
	}
	if !isStream {
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		return parseTURNMessage(buf[:n])
	}

	header := make([]byte, 20)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	if length < 0 || length > 64*1024 {
		return nil, errors.New("invalid turn stream frame length")
	}
	packet := make([]byte, 20+length)
	copy(packet[:20], header)
	if length > 0 {
		if _, err := io.ReadFull(conn, packet[20:]); err != nil {
			return nil, err
		}
	}
	return parseTURNMessage(packet)
}

func parseTURNMessage(packet []byte) (*turnMessage, error) {
	if len(packet) < 20 {
		return nil, errors.New("short turn packet")
	}
	msgType := binary.BigEndian.Uint16(packet[0:2])
	msgLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if 20+msgLen > len(packet) {
		return nil, errors.New("invalid turn packet length")
	}
	if binary.BigEndian.Uint32(packet[4:8]) != stunMagicCookie {
		return nil, errors.New("invalid turn magic cookie")
	}
	var txID [12]byte
	copy(txID[:], packet[8:20])

	msg := &turnMessage{
		Type:  msgType,
		TxID:  txID,
		Attrs: make(map[uint16][]byte),
	}
	attrs := packet[20 : 20+msgLen]
	for len(attrs) >= 4 {
		attrType := binary.BigEndian.Uint16(attrs[0:2])
		attrLen := int(binary.BigEndian.Uint16(attrs[2:4]))
		if len(attrs) < 4+attrLen {
			break
		}
		value := make([]byte, attrLen)
		copy(value, attrs[4:4+attrLen])
		msg.Attrs[attrType] = value

		padded := attrLen
		if rem := attrLen % 4; rem != 0 {
			padded += 4 - rem
		}
		if len(attrs) < 4+padded {
			break
		}
		attrs = attrs[4+padded:]
	}
	return msg, nil
}

func parseTURNErrorCode(attr []byte) (int, string) {
	if len(attr) < 4 {
		return 0, ""
	}
	class := int(attr[2] & 0x07)
	number := int(attr[3])
	code := class*100 + number
	reason := strings.TrimSpace(string(attr[4:]))
	return code, reason
}

func parseTURNXORAddress(attr []byte, txID [12]byte) (string, int, error) {
	host, port, err := parseSTUNMappedAddress(attr, true, txID[:])
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func encodeTURNLifetime(seconds int) []byte {
	if seconds <= 0 {
		seconds = 300
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(seconds))
	return buf
}

func decodeTURNLifetime(attr []byte) time.Duration {
	if len(attr) < 4 {
		return 0
	}
	seconds := int(binary.BigEndian.Uint32(attr[:4]))
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}
