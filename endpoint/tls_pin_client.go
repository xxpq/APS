package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	TLSPinAlgorithm                  = "spki-sha256-aesgcm-v1"
	TLSEncryptedConfigIDParam        = "eid"
	TLSEncryptedSaltParam            = "salt"
	endpointTLSPinSaltLayout         = "200601021504"
	endpointPinnedHTTPProxyEnableEnv = "APS_PINNED_HTTP_PROXY_ENABLE"
	endpointTLSPinTokenEnv           = "APS_TOKEN"
	endpointTLSPinTokenPrefix        = "apspt1."

	endpointBootstrapGatewayAddressEnv      = "APS_GATEWAY_ADDRESS"
	endpointBootstrapGatewayDiscoverPortEnv = "APS_GATEWAY_DISCOVER_PORT"
)

var (
	errEndpointTLSPinMismatch     = errors.New("tls pin mismatch")
	errEndpointTLSPinTokenExpired = errors.New("pin token expired")

	endpointTLSPins = struct {
		mu        sync.Mutex
		byAddress map[string]*endpointTLSPin
	}{
		byAddress: make(map[string]*endpointTLSPin),
	}
)

type EncryptedPayloadEnvelope struct {
	Encrypted bool   `json:"encrypted"`
	Alg       string `json:"alg"`
	Salt      string `json:"salt"`
	Payload   string `json:"payload"`
}

type encryptedEndpointConfigRequest struct {
	ConfigID  string `json:"cid"`
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"ts"`
	Token     string `json:"token"`
}

type endpointTLSPin struct {
	serverAddress string
	serverName    string

	mu            sync.RWMutex
	allowed       map[string][]byte
	allowedOrder  []string
	activeHash    string
	enforceTLSPin bool
	client        *http.Client
}

type endpointTLSPinTokenPayload struct {
	Pin  string `json:"pin"`
	CID  string `json:"cid,omitempty"`
	Host string `json:"host,omitempty"`
	Exp  int64  `json:"exp,omitempty"`
}

func normalizeEndpointTLSPinHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.Trim(host, "[]")
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

func normalizeEndpointServerAddress(serverAddress string) (string, string, error) {
	addr := strings.TrimSpace(serverAddress)
	if addr == "" {
		return "", "", errors.New("empty server address")
	}
	if idx := strings.Index(addr, "@"); idx >= 0 && idx+1 < len(addr) {
		addr = addr[idx+1:]
	}
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", "", errors.New("empty server address after cid prefix")
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") || strings.Contains(err.Error(), "too many colons") {
			host = addr
		} else {
			return "", "", err
		}
	}

	host = normalizeEndpointTLSPinHost(host)
	if host == "" {
		return "", "", errors.New("empty host in server address")
	}

	urlAuthority := host
	if strings.Contains(host, ":") {
		urlAuthority = "[" + host + "]"
	}

	return urlAuthority, host, nil
}

func parseEndpointTLSPinHashHex(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(strings.ToLower(raw), "sha256:")
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty pin hash")
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid pin hash hex: %w", err)
	}
	if len(decoded) != sha256.Size {
		return nil, fmt.Errorf("pin hash length must be %d bytes, got %d", sha256.Size, len(decoded))
	}
	return decoded, nil
}

func deriveEndpointTLSPinTokenKey(cid, authority string) []byte {
	h := sha256.New()
	h.Write([]byte("aps-pin-token-v1"))
	h.Write([]byte("|"))
	h.Write([]byte(strings.TrimSpace(cid)))
	h.Write([]byte("|"))
	h.Write([]byte(normalizeEndpointTLSPinHost(authority)))
	return h.Sum(nil)
}

func encodeEndpointTLSPinToken(pinHash []byte, cid, authority string, expUnix int64) (string, error) {
	if len(pinHash) != sha256.Size {
		return "", fmt.Errorf("pin hash length must be %d bytes, got %d", sha256.Size, len(pinHash))
	}
	payload := endpointTLSPinTokenPayload{
		Pin:  hex.EncodeToString(pinHash),
		CID:  strings.TrimSpace(cid),
		Host: normalizeEndpointTLSPinHost(authority),
		Exp:  expUnix,
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(deriveEndpointTLSPinTokenKey(cid, authority))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plain, nil)
	return endpointTLSPinTokenPrefix + base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func decodeEndpointTLSPinToken(token, cid, authority string) ([]byte, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("empty token")
	}
	body := token
	lower := strings.ToLower(token)
	if strings.HasPrefix(lower, endpointTLSPinTokenPrefix) {
		body = token[len(endpointTLSPinTokenPrefix):]
	} else if strings.HasPrefix(lower, "apspt1:") {
		body = token[len("apspt1:"):]
	} else {
		return nil, errors.New("unsupported token format")
	}
	body = strings.TrimSpace(body)
	if body == "" {
		return nil, errors.New("empty token payload")
	}
	cid = strings.TrimSpace(cid)
	if cid == "" {
		return nil, errors.New("token requires non-empty cid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("invalid token payload: %w", err)
	}
	block, err := aes.NewCipher(deriveEndpointTLSPinTokenKey(cid, authority))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(raw) <= nonceSize {
		return nil, errors.New("token payload too short")
	}
	plain, err := gcm.Open(nil, raw[:nonceSize], raw[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("token decrypt failed: %w", err)
	}
	var payload endpointTLSPinTokenPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, fmt.Errorf("token payload parse failed: %w", err)
	}
	if payload.Exp > 0 && time.Now().UTC().Unix() > payload.Exp {
		return nil, errEndpointTLSPinTokenExpired
	}
	if strings.TrimSpace(payload.CID) != "" && !strings.EqualFold(strings.TrimSpace(payload.CID), cid) {
		return nil, errors.New("token cid mismatch")
	}
	tokenHost := normalizeEndpointTLSPinHost(payload.Host)
	currentHost := normalizeEndpointTLSPinHost(authority)
	if tokenHost != "" && currentHost != "" && !strings.EqualFold(tokenHost, currentHost) {
		return nil, errors.New("token host mismatch")
	}
	return parseEndpointTLSPinHashHex(payload.Pin)
}

func isEndpointTLSPinTokenExpiredError(err error) bool {
	return errors.Is(err, errEndpointTLSPinTokenExpired)
}

func resolveEndpointTLSPinOverride(authority string) ([]byte, string, error) {
	authority = normalizeEndpointTLSPinHost(authority)
	token := strings.TrimSpace(*pinToken)
	if token == "" {
		token = strings.TrimSpace(os.Getenv(endpointTLSPinTokenEnv))
	}
	if token == "" {
		return nil, "", nil
	}

	// Emergency compatibility: token can still carry a direct hash payload.
	if hash, err := parseEndpointTLSPinHashHex(token); err == nil {
		return hash, "token(raw-hash)", nil
	}

	hash, err := decodeEndpointTLSPinToken(token, strings.TrimSpace(*configID), authority)
	if err != nil {
		return nil, "", fmt.Errorf("invalid pin token: %w", err)
	}
	if authority != "" {
		return hash, "token(encrypted) for " + authority, nil
	}
	return hash, "token(encrypted)", nil
}

func endpointBootstrapGatewayDiscoverPort() int {
	if raw := strings.TrimSpace(os.Getenv(endpointBootstrapGatewayDiscoverPortEnv)); raw != "" {
		if port, err := strconv.Atoi(raw); err == nil && port > 0 && port <= 65535 {
			return port
		}
	}
	return defaultGatewayDiscoverPort
}

func splitEndpointBootstrapGatewayAddresses(raw string) []string {
	raw = strings.NewReplacer(";", ",", "\n", ",", "\r", ",", "\t", ",").Replace(raw)
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		addr := strings.TrimSpace(part)
		if addr == "" {
			continue
		}
		out = append(out, addr)
	}
	return out
}

func endpointBootstrapGatewayAddresses() []string {
	maxCandidates := gatewayRouteBundleMaxAddrs
	if maxCandidates <= 0 {
		maxCandidates = 1
	}
	out := make([]string, 0, maxCandidates)
	seen := make(map[string]struct{}, maxCandidates)
	add := func(raw string) {
		if len(out) >= maxCandidates {
			return
		}
		addr := normalizeGatewayAddress(raw)
		if addr == "" {
			return
		}
		if isLocalGatewayAddress(addr) {
			DebugLog("[CONN-INIT] Ignoring local bootstrap gateway address=%s", addr)
			return
		}
		if _, exists := seen[addr]; exists {
			return
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}

	if raw := strings.TrimSpace(os.Getenv(endpointBootstrapGatewayAddressEnv)); raw != "" {
		for _, addr := range splitEndpointBootstrapGatewayAddresses(raw) {
			add(addr)
		}
		return out
	}
	discoverPort := endpointBootstrapGatewayDiscoverPort()
	if discoverPort <= 0 {
		DebugLog("[CONN-INIT] Bootstrap gateway discovery disabled: invalid port %d", discoverPort)
		return nil
	}
	discovered, err := discoverGatewayAddresses(discoverPort, maxCandidates)
	if err != nil {
		DebugLog("[CONN-INIT] Bootstrap gateway discovery failed on UDP/%d: %v", discoverPort, err)
		return nil
	}
	for _, addr := range discovered {
		add(addr)
	}
	return out
}

func endpointPinnedHTTPProxyEnabled() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(endpointPinnedHTTPProxyEnableEnv)))
	if raw == "" {
		// Backward compatible behavior: use system proxy by default.
		return true
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func endpointPinnedHTTPProxySelector(req *http.Request) (*url.URL, error) {
	if endpointPinnedHTTPProxyEnabled() {
		return endpointHTTPProxySelector(req)
	}
	return nil, nil
}

func buildEndpointBootstrapGatewayDialContexts(targetAddress string) ([]func(context.Context, string, string) (net.Conn, error), []string) {
	targetAddress = normalizeServerAddressForSession(targetAddress)
	if targetAddress == "" {
		return nil, nil
	}
	gatewayAddresses := endpointBootstrapGatewayAddresses()
	if len(gatewayAddresses) == 0 {
		DebugLog("[CONN-INIT] No bootstrap gateway available for target=%s", targetAddress)
		return nil, nil
	}
	dialers := make([]func(context.Context, string, string) (net.Conn, error), 0, len(gatewayAddresses))
	filteredAddrs := make([]string, 0, len(gatewayAddresses))
	originNode := strings.TrimSpace(*configID)
	for _, gatewayAddress := range gatewayAddresses {
		gwAddr := normalizeGatewayAddress(gatewayAddress)
		if gwAddr == "" || sameGatewayAddress(gwAddr, targetAddress) {
			continue
		}
		dialViaGateway := func(ctx context.Context, network, addr string) (net.Conn, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return dialTunnelServerViaGateway(gwAddr, targetAddress, originNode)
		}
		filteredAddrs = append(filteredAddrs, gwAddr)
		dialers = append(dialers, dialViaGateway)
	}
	if len(dialers) == 0 {
		return nil, nil
	}
	return dialers, filteredAddrs
}

func (p *endpointTLSPin) allowedSummaryLocked() string {
	if len(p.allowedOrder) == 0 {
		return "<none>"
	}
	return strings.Join(p.allowedOrder, ",")
}

func (p *endpointTLSPin) addAllowedHash(hash []byte) (bool, string) {
	return p.addAllowedHashWithMode(hash, true)
}

func (p *endpointTLSPin) addAllowedHashWithMode(hash []byte, activate bool) (bool, string) {
	hashHex := hex.EncodeToString(hash)
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.allowed[hashHex]; exists {
		if activate {
			p.activeHash = hashHex
		}
		return false, hashHex
	}

	p.allowed[hashHex] = append([]byte(nil), hash...)
	p.allowedOrder = append(p.allowedOrder, hashHex)
	if len(p.allowedOrder) > 6 {
		evict := p.allowedOrder[0]
		p.allowedOrder = p.allowedOrder[1:]
		delete(p.allowed, evict)
	}
	if activate {
		p.activeHash = hashHex
	}
	return true, hashHex
}

func (p *endpointTLSPin) getActiveKey() ([]byte, string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.activeHash != "" {
		if key, ok := p.allowed[p.activeHash]; ok {
			return append([]byte(nil), key...), p.activeHash, nil
		}
	}
	if len(p.allowedOrder) == 0 {
		return nil, "", errors.New("no tls pin key available")
	}
	hashHex := p.allowedOrder[len(p.allowedOrder)-1]
	key := p.allowed[hashHex]
	return append([]byte(nil), key...), hashHex, nil
}

func (p *endpointTLSPin) candidateKeys() [][]byte {
	p.mu.RLock()
	defer p.mu.RUnlock()

	keys := make([][]byte, 0, len(p.allowed))
	if p.activeHash != "" {
		if key, ok := p.allowed[p.activeHash]; ok {
			keys = append(keys, append([]byte(nil), key...))
		}
	}
	for _, hashHex := range p.allowedOrder {
		if hashHex == p.activeHash {
			continue
		}
		if key, ok := p.allowed[hashHex]; ok {
			keys = append(keys, append([]byte(nil), key...))
		}
	}
	return keys
}

func (p *endpointTLSPin) setEnforceTLSPin(enforce bool) {
	p.mu.Lock()
	p.enforceTLSPin = enforce
	p.mu.Unlock()
}

func (p *endpointTLSPin) isTLSPinEnforced() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.enforceTLSPin
}

func shouldEnforceTLSPinForOverride(overrideHash []byte, overrideSource string) bool {
	if len(overrideHash) == 0 {
		// No override: always enforce transport TLS pin.
		return true
	}
	// Encrypted token is the compatibility path for MITM/proxy environments:
	// transport certificate may be substituted, but control-plane pin-based crypto stays bound to APS pin.
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(overrideSource)), "token(encrypted)") {
		return false
	}
	// Raw hash input keeps strict transport pin semantics.
	return true
}

func fetchServerSPKIHashOverHTTPS(authority, serverName string) ([]byte, string, error) {
	reqURL := "https://" + authority + "/.api/tls-pin"

	send := func(dialContext func(context.Context, string, string) (net.Conn, error)) (*http.Response, error) {
		if dialContext == nil {
			dialContext = (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext
		}
		transport := &http.Transport{
			Proxy:               endpointPinnedHTTPProxySelector,
			DialContext:         dialContext,
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				ServerName: serverName,
			},
		}
		client := &http.Client{
			Transport: transport,
			Timeout:   20 * time.Second,
		}
		return client.Get(reqURL)
	}

	resp, err := send(nil)
	var gatewayAddress string
	if err != nil {
		dialViaGateways, gwAddrs := buildEndpointBootstrapGatewayDialContexts(authority)
		for i, dialViaGateway := range dialViaGateways {
			resp, err = send(dialViaGateway)
			if err == nil {
				gatewayAddress = gwAddrs[i]
				break
			}
			DebugLog("[CONN-INIT] Connectivity test via bootstrap gateway=%s failed target=%s: %v", gwAddrs[i], authority, err)
		}
	}
	if err != nil {
		DebugLog("[CONN-INIT] Connectivity test request failed for %s: %v", authority, err)
		return nil, "", errors.New("connectivity test failed")
	}
	defer resp.Body.Close()
	if gatewayAddress != "" {
		DebugLog("[CONN-INIT] Connectivity test via bootstrap gateway=%s target=%s", gatewayAddress, authority)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
	if resp.StatusCode != http.StatusOK {
		DebugLog("[CONN-INIT] Connectivity test returned non-200 for %s: status=%d", authority, resp.StatusCode)
		return nil, "", errors.New("connectivity test failed")
	}

	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		DebugLog("[CONN-INIT] Connectivity test missing peer certificate for %s", authority)
		return nil, "", errors.New("connectivity test failed")
	}

	sum := sha256.Sum256(resp.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
	hash := sum[:]
	hashHex := hex.EncodeToString(hash)

	var pinResp struct {
		Success bool   `json:"success"`
		Hash    string `json:"hash"`
	}
	if err := json.Unmarshal(body, &pinResp); err == nil && pinResp.Hash != "" {
		if !strings.EqualFold(pinResp.Hash, hashHex) {
			DebugLog("[CONN-INIT] Connectivity test hash mismatch for %s", authority)
			return nil, "", errors.New("connectivity test failed")
		}
	}

	return append([]byte(nil), hash...), hashHex, nil
}

func (p *endpointTLSPin) verifyPinnedTLSConnection(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		DebugLog("[CONN-INIT] Missing peer certificate while verifying %s", p.serverAddress)
		return fmt.Errorf("%w: connectivity test failed", errEndpointTLSPinMismatch)
	}
	sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
	hashHex := hex.EncodeToString(sum[:])

	p.mu.Lock()
	_, ok := p.allowed[hashHex]
	if ok {
		p.activeHash = hashHex
	}
	enforceTLSPin := p.enforceTLSPin
	summary := p.allowedSummaryLocked()
	p.mu.Unlock()

	if !ok {
		if !enforceTLSPin {
			DebugLog("[CONN-INIT] Transport TLS pin mismatch tolerated for %s (configured token mode). cached=%s got=%s", p.serverAddress, summary, hashHex)
			return nil
		}
		DebugLog("[CONN-INIT] Pin mismatch for %s. cached=%s got=%s", p.serverAddress, summary, hashHex)
		return fmt.Errorf("%w: connectivity test failed", errEndpointTLSPinMismatch)
	}
	return nil
}

func newPinnedHTTPClientWithDialContextAndProxy(pin *endpointTLSPin, dialContext func(context.Context, string, string) (net.Conn, error), enableProxy bool) *http.Client {
	if dialContext == nil {
		dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
		dialContext = dialer.DialContext
	}
	var proxySelector func(*http.Request) (*url.URL, error)
	if enableProxy {
		proxySelector = endpointPinnedHTTPProxySelector
	}
	transport := &http.Transport{
		Proxy:               proxySelector,
		DialContext:         dialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:       tls.VersionTLS13,
			ServerName:       pin.serverName,
			VerifyConnection: pin.verifyPinnedTLSConnection,
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

func newPinnedHTTPClientWithDialContext(pin *endpointTLSPin, dialContext func(context.Context, string, string) (net.Conn, error)) *http.Client {
	return newPinnedHTTPClientWithDialContextAndProxy(pin, dialContext, true)
}

func newPinnedHTTPClient(pin *endpointTLSPin) *http.Client {
	return newPinnedHTTPClientWithDialContext(pin, nil)
}

func ensureEndpointTLSPin(serverAddress string) (*endpointTLSPin, error) {
	authority, serverName, err := normalizeEndpointServerAddress(serverAddress)
	if err != nil {
		return nil, err
	}
	cacheKey := strings.ToLower(authority)

	endpointTLSPins.mu.Lock()
	if pin, exists := endpointTLSPins.byAddress[cacheKey]; exists {
		endpointTLSPins.mu.Unlock()
		overrideHash, overrideSource, overrideErr := resolveEndpointTLSPinOverride(authority)
		if overrideErr != nil {
			if isEndpointTLSPinTokenExpiredError(overrideErr) {
				DebugLog("[CONN-INIT] Pin token expired for %s; continue with cached pin", authority)
				return pin, nil
			}
			return nil, overrideErr
		}
		pin.setEnforceTLSPin(shouldEnforceTLSPinForOverride(overrideHash, overrideSource))
		if len(overrideHash) > 0 {
			activateOverrideHash := pin.isTLSPinEnforced()
			added, hashHex := pin.addAllowedHashWithMode(overrideHash, activateOverrideHash)
			if added {
				DebugLog("[CONN-INIT] Applied configured TLS pin (%s) for %s hash=%s", overrideSource, authority, hashHex)
			}
			if pin.isTLSPinEnforced() {
				DebugLog("[CONN-INIT] Token override active; TLS transport pin enforcement remains strict for %s", authority)
			} else {
				DebugLog("[CONN-INIT] Token override active; TLS transport pin enforcement relaxed for %s", authority)
			}
		}
		return pin, nil
	}
	endpointTLSPins.mu.Unlock()

	overrideHash, overrideSource, overrideErr := resolveEndpointTLSPinOverride(authority)
	if overrideErr != nil {
		return nil, overrideErr
	}

	var hash []byte
	if len(overrideHash) > 0 {
		hash = append([]byte(nil), overrideHash...)
		DebugLog("[CONN-INIT] Using configured TLS pin (%s) for %s", overrideSource, authority)
	} else {
		hash, _, err = fetchServerSPKIHashOverHTTPS(authority, serverName)
		if err != nil {
			return nil, err
		}
	}

	pin := &endpointTLSPin{
		serverAddress: authority,
		serverName:    serverName,
		allowed:       make(map[string][]byte),
		enforceTLSPin: shouldEnforceTLSPinForOverride(overrideHash, overrideSource),
	}
	pin.addAllowedHash(hash)
	pin.client = newPinnedHTTPClient(pin)
	if len(overrideHash) > 0 {
		if pin.isTLSPinEnforced() {
			DebugLog("[CONN-INIT] Token override active; TLS transport pin enforcement remains strict for %s", authority)
		} else {
			DebugLog("[CONN-INIT] Token override active; TLS transport pin enforcement relaxed for %s", authority)
		}
	}

	endpointTLSPins.mu.Lock()
	if existing, exists := endpointTLSPins.byAddress[cacheKey]; exists {
		endpointTLSPins.mu.Unlock()
		existing.addAllowedHash(hash)
		return existing, nil
	}
	endpointTLSPins.byAddress[cacheKey] = pin
	endpointTLSPins.mu.Unlock()

	DebugLog("[CONN-INIT] Cached TLS pin for %s", authority)
	return pin, nil
}

func refreshEndpointTLSPin(serverAddress string) (*endpointTLSPin, error) {
	pin, err := ensureEndpointTLSPin(serverAddress)
	if err != nil {
		return nil, err
	}

	overrideHash, overrideSource, overrideErr := resolveEndpointTLSPinOverride(pin.serverAddress)
	if overrideErr != nil {
		if isEndpointTLSPinTokenExpiredError(overrideErr) {
			DebugLog("[CONN-INIT] Pin token expired for %s during refresh; keep cached pin", pin.serverAddress)
			return pin, nil
		}
		return nil, overrideErr
	}
	if len(overrideHash) > 0 {
		added, _ := pin.addAllowedHash(overrideHash)
		if added {
			DebugLog("[CONN-INIT] Refreshed configured TLS pin (%s) for %s", overrideSource, pin.serverAddress)
		}
		// In encrypted-token compatibility mode, transport TLS pin enforcement is relaxed.
		// If APS rejects encrypted eid, promote the currently observed SPKI hash once and retry.
		if !pin.isTLSPinEnforced() {
			liveHash, liveHashHex, liveErr := fetchServerSPKIHashOverHTTPS(pin.serverAddress, pin.serverName)
			if liveErr != nil {
				DebugLog("[CONN-INIT] Token mode live SPKI probe failed for %s: %v", pin.serverAddress, liveErr)
				return pin, nil
			}
			liveAdded, _ := pin.addAllowedHash(liveHash)
			if liveAdded {
				DebugLog("[CONN-INIT] Token mode added live SPKI hash for %s hash=%s", pin.serverAddress, liveHashHex)
			}
			DebugLog("[CONN-INIT] Token mode promoted live SPKI hash for %s (eid retry path)", pin.serverAddress)
		}
		return pin, nil
	}

	hash, _, err := fetchServerSPKIHashOverHTTPS(pin.serverAddress, pin.serverName)
	if err != nil {
		return nil, err
	}
	added, _ := pin.addAllowedHash(hash)
	if added {
		DebugLog("[CONN-INIT] Added rotated TLS pin for %s", pin.serverAddress)
	}
	return pin, nil
}

func shouldRefreshPinAfterError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errEndpointTLSPinMismatch) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "tls pin mismatch")
}

func PrimeTLSPinForServer(serverAddress string) error {
	_, err := ensureEndpointTLSPin(serverAddress)
	return err
}

func GetTLSPinRegistrationInfo(serverAddress string) (string, []byte, bool, error) {
	pin, err := ensureEndpointTLSPin(serverAddress)
	if err != nil {
		return "", nil, true, err
	}
	key, _, err := pin.getActiveKey()
	if err != nil {
		return "", nil, pin.isTLSPinEnforced(), err
	}
	return pin.serverName, key, pin.isTLSPinEnforced(), nil
}

func currentEndpointTLSPinSalt() string {
	return time.Now().UTC().Format(endpointTLSPinSaltLayout)
}

func deriveEndpointConfigTokenKey(pinKey []byte, salt string) []byte {
	h := sha256.New()
	h.Write(pinKey)
	h.Write([]byte{':'})
	h.Write([]byte(salt))
	h.Write([]byte(":eid-token-v1"))
	return h.Sum(nil)
}

func computeEndpointConfigToken(pinKey []byte, cid, nonce string, ts int64, salt string) string {
	key := deriveEndpointConfigTokenKey(pinKey, salt)
	msg := strings.Join([]string{
		strings.TrimSpace(cid),
		strings.TrimSpace(nonce),
		strconv.FormatInt(ts, 10),
		strings.TrimSpace(salt),
	}, "|")
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func generateEndpointRequestNonce() (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce), nil
}

func deriveEndpointTLSPinAESKey(keyMaterial []byte, salt string) []byte {
	base := keyMaterial
	if len(base) != 32 {
		sum := sha256.Sum256(base)
		base = sum[:]
	}

	derived := sha256.New()
	derived.Write(base)
	derived.Write([]byte{':'})
	derived.Write([]byte(salt))
	return derived.Sum(nil)
}

func encryptWithEndpointTLSPin(keyMaterial []byte, salt string, plaintext []byte) ([]byte, error) {
	key := deriveEndpointTLSPinAESKey(keyMaterial, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptWithEndpointTLSPin(keyMaterial []byte, salt string, ciphertext []byte) ([]byte, error) {
	key := deriveEndpointTLSPinAESKey(keyMaterial, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, encrypted, nil)
}

func buildEncryptedConfigIDForServer(serverAddress, configID string) (string, string, *endpointTLSPin, error) {
	pin, err := ensureEndpointTLSPin(serverAddress)
	if err != nil {
		return "", "", nil, err
	}
	key, _, err := pin.getActiveKey()
	if err != nil {
		return "", "", nil, err
	}

	salt := currentEndpointTLSPinSalt()
	nonce, err := generateEndpointRequestNonce()
	if err != nil {
		return "", "", nil, err
	}
	ts := time.Now().UTC().Unix()
	request := encryptedEndpointConfigRequest{
		ConfigID:  strings.TrimSpace(configID),
		Nonce:     nonce,
		Timestamp: ts,
		Token:     computeEndpointConfigToken(key, strings.TrimSpace(configID), nonce, ts, salt),
	}
	keyHex := hex.EncodeToString(key)
	keyHint := keyHex
	if len(keyHint) > 12 {
		keyHint = keyHint[:12]
	}
	DebugLog("[CONFIG] Encrypted eid prepared for server=%s cid=%s salt=%s key=%s... enforce_tls_pin=%v",
		pin.serverAddress,
		strings.TrimSpace(configID),
		salt,
		keyHint,
		pin.isTLSPinEnforced(),
	)
	payload, err := json.Marshal(request)
	if err != nil {
		return "", "", nil, err
	}
	ciphertext, err := encryptWithEndpointTLSPin(key, salt, payload)
	if err != nil {
		return "", "", nil, err
	}
	return base64.RawURLEncoding.EncodeToString(ciphertext), salt, pin, nil
}

func decodeEncryptedEnvelopeWithPin(pin *endpointTLSPin, envelope *EncryptedPayloadEnvelope) ([]byte, error) {
	if envelope == nil {
		return nil, errors.New("nil encrypted envelope")
	}
	if !envelope.Encrypted {
		return nil, errors.New("response is not encrypted")
	}
	if envelope.Alg != "" && envelope.Alg != TLSPinAlgorithm {
		return nil, fmt.Errorf("unexpected encryption algorithm: %s", envelope.Alg)
	}
	if envelope.Salt == "" {
		return nil, errors.New("missing encrypted salt")
	}
	raw, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("invalid encrypted payload: %w", err)
	}

	var lastErr error
	for _, key := range pin.candidateKeys() {
		plain, decErr := decryptWithEndpointTLSPin(key, envelope.Salt, raw)
		if decErr == nil {
			return plain, nil
		}
		lastErr = decErr
	}
	if lastErr == nil {
		lastErr = errors.New("no key candidates available")
	}
	return nil, fmt.Errorf("failed to decrypt encrypted payload: %w", lastErr)
}

func doPinnedAPSGet(serverAddress, requestPath string) (*http.Response, *endpointTLSPin, error) {
	pin, err := ensureEndpointTLSPin(serverAddress)
	if err != nil {
		return nil, nil, err
	}

	send := func(client *http.Client, p *endpointTLSPin) (*http.Response, error) {
		req, reqErr := http.NewRequest(http.MethodGet, "https://"+p.serverAddress+requestPath, nil)
		if reqErr != nil {
			return nil, reqErr
		}
		return client.Do(req)
	}

	trySendWithGatewayFallback := func(p *endpointTLSPin) (*http.Response, error) {
		resp, directErr := send(p.client, p)
		if directErr == nil {
			return resp, nil
		}
		dialViaGateways, gatewayAddresses := buildEndpointBootstrapGatewayDialContexts(p.serverAddress)
		if len(dialViaGateways) == 0 {
			return nil, directErr
		}
		for i, dialViaGateway := range dialViaGateways {
			gatewayAddress := gatewayAddresses[i]
			gatewayClient := newPinnedHTTPClientWithDialContextAndProxy(p, dialViaGateway, false)
			gatewayResp, gatewayErr := send(gatewayClient, p)
			if gatewayErr == nil {
				DebugLog("[CONN-INIT] pinned GET %s via bootstrap gateway=%s target=%s", strings.TrimSpace(requestPath), gatewayAddress, p.serverAddress)
				return gatewayResp, nil
			}
			DebugLog("[CONN-INIT] pinned GET %s via bootstrap gateway=%s failed target=%s: %v", strings.TrimSpace(requestPath), gatewayAddress, p.serverAddress, gatewayErr)
		}
		return nil, directErr
	}

	resp, err := trySendWithGatewayFallback(pin)
	if err == nil {
		return resp, pin, nil
	}

	if !shouldRefreshPinAfterError(err) {
		return nil, pin, err
	}

	refreshedPin, refreshErr := refreshEndpointTLSPin(serverAddress)
	if refreshErr != nil {
		return nil, pin, fmt.Errorf("tls pin request failed: %w (refresh failed: %v)", err, refreshErr)
	}

	resp, err = trySendWithGatewayFallback(refreshedPin)
	if err != nil {
		return nil, refreshedPin, err
	}
	return resp, refreshedPin, nil
}
