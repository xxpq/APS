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
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	TLSPinAlgorithm           = "spki-sha256-aesgcm-v1"
	TLSEncryptedConfigIDParam = "eid"
	TLSEncryptedSaltParam     = "salt"
	endpointTLSPinSaltLayout  = "200601021504"

	endpointBootstrapGatewayAddressEnv      = "APS_GATEWAY_ADDRESS"
	endpointBootstrapGatewayDiscoverPortEnv = "APS_GATEWAY_DISCOVER_PORT"
)

var (
	errEndpointTLSPinMismatch = errors.New("tls pin mismatch")

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

	mu           sync.RWMutex
	allowed      map[string][]byte
	allowedOrder []string
	activeHash   string
	client       *http.Client
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

func endpointBootstrapGatewayDiscoverPort() int {
	if raw := strings.TrimSpace(os.Getenv(endpointBootstrapGatewayDiscoverPortEnv)); raw != "" {
		if port, err := strconv.Atoi(raw); err == nil && port > 0 && port <= 65535 {
			return port
		}
	}
	return defaultGatewayDiscoverPort
}

func endpointBootstrapGatewayAddress() string {
	if addr := normalizeGatewayAddress(os.Getenv(endpointBootstrapGatewayAddressEnv)); addr != "" {
		if isLocalGatewayAddress(addr) {
			DebugLog("[CONN-INIT] Ignoring local bootstrap gateway address=%s", addr)
			return ""
		}
		return addr
	}
	discoverPort := endpointBootstrapGatewayDiscoverPort()
	if discoverPort <= 0 {
		DebugLog("[CONN-INIT] Bootstrap gateway discovery disabled: invalid port %d", discoverPort)
		return ""
	}
	discovered, err := discoverGatewayAddress(discoverPort)
	if err != nil {
		DebugLog("[CONN-INIT] Bootstrap gateway discovery failed on UDP/%d: %v", discoverPort, err)
		return ""
	}
	discovered = normalizeGatewayAddress(discovered)
	if discovered == "" {
		return ""
	}
	if isLocalGatewayAddress(discovered) {
		DebugLog("[CONN-INIT] Ignoring discovered local gateway address=%s", discovered)
		return ""
	}
	return discovered
}

func buildEndpointBootstrapGatewayDialContext(targetAddress string) (func(context.Context, string, string) (net.Conn, error), string) {
	targetAddress = normalizeServerAddressForSession(targetAddress)
	if targetAddress == "" {
		return nil, ""
	}
	gatewayAddress := endpointBootstrapGatewayAddress()
	if gatewayAddress == "" {
		DebugLog("[CONN-INIT] No bootstrap gateway available for target=%s", targetAddress)
		return nil, ""
	}
	if sameGatewayAddress(gatewayAddress, targetAddress) {
		return nil, ""
	}
	originNode := strings.TrimSpace(*configID)
	dialViaGateway := func(ctx context.Context, network, addr string) (net.Conn, error) {
		type dialResult struct {
			conn net.Conn
			err  error
		}
		done := make(chan dialResult, 1)
		go func() {
			conn, err := dialTunnelServerViaGateway(gatewayAddress, targetAddress, originNode)
			done <- dialResult{conn: conn, err: err}
		}()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-done:
			return result.conn, result.err
		}
	}
	return dialViaGateway, gatewayAddress
}

func (p *endpointTLSPin) allowedSummaryLocked() string {
	if len(p.allowedOrder) == 0 {
		return "<none>"
	}
	return strings.Join(p.allowedOrder, ",")
}

func (p *endpointTLSPin) addAllowedHash(hash []byte) (bool, string) {
	hashHex := hex.EncodeToString(hash)
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.allowed[hashHex]; exists {
		p.activeHash = hashHex
		return false, hashHex
	}

	p.allowed[hashHex] = append([]byte(nil), hash...)
	p.allowedOrder = append(p.allowedOrder, hashHex)
	if len(p.allowedOrder) > 6 {
		evict := p.allowedOrder[0]
		p.allowedOrder = p.allowedOrder[1:]
		delete(p.allowed, evict)
	}
	p.activeHash = hashHex
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

func fetchServerSPKIHashOverHTTPS(authority, serverName string) ([]byte, string, error) {
	reqURL := "https://" + authority + "/.api/tls-pin"

	send := func(dialContext func(context.Context, string, string) (net.Conn, error)) (*http.Response, error) {
		if dialContext == nil {
			dialContext = (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext
		}
		transport := &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
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
		dialViaGateway, gwAddr := buildEndpointBootstrapGatewayDialContext(authority)
		if dialViaGateway != nil {
			gatewayAddress = gwAddr
			resp, err = send(dialViaGateway)
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
	summary := p.allowedSummaryLocked()
	p.mu.Unlock()

	if !ok {
		DebugLog("[CONN-INIT] Pin mismatch for %s. cached=%s got=%s", p.serverAddress, summary, hashHex)
		return fmt.Errorf("%w: connectivity test failed", errEndpointTLSPinMismatch)
	}
	return nil
}

func newPinnedHTTPClientWithDialContext(pin *endpointTLSPin, dialContext func(context.Context, string, string) (net.Conn, error)) *http.Client {
	if dialContext == nil {
		dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
		dialContext = dialer.DialContext
	}
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
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
		return pin, nil
	}
	endpointTLSPins.mu.Unlock()

	hash, _, err := fetchServerSPKIHashOverHTTPS(authority, serverName)
	if err != nil {
		return nil, err
	}

	pin := &endpointTLSPin{
		serverAddress: authority,
		serverName:    serverName,
		allowed:       make(map[string][]byte),
	}
	pin.addAllowedHash(hash)
	pin.client = newPinnedHTTPClient(pin)

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

func GetTLSPinRegistrationInfo(serverAddress string) (string, []byte, error) {
	pin, err := ensureEndpointTLSPin(serverAddress)
	if err != nil {
		return "", nil, err
	}
	key, _, err := pin.getActiveKey()
	if err != nil {
		return "", nil, err
	}
	return pin.serverName, key, nil
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
		dialViaGateway, gatewayAddress := buildEndpointBootstrapGatewayDialContext(p.serverAddress)
		if dialViaGateway == nil {
			return nil, directErr
		}
		gatewayClient := newPinnedHTTPClientWithDialContext(p, dialViaGateway)
		gatewayResp, gatewayErr := send(gatewayClient, p)
		if gatewayErr == nil {
			DebugLog("[CONN-INIT] pinned GET %s via bootstrap gateway=%s target=%s", strings.TrimSpace(requestPath), gatewayAddress, p.serverAddress)
			return gatewayResp, nil
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
