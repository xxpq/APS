package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// TLSPinAlgorithm is shared by endpoint and APS for encrypted endpoint config fetch.
	TLSPinAlgorithm = "spki-sha256-aesgcm-v1"
	// TLSEncryptedConfigIDParam is the encrypted query parameter for endpoint config fetch.
	TLSEncryptedConfigIDParam = "eid"
	// TLSEncryptedSaltParam is the minute-level dynamic salt parameter.
	TLSEncryptedSaltParam = "salt"

	tlsPinSaltLayout = "200601021504"

	endpointConfigTokenWindow    = 3 * time.Minute
	endpointConfigReplayMaxEntry = 20000
)

var (
	errTLSPinHashUnavailable = errors.New("tls pin hash unavailable")

	tlsPinHashes = struct {
		mu     sync.RWMutex
		byHost map[string][]byte
	}{
		byHost: make(map[string][]byte),
	}

	endpointConfigReplay = struct {
		mu   sync.Mutex
		seen map[string]int64
	}{
		seen: make(map[string]int64, 1024),
	}
)

// EncryptedPayloadEnvelope wraps encrypted JSON payloads exchanged between endpoint and APS.
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

func normalizeTLSPinHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.Trim(host, "[]")
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

func hostWithoutPort(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return normalizeTLSPinHost(host)
	}
	return normalizeTLSPinHost(hostport)
}

func lookupTLSPinHashForHost(host string) ([]byte, bool) {
	host = normalizeTLSPinHost(host)
	if host == "" {
		return nil, false
	}

	tlsPinHashes.mu.RLock()
	defer tlsPinHashes.mu.RUnlock()

	if hash, ok := tlsPinHashes.byHost[host]; ok {
		return append([]byte(nil), hash...), true
	}

	parts := strings.Split(host, ".")
	for i := 1; i < len(parts)-1; i++ {
		wildcard := "*." + strings.Join(parts[i:], ".")
		if hash, ok := tlsPinHashes.byHost[wildcard]; ok {
			return append([]byte(nil), hash...), true
		}
	}
	return nil, false
}

func parseTLSPinLeafCertificate(cert *tls.Certificate) (*x509.Certificate, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, errors.New("empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	return leaf, nil
}

// registerTLSPinHash extracts SPKI hash from certificate and binds it to host aliases.
func registerTLSPinHash(cert *tls.Certificate, aliases ...string) {
	leaf, err := parseTLSPinLeafCertificate(cert)
	if err != nil {
		log.Printf("[TLS-PIN] Failed to parse certificate for pin registration: %v", err)
		return
	}

	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	hash := sum[:]
	hashHex := hex.EncodeToString(hash)

	hostSet := make(map[string]struct{})
	if cn := normalizeTLSPinHost(leaf.Subject.CommonName); cn != "" {
		hostSet[cn] = struct{}{}
	}
	for _, dnsName := range leaf.DNSNames {
		if normalized := normalizeTLSPinHost(dnsName); normalized != "" {
			hostSet[normalized] = struct{}{}
		}
	}
	for _, alias := range aliases {
		if normalized := normalizeTLSPinHost(alias); normalized != "" {
			hostSet[normalized] = struct{}{}
		}
	}

	if len(hostSet) == 0 {
		log.Printf("[TLS-PIN] No host alias available for certificate hash %s", hashHex)
		return
	}

	tlsPinHashes.mu.Lock()
	defer tlsPinHashes.mu.Unlock()

	for host := range hostSet {
		existing, exists := tlsPinHashes.byHost[host]
		if exists && bytes.Equal(existing, hash) {
			continue
		}
		tlsPinHashes.byHost[host] = append([]byte(nil), hash...)
		log.Printf("[TLS-PIN] Registered host '%s' with SPKI hash %s", host, hashHex)
	}
}

// getTLSPinHashForRequest resolves the expected SPKI hash key for current HTTPS request host.
func getTLSPinHashForRequest(r *http.Request) ([]byte, string, error) {
	if r == nil {
		return nil, "", errTLSPinHashUnavailable
	}
	if r.TLS == nil {
		return nil, "", fmt.Errorf("%w: request is not over TLS", errTLSPinHashUnavailable)
	}

	candidates := make([]string, 0, 2)
	if sni := normalizeTLSPinHost(r.TLS.ServerName); sni != "" {
		candidates = append(candidates, sni)
	}
	if host := hostWithoutPort(r.Host); host != "" {
		duplicate := false
		for _, candidate := range candidates {
			if candidate == host {
				duplicate = true
				break
			}
		}
		if !duplicate {
			candidates = append(candidates, host)
		}
	}

	for _, candidate := range candidates {
		if hash, ok := lookupTLSPinHashForHost(candidate); ok {
			return hash, candidate, nil
		}
	}

	return nil, "", fmt.Errorf("%w: no pin registered for hosts %v", errTLSPinHashUnavailable, candidates)
}

func deriveTLSPinAESKey(keyMaterial []byte, salt string) []byte {
	baseKey := keyMaterial
	if len(baseKey) != 32 {
		sum := sha256.Sum256(baseKey)
		baseKey = sum[:]
	}

	derived := sha256.New()
	derived.Write(baseKey)
	derived.Write([]byte{':'})
	derived.Write([]byte(salt))
	return derived.Sum(nil)
}

func encryptWithTLSPinHash(keyMaterial []byte, salt string, plaintext []byte) ([]byte, error) {
	if len(keyMaterial) == 0 {
		return nil, errors.New("empty tls pin key")
	}
	key := deriveTLSPinAESKey(keyMaterial, salt)
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

func decryptWithTLSPinHash(keyMaterial []byte, salt string, ciphertext []byte) ([]byte, error) {
	if len(keyMaterial) == 0 {
		return nil, errors.New("empty tls pin key")
	}
	key := deriveTLSPinAESKey(keyMaterial, salt)
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

func encodeTLSPinCiphertext(ciphertext []byte) string {
	return base64.RawURLEncoding.EncodeToString(ciphertext)
}

func decodeTLSPinCiphertext(encoded string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(encoded)
}

func currentTLSPinSalt() string {
	return time.Now().UTC().Format(tlsPinSaltLayout)
}

func isTLSPinSaltAllowed(salt string) bool {
	if _, err := time.Parse(tlsPinSaltLayout, salt); err != nil {
		return false
	}

	now := time.Now().UTC()
	for delta := -2; delta <= 2; delta++ {
		allowed := now.Add(time.Duration(delta) * time.Minute).Format(tlsPinSaltLayout)
		if salt == allowed {
			return true
		}
	}
	return false
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

func isEndpointConfigTokenFresh(ts int64) bool {
	now := time.Now().UTC().Unix()
	delta := now - ts
	if delta < 0 {
		delta = -delta
	}
	return time.Duration(delta)*time.Second <= endpointConfigTokenWindow
}

func registerEndpointConfigReplayToken(cid, nonce, token string, ts int64) error {
	now := time.Now().UTC().Unix()
	expiry := ts + int64((endpointConfigTokenWindow + time.Minute).Seconds())
	replayToken := strings.Join([]string{
		strings.TrimSpace(cid),
		strings.TrimSpace(nonce),
		strings.TrimSpace(token),
	}, "|")

	endpointConfigReplay.mu.Lock()
	defer endpointConfigReplay.mu.Unlock()

	for k, exp := range endpointConfigReplay.seen {
		if exp < now {
			delete(endpointConfigReplay.seen, k)
		}
	}

	if exp, exists := endpointConfigReplay.seen[replayToken]; exists && exp >= now {
		return errors.New("endpoint config request replay detected")
	}
	endpointConfigReplay.seen[replayToken] = expiry

	if len(endpointConfigReplay.seen) > endpointConfigReplayMaxEntry {
		toDelete := len(endpointConfigReplay.seen) - endpointConfigReplayMaxEntry
		for k := range endpointConfigReplay.seen {
			delete(endpointConfigReplay.seen, k)
			toDelete--
			if toDelete <= 0 {
				break
			}
		}
	}
	return nil
}

func decryptEndpointConfigIDFromRequest(r *http.Request, encryptedID, salt string) (string, string, []byte, error) {
	pinKey, _, err := getTLSPinHashForRequest(r)
	if err != nil {
		return "", "", nil, err
	}
	if !isTLSPinSaltAllowed(salt) {
		return "", "", nil, errors.New("invalid or expired salt")
	}
	raw, err := decodeTLSPinCiphertext(encryptedID)
	if err != nil {
		return "", "", nil, fmt.Errorf("invalid encrypted id format: %w", err)
	}
	plaintext, err := decryptWithTLSPinHash(pinKey, salt, raw)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to decrypt config id: %w", err)
	}

	var request encryptedEndpointConfigRequest
	if err := json.Unmarshal(plaintext, &request); err != nil {
		return "", "", nil, errors.New("invalid encrypted eid payload")
	}
	request.ConfigID = strings.TrimSpace(request.ConfigID)
	request.Nonce = strings.TrimSpace(request.Nonce)
	request.Token = strings.TrimSpace(request.Token)
	if request.ConfigID == "" || request.Nonce == "" || request.Token == "" || request.Timestamp == 0 {
		return "", "", nil, errors.New("incomplete encrypted eid payload")
	}
	if !isEndpointConfigTokenFresh(request.Timestamp) {
		return "", "", nil, errors.New("eid token expired")
	}

	expectedToken := computeEndpointConfigToken(pinKey, request.ConfigID, request.Nonce, request.Timestamp, salt)
	providedToken, err := hex.DecodeString(request.Token)
	if err != nil {
		return "", "", nil, errors.New("invalid eid token encoding")
	}
	expectedTokenBytes, _ := hex.DecodeString(expectedToken)
	if !hmac.Equal(providedToken, expectedTokenBytes) {
		return "", "", nil, errors.New("invalid eid token")
	}
	if err := registerEndpointConfigReplayToken(request.ConfigID, request.Nonce, request.Token, request.Timestamp); err != nil {
		return "", "", nil, err
	}
	return request.ConfigID, salt, pinKey, nil
}

func writeEncryptedJSONWithTLSPin(w http.ResponseWriter, pinKey []byte, salt string, payload interface{}) error {
	plain, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ciphertext, err := encryptWithTLSPinHash(pinKey, salt, plain)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(EncryptedPayloadEnvelope{
		Encrypted: true,
		Alg:       TLSPinAlgorithm,
		Salt:      salt,
		Payload:   encodeTLSPinCiphertext(ciphertext),
	})
}
