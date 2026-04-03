package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// Key rotation parameters
const (
	KeyRotationMinInterval = 30 * time.Minute // Minimum rotation interval
	KeyRotationMaxInterval = 60 * time.Minute // Maximum rotation interval
	KeyGracePeriod         = 5 * time.Minute  // Old key valid for this long after rotation
	KeySize                = 32               // AES-256 key size
	NonceSize              = 12               // GCM nonce size
	SecureEnvelopeVersion  = 0xA1             // Secure envelope marker
	SecureReplayWindow     = 5 * time.Minute  // Timestamp/replay window
	SecureReplayMaxEntries = 20000            // Anti-replay cache cap
	KeyMaterialMaxLifetime = KeyRotationMaxInterval + KeyGracePeriod + 10*time.Minute

	secureSaltLayout     = "200601021504"
	KDFVersionArgon2idV1 = "argon2id-v1"
	KDFVersionPBKDF2V3   = "pbkdf2-sha256-v3"
	DefaultKDFVersion    = KDFVersionArgon2idV1

	kdfArgon2Time       = uint32(3)
	kdfArgon2MemoryKB   = uint32(64 * 1024)
	kdfArgon2Threads    = uint8(4)
	kdfPBKDF2Rounds     = 600000
	legacyKeyDeriveSalt = "aps:transport-key:v2"
	keyRotateInfoLabel  = "aps:key-rotation:v3"
)

// SessionKeyManager manages encryption keys with automatic rotation
type SessionKeyManager struct {
	currentKey      []byte      // Active encryption key
	previousKey     []byte      // Previous key (valid during grace period)
	keyCreatedAt    time.Time   // When current key was created
	gracePeriodEnds time.Time   // When previous key expires
	rotationTimer   *time.Timer // Auto-rotation timer
	masterPassword  string      // Master password for key derivation
	isInitiator     bool        // Whether this side initiated the last key exchange
	pendingKey      []byte      // Key being negotiated
	pendingNonce    []byte      // Nonce for pending negotiation
	pendingECDHPriv *ecdh.PrivateKey
	pendingECDHPub  []byte
	onKeyRotated    func([]byte) // Callback when key is rotated
	endpointName    string       // Name of the endpoint for logging purposes
	secureEnabled   bool         // Whether secure transport mode is enabled
	tlsPinHash      []byte       // SPKI hash used for key derivation hardening
	transportCID    string       // Endpoint config ID bound to transport key derivation
	kdfVersion      string       // KDF version (argon2id-v1 or pbkdf2-sha256-v3)
	kdfSalt         string       // KDF salt from tunnel config
	replaySeen      map[string]int64
	replayOpCount   uint64
	mu              sync.RWMutex
}

// KeyRequestPayload is sent to initiate key negotiation
type KeyRequestPayload struct {
	Nonce           []byte `json:"nonce"`                       // Random nonce for this negotiation
	Timestamp       int64  `json:"timestamp"`                   // Request timestamp
	EphemeralPubKey []byte `json:"ephemeral_pub_key,omitempty"` // Initiator ephemeral ECDH public key
}

// KeyResponsePayload contains the encrypted new key
type KeyResponsePayload struct {
	Nonce           []byte `json:"nonce"`                   // Responder's nonce
	EncryptedKey    []byte `json:"encrypted_key,omitempty"` // Legacy field for compatibility
	Timestamp       int64  `json:"timestamp"`
	EphemeralPubKey []byte `json:"ephemeral_pub_key,omitempty"` // Responder ephemeral ECDH public key
}

// KeyConfirmPayload confirms key activation
type KeyConfirmPayload struct {
	KeyHash   []byte `json:"key_hash"` // SHA256 of new key for verification
	Timestamp int64  `json:"timestamp"`
}

// NewSessionKeyManager creates a new session key manager
func NewSessionKeyManager(masterPassword string, endpointName string) *SessionKeyManager {
	return &SessionKeyManager{
		masterPassword: masterPassword,
		endpointName:   endpointName,
		kdfVersion:     DefaultKDFVersion,
	}
}

func normalizeEndpointKDFVersion(version string) (string, error) {
	version = strings.ToLower(strings.TrimSpace(version))
	if version == "" {
		return DefaultKDFVersion, nil
	}
	switch version {
	case KDFVersionArgon2idV1, KDFVersionPBKDF2V3:
		return version, nil
	default:
		return "", fmt.Errorf("unsupported kdfVersion: %s", version)
	}
}

func (skm *SessionKeyManager) SetKDFParams(version, salt string) error {
	normalizedVersion, err := normalizeEndpointKDFVersion(version)
	if err != nil {
		return err
	}

	salt = strings.TrimSpace(salt)
	if salt == "" {
		return errors.New("kdfSalt is required")
	}

	skm.mu.Lock()
	skm.kdfVersion = normalizedVersion
	skm.kdfSalt = salt
	skm.mu.Unlock()
	return nil
}

func deriveInitialKeyWithKDF(masterPassword, version, salt string) ([]byte, error) {
	normalizedVersion, err := normalizeEndpointKDFVersion(version)
	if err != nil {
		return nil, err
	}

	kdfSalt := strings.TrimSpace(salt)
	if kdfSalt == "" {
		return nil, errors.New("kdfSalt is required before deriving initial key")
	}

	switch normalizedVersion {
	case KDFVersionArgon2idV1:
		return argon2.IDKey(
			[]byte(masterPassword),
			[]byte(kdfSalt),
			kdfArgon2Time,
			kdfArgon2MemoryKB,
			kdfArgon2Threads,
			KeySize,
		), nil
	case KDFVersionPBKDF2V3:
		return pbkdf2.Key([]byte(masterPassword), []byte(kdfSalt), kdfPBKDF2Rounds, KeySize, sha256.New), nil
	default:
		return pbkdf2.Key([]byte(masterPassword), []byte(legacyKeyDeriveSalt), kdfPBKDF2Rounds, KeySize, sha256.New), nil
	}
}

// DeriveInitialKey derives the initial session key from master password
func (skm *SessionKeyManager) DeriveInitialKey() error {
	skm.mu.Lock()
	defer skm.mu.Unlock()

	kdfVersion := strings.TrimSpace(skm.kdfVersion)
	if kdfVersion == "" {
		kdfVersion = DefaultKDFVersion
	}
	derivedKey, err := deriveInitialKeyWithKDF(skm.masterPassword, kdfVersion, skm.kdfSalt)
	if err != nil {
		return err
	}

	skm.currentKey = derivedKey
	skm.keyCreatedAt = time.Now()

	DebugLog("[KEY] [%s] Initial session key derived (%s)", skm.endpointName, kdfVersion)
	return nil
}

// EnableSecureTransport enables secure transport hardening with SPKI hash + CID + ts salt.
func (skm *SessionKeyManager) EnableSecureTransport(pinHash []byte, cid string) error {
	skm.mu.Lock()
	defer skm.mu.Unlock()
	cid = strings.TrimSpace(cid)

	if len(pinHash) == 0 || cid == "" {
		return errors.New("secure transport requires non-empty pin hash and cid")
	}

	skm.secureEnabled = true
	skm.tlsPinHash = append([]byte(nil), pinHash...)
	skm.transportCID = cid
	if skm.replaySeen == nil {
		skm.replaySeen = make(map[string]int64, 1024)
	}
	DebugLog("[SECURE] [%s] Secure transport enabled (SPKI hash %s, cid %s)", skm.endpointName, hex.EncodeToString(pinHash), cid)
	return nil
}

// StartAutoRotation starts the automatic key rotation timer
func (skm *SessionKeyManager) StartAutoRotation(initiateFunc func() error) {
	skm.mu.Lock()
	defer skm.mu.Unlock()

	// Random interval between min and max
	interval := skm.randomRotationInterval()
	skm.rotationTimer = time.AfterFunc(interval, func() {
		if err := initiateFunc(); err != nil {
			log.Printf("[KEY] [%s] Auto-rotation initiation failed: %v", skm.endpointName, err)
		}
		// Reschedule for next rotation
		skm.StartAutoRotation(initiateFunc)
	})

	DebugLog("[KEY] [%s] Auto-rotation scheduled in %v", skm.endpointName, interval)
}

// StopAutoRotation stops the automatic key rotation
func (skm *SessionKeyManager) StopAutoRotation() {
	skm.mu.Lock()
	defer skm.mu.Unlock()

	if skm.rotationTimer != nil {
		skm.rotationTimer.Stop()
		skm.rotationTimer = nil
	}
	skm.zeroizeKeyMaterialLocked(true)
}

// randomRotationInterval returns a random interval between min and max
func (skm *SessionKeyManager) randomRotationInterval() time.Duration {
	diff := KeyRotationMaxInterval - KeyRotationMinInterval
	randomDiff, _ := rand.Int(rand.Reader, big.NewInt(int64(diff)))
	return KeyRotationMinInterval + time.Duration(randomDiff.Int64())
}

func zeroBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

func (skm *SessionKeyManager) zeroizeKeyMaterialLocked(clearCurrent bool) {
	if skm.previousKey != nil {
		zeroBytes(skm.previousKey)
		skm.previousKey = nil
	}
	if clearCurrent && skm.currentKey != nil {
		zeroBytes(skm.currentKey)
		skm.currentKey = nil
	}
	if skm.pendingKey != nil {
		zeroBytes(skm.pendingKey)
		skm.pendingKey = nil
	}
	if skm.pendingNonce != nil {
		zeroBytes(skm.pendingNonce)
		skm.pendingNonce = nil
	}
	if skm.pendingECDHPub != nil {
		zeroBytes(skm.pendingECDHPub)
		skm.pendingECDHPub = nil
	}
	skm.pendingECDHPriv = nil
}

func (skm *SessionKeyManager) enforceKeyMaterialLifetime(now time.Time) error {
	skm.mu.Lock()
	defer skm.mu.Unlock()

	if skm.previousKey != nil && !skm.gracePeriodEnds.IsZero() && now.After(skm.gracePeriodEnds) {
		zeroBytes(skm.previousKey)
		skm.previousKey = nil
	}
	if skm.currentKey == nil {
		return errors.New("no encryption key available")
	}
	if !skm.keyCreatedAt.IsZero() && now.Sub(skm.keyCreatedAt) > KeyMaterialMaxLifetime {
		skm.zeroizeKeyMaterialLocked(true)
		return errors.New("session key material lifetime exceeded; reconnect required")
	}
	return nil
}

func deriveForwardSecureRotatedKey(sharedSecret, reqNonce, respNonce, initiatorPub, responderPub []byte) ([]byte, error) {
	if len(sharedSecret) == 0 {
		return nil, errors.New("shared secret is empty")
	}
	saltH := sha256.New()
	saltH.Write(reqNonce)
	saltH.Write([]byte{':'})
	saltH.Write(respNonce)
	salt := saltH.Sum(nil)

	infoH := sha256.New()
	infoH.Write([]byte(keyRotateInfoLabel))
	infoH.Write([]byte{':'})
	infoH.Write(initiatorPub)
	infoH.Write([]byte{':'})
	infoH.Write(responderPub)
	info := infoH.Sum(nil)

	reader := hkdf.New(sha256.New, sharedSecret, salt, info)
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateKeyRequest creates a key negotiation request
func (skm *SessionKeyManager) GenerateKeyRequest() (*KeyRequestPayload, error) {
	skm.mu.Lock()
	defer skm.mu.Unlock()

	// Generate random nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	skm.pendingNonce = nonce
	skm.isInitiator = true
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ecdh key: %w", err)
	}
	skm.pendingECDHPriv = priv
	skm.pendingECDHPub = priv.PublicKey().Bytes()

	return &KeyRequestPayload{
		Nonce:           nonce,
		Timestamp:       time.Now().UnixNano(),
		EphemeralPubKey: append([]byte(nil), skm.pendingECDHPub...),
	}, nil
}

// HandleKeyRequest processes an incoming key request and generates response
func (skm *SessionKeyManager) HandleKeyRequest(req *KeyRequestPayload) (*KeyResponsePayload, error) {
	skm.mu.Lock()
	defer skm.mu.Unlock()

	if len(req.EphemeralPubKey) == 0 {
		return nil, errors.New("missing initiator ecdh public key")
	}
	initiatorPub, err := ecdh.P256().NewPublicKey(req.EphemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("invalid initiator ecdh public key: %w", err)
	}

	responderPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate responder ecdh key: %w", err)
	}
	responderPub := responderPriv.PublicKey().Bytes()

	respNonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, respNonce); err != nil {
		return nil, fmt.Errorf("failed to generate response nonce: %w", err)
	}

	sharedSecret, err := responderPriv.ECDH(initiatorPub)
	if err != nil {
		return nil, fmt.Errorf("failed to compute ecdh shared secret: %w", err)
	}
	newKey, err := deriveForwardSecureRotatedKey(
		sharedSecret,
		req.Nonce,
		respNonce,
		req.EphemeralPubKey,
		responderPub,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive rotated key: %w", err)
	}

	skm.pendingKey = newKey
	skm.isInitiator = false
	skm.pendingECDHPriv = nil
	skm.pendingECDHPub = nil

	return &KeyResponsePayload{
		Nonce:           respNonce,
		Timestamp:       time.Now().UnixNano(),
		EphemeralPubKey: responderPub,
	}, nil
}

// HandleKeyResponse processes a key response and extracts the new key
func (skm *SessionKeyManager) HandleKeyResponse(resp *KeyResponsePayload) (*KeyConfirmPayload, error) {
	skm.mu.Lock()
	defer skm.mu.Unlock()

	if !skm.isInitiator {
		return nil, errors.New("unexpected key response - not an initiator")
	}
	if skm.pendingECDHPriv == nil {
		return nil, errors.New("missing pending initiator ecdh private key")
	}
	if len(resp.EphemeralPubKey) == 0 {
		return nil, errors.New("missing responder ecdh public key")
	}
	responderPub, err := ecdh.P256().NewPublicKey(resp.EphemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("invalid responder ecdh public key: %w", err)
	}

	sharedSecret, err := skm.pendingECDHPriv.ECDH(responderPub)
	if err != nil {
		return nil, fmt.Errorf("failed to compute ecdh shared secret: %w", err)
	}
	newKey, err := deriveForwardSecureRotatedKey(
		sharedSecret,
		skm.pendingNonce,
		resp.Nonce,
		skm.pendingECDHPub,
		resp.EphemeralPubKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive rotated key: %w", err)
	}

	skm.pendingKey = newKey
	skm.pendingECDHPriv = nil
	skm.pendingECDHPub = nil

	keyHash := sha256.Sum256(newKey)
	return &KeyConfirmPayload{
		KeyHash:   keyHash[:],
		Timestamp: time.Now().UnixNano(),
	}, nil
}

// HandleKeyConfirm processes key confirmation and activates the new key
func (skm *SessionKeyManager) HandleKeyConfirm(confirm *KeyConfirmPayload) error {
	skm.mu.Lock()
	defer skm.mu.Unlock()

	if skm.pendingKey == nil {
		return errors.New("no pending key to confirm")
	}

	// Verify key hash
	keyHash := sha256.Sum256(skm.pendingKey)
	if len(confirm.KeyHash) != len(keyHash) {
		return errors.New("key hash length mismatch")
	}
	for i := range keyHash {
		if confirm.KeyHash[i] != keyHash[i] {
			return errors.New("key hash verification failed")
		}
	}

	// Activate new key
	if skm.previousKey != nil {
		zeroBytes(skm.previousKey)
	}
	skm.previousKey = skm.currentKey
	skm.currentKey = skm.pendingKey
	skm.pendingKey = nil
	skm.pendingNonce = nil
	skm.pendingECDHPriv = nil
	skm.pendingECDHPub = nil
	skm.keyCreatedAt = time.Now()
	skm.gracePeriodEnds = time.Now().Add(KeyGracePeriod)

	DebugLog("[KEY] [%s] New session key activated (grace period ends: %v)", skm.endpointName, skm.gracePeriodEnds)

	// Call rotation callback if set
	if skm.onKeyRotated != nil {
		skm.onKeyRotated(skm.currentKey)
	}

	return nil
}

// ActivateKey activates a confirmed key (for initiator after sending confirm)
func (skm *SessionKeyManager) ActivateKey() error {
	skm.mu.Lock()
	defer skm.mu.Unlock()

	if skm.pendingKey == nil {
		return errors.New("no pending key to activate")
	}

	// Activate new key
	if skm.previousKey != nil {
		zeroBytes(skm.previousKey)
	}
	skm.previousKey = skm.currentKey
	skm.currentKey = skm.pendingKey
	skm.pendingKey = nil
	skm.pendingNonce = nil
	skm.pendingECDHPriv = nil
	skm.pendingECDHPub = nil
	skm.keyCreatedAt = time.Now()
	skm.gracePeriodEnds = time.Now().Add(KeyGracePeriod)

	DebugLog("[KEY] [%s] New session key activated by initiator (grace period ends: %v)", skm.endpointName, skm.gracePeriodEnds)

	// Call rotation callback if set
	if skm.onKeyRotated != nil {
		skm.onKeyRotated(skm.currentKey)
	}

	return nil
}

// Encrypt encrypts data with the current key
func (skm *SessionKeyManager) Encrypt(plaintext []byte) ([]byte, error) {
	if err := skm.enforceKeyMaterialLifetime(time.Now().UTC()); err != nil {
		return nil, err
	}

	skm.mu.RLock()
	key := skm.currentKey
	secureEnabled := skm.secureEnabled
	pinHash := append([]byte(nil), skm.tlsPinHash...)
	transportCID := skm.transportCID
	skm.mu.RUnlock()

	if key == nil {
		return nil, errors.New("no encryption key available")
	}

	if !secureEnabled {
		return nil, errors.New("secure transport is not enabled")
	}

	return skm.encryptSecureMessage(key, pinHash, transportCID, plaintext)
}

// Decrypt decrypts data, trying current key first, then previous key during grace period
func (skm *SessionKeyManager) Decrypt(ciphertext []byte) ([]byte, error) {
	if err := skm.enforceKeyMaterialLifetime(time.Now().UTC()); err != nil {
		return nil, err
	}

	skm.mu.RLock()
	currentKey := skm.currentKey
	previousKey := skm.previousKey
	gracePeriodEnds := skm.gracePeriodEnds
	secureEnabled := skm.secureEnabled
	pinHash := append([]byte(nil), skm.tlsPinHash...)
	transportCID := skm.transportCID
	skm.mu.RUnlock()

	if !secureEnabled {
		return nil, errors.New("secure transport is not enabled")
	}

	if len(ciphertext) < 1+8 || ciphertext[0] != SecureEnvelopeVersion {
		return nil, errors.New("secure transport requires protected envelope")
	}
	return skm.decryptSecureMessage(currentKey, previousKey, gracePeriodEnds, pinHash, transportCID, ciphertext)
}

func (skm *SessionKeyManager) encryptSecureMessage(key, pinHash []byte, cid string, plaintext []byte) ([]byte, error) {
	if len(pinHash) == 0 {
		return nil, errors.New("secure transport pin hash missing")
	}
	if strings.TrimSpace(cid) == "" {
		return nil, errors.New("secure transport cid missing")
	}

	ts := time.Now().UTC().Unix()
	derivedKey := deriveSecureMessageKey(key, pinHash, cid, ts)
	innerCiphertext, err := skm.encryptWithKey(derivedKey, plaintext)
	if err != nil {
		return nil, err
	}

	envelope := make([]byte, 1+8+len(innerCiphertext))
	envelope[0] = SecureEnvelopeVersion
	binary.BigEndian.PutUint64(envelope[1:9], uint64(ts))
	copy(envelope[9:], innerCiphertext)
	return envelope, nil
}

func (skm *SessionKeyManager) decryptSecureMessage(currentKey, previousKey []byte, gracePeriodEnds time.Time, pinHash []byte, cid string, ciphertext []byte) ([]byte, error) {
	if len(pinHash) == 0 {
		return nil, errors.New("secure transport pin hash missing")
	}
	if strings.TrimSpace(cid) == "" {
		return nil, errors.New("secure transport cid missing")
	}
	if len(ciphertext) < 1+8 {
		return nil, errors.New("secure envelope too short")
	}

	ts := int64(binary.BigEndian.Uint64(ciphertext[1:9]))
	if !isSecureTimestampFresh(ts) {
		return nil, errors.New("secure envelope timestamp out of window")
	}

	innerCiphertext := ciphertext[9:]

	if currentKey != nil {
		derivedKey := deriveSecureMessageKey(currentKey, pinHash, cid, ts)
		plaintext, err := skm.decryptWithKey(derivedKey, innerCiphertext)
		if err == nil {
			if replayErr := skm.registerReplayCiphertext(ciphertext, ts); replayErr != nil {
				return nil, replayErr
			}
			return plaintext, nil
		}
	}

	if previousKey != nil && time.Now().Before(gracePeriodEnds) {
		derivedKey := deriveSecureMessageKey(previousKey, pinHash, cid, ts)
		plaintext, err := skm.decryptWithKey(derivedKey, innerCiphertext)
		if err == nil {
			if replayErr := skm.registerReplayCiphertext(ciphertext, ts); replayErr != nil {
				return nil, replayErr
			}
			DebugLog("[KEY] [%s] Decrypted secure envelope with previous key (grace period)", skm.endpointName)
			return plaintext, nil
		}
	}

	return nil, errors.New("failed to decrypt secure envelope with any available key")
}

func deriveSecureMessageKey(baseKey, pinHash []byte, cid string, ts int64) []byte {
	salt := time.Unix(ts, 0).UTC().Format(secureSaltLayout)
	h := sha256.New()
	h.Write(baseKey)
	h.Write([]byte{':'})
	h.Write(pinHash)
	h.Write([]byte{':'})
	h.Write([]byte(strings.TrimSpace(cid)))
	h.Write([]byte{':'})
	h.Write([]byte(salt))
	return h.Sum(nil)
}

func isSecureTimestampFresh(ts int64) bool {
	now := time.Now().UTC().Unix()
	delta := now - ts
	if delta < 0 {
		delta = -delta
	}
	return time.Duration(delta)*time.Second <= SecureReplayWindow
}

func (skm *SessionKeyManager) registerReplayCiphertext(ciphertext []byte, ts int64) error {
	tokenHash := sha256.Sum256(ciphertext)
	token := hex.EncodeToString(tokenHash[:16])

	now := time.Now().UTC().Unix()
	expiry := ts + int64((SecureReplayWindow + time.Minute).Seconds())

	skm.mu.Lock()
	defer skm.mu.Unlock()

	if skm.replaySeen == nil {
		skm.replaySeen = make(map[string]int64, 1024)
	}

	skm.replayOpCount++
	if skm.replayOpCount%128 == 0 || len(skm.replaySeen) > SecureReplayMaxEntries {
		for k, exp := range skm.replaySeen {
			if exp < now {
				delete(skm.replaySeen, k)
			}
		}
	}

	if exp, exists := skm.replaySeen[token]; exists && exp >= now {
		return errors.New("replay detected")
	}
	skm.replaySeen[token] = expiry

	if len(skm.replaySeen) > SecureReplayMaxEntries {
		toDelete := len(skm.replaySeen) - SecureReplayMaxEntries
		for k := range skm.replaySeen {
			delete(skm.replaySeen, k)
			toDelete--
			if toDelete <= 0 {
				break
			}
		}
	}
	return nil
}

// encryptWithKey encrypts data with a specific key using AES-GCM
func (skm *SessionKeyManager) encryptWithKey(key, plaintext []byte) ([]byte, error) {
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

	// Prepend nonce to ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decryptWithKey decrypts data with a specific key using AES-GCM
func (skm *SessionKeyManager) decryptWithKey(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

// GetCurrentKey returns the current encryption key
func (skm *SessionKeyManager) GetCurrentKey() []byte {
	skm.mu.RLock()
	defer skm.mu.RUnlock()
	return skm.currentKey
}

// SetOnKeyRotated sets a callback for when key is rotated
func (skm *SessionKeyManager) SetOnKeyRotated(callback func([]byte)) {
	skm.mu.Lock()
	defer skm.mu.Unlock()
	skm.onKeyRotated = callback
}

// MarshalKeyRequest marshals a key request to JSON
func MarshalKeyRequest(req *KeyRequestPayload) ([]byte, error) {
	return json.Marshal(req)
}

// UnmarshalKeyRequest unmarshals a key request from JSON
func UnmarshalKeyRequest(data []byte) (*KeyRequestPayload, error) {
	var req KeyRequestPayload
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// MarshalKeyResponse marshals a key response to JSON
func MarshalKeyResponse(resp *KeyResponsePayload) ([]byte, error) {
	return json.Marshal(resp)
}

// UnmarshalKeyResponse unmarshals a key response from JSON
func UnmarshalKeyResponse(data []byte) (*KeyResponsePayload, error) {
	var resp KeyResponsePayload
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// MarshalKeyConfirm marshals a key confirm to JSON
func MarshalKeyConfirm(confirm *KeyConfirmPayload) ([]byte, error) {
	return json.Marshal(confirm)
}

// UnmarshalKeyConfirm unmarshals a key confirm from JSON
func UnmarshalKeyConfirm(data []byte) (*KeyConfirmPayload, error) {
	var confirm KeyConfirmPayload
	if err := json.Unmarshal(data, &confirm); err != nil {
		return nil, err
	}
	return &confirm, nil
}
