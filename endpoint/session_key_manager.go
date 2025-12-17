package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"sync"
	"time"
)

// Key rotation parameters
const (
	KeyRotationMinInterval = 30 * time.Minute // Minimum rotation interval
	KeyRotationMaxInterval = 60 * time.Minute // Maximum rotation interval
	KeyGracePeriod         = 5 * time.Minute  // Old key valid for this long after rotation
	KeySize                = 32               // AES-256 key size
	NonceSize              = 12               // GCM nonce size
)

// SessionKeyManager manages encryption keys with automatic rotation
type SessionKeyManager struct {
	currentKey      []byte       // Active encryption key
	previousKey     []byte       // Previous key (valid during grace period)
	keyCreatedAt    time.Time    // When current key was created
	gracePeriodEnds time.Time    // When previous key expires
	rotationTimer   *time.Timer  // Auto-rotation timer
	masterPassword  string       // Master password for key derivation
	isInitiator     bool         // Whether this side initiated the last key exchange
	pendingKey      []byte       // Key being negotiated
	pendingNonce    []byte       // Nonce for pending negotiation
	onKeyRotated    func([]byte) // Callback when key is rotated
	endpointName    string       // Name of the endpoint for logging purposes
	mu              sync.RWMutex
}

// KeyRequestPayload is sent to initiate key negotiation
type KeyRequestPayload struct {
	Nonce     []byte `json:"nonce"`     // Random nonce for this negotiation
	Timestamp int64  `json:"timestamp"` // Request timestamp
}

// KeyResponsePayload contains the encrypted new key
type KeyResponsePayload struct {
	Nonce        []byte `json:"nonce"`         // Responder's nonce
	EncryptedKey []byte `json:"encrypted_key"` // New key encrypted with current key
	Timestamp    int64  `json:"timestamp"`
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
	}
}

// DeriveInitialKey derives the initial session key from master password
func (skm *SessionKeyManager) DeriveInitialKey() error {
	skm.mu.Lock()
	defer skm.mu.Unlock()

	// Derive key from master password using SHA-256
	hash := sha256.Sum256([]byte(skm.masterPassword + ":session_key"))
	skm.currentKey = hash[:]
	skm.keyCreatedAt = time.Now()

	log.Printf("[KEY] [%s] Initial session key derived", skm.endpointName)
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

	log.Printf("[KEY] [%s] Auto-rotation scheduled in %v", skm.endpointName, interval)
}

// StopAutoRotation stops the automatic key rotation
func (skm *SessionKeyManager) StopAutoRotation() {
	skm.mu.Lock()
	defer skm.mu.Unlock()

	if skm.rotationTimer != nil {
		skm.rotationTimer.Stop()
		skm.rotationTimer = nil
	}
}

// randomRotationInterval returns a random interval between min and max
func (skm *SessionKeyManager) randomRotationInterval() time.Duration {
	diff := KeyRotationMaxInterval - KeyRotationMinInterval
	randomDiff, _ := rand.Int(rand.Reader, big.NewInt(int64(diff)))
	return KeyRotationMinInterval + time.Duration(randomDiff.Int64())
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

	return &KeyRequestPayload{
		Nonce:     nonce,
		Timestamp: time.Now().UnixNano(),
	}, nil
}

// HandleKeyRequest processes an incoming key request and generates response
func (skm *SessionKeyManager) HandleKeyRequest(req *KeyRequestPayload) (*KeyResponsePayload, error) {
	skm.mu.Lock()
	defer skm.mu.Unlock()

	// Generate new session key
	newKey := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return nil, fmt.Errorf("failed to generate new key: %w", err)
	}

	// Encrypt new key with current key
	encryptedKey, err := skm.encryptWithKey(skm.currentKey, newKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt new key: %w", err)
	}

	// Generate response nonce
	respNonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, respNonce); err != nil {
		return nil, fmt.Errorf("failed to generate response nonce: %w", err)
	}

	// Store pending key
	skm.pendingKey = newKey
	skm.isInitiator = false

	return &KeyResponsePayload{
		Nonce:        respNonce,
		EncryptedKey: encryptedKey,
		Timestamp:    time.Now().UnixNano(),
	}, nil
}

// HandleKeyResponse processes a key response and extracts the new key
func (skm *SessionKeyManager) HandleKeyResponse(resp *KeyResponsePayload) (*KeyConfirmPayload, error) {
	skm.mu.Lock()
	defer skm.mu.Unlock()

	if !skm.isInitiator {
		return nil, errors.New("unexpected key response - not an initiator")
	}

	// Decrypt the new key
	newKey, err := skm.decryptWithKey(skm.currentKey, resp.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt new key: %w", err)
	}

	// Store pending key
	skm.pendingKey = newKey

	// Generate confirmation with key hash
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
	skm.previousKey = skm.currentKey
	skm.currentKey = skm.pendingKey
	skm.pendingKey = nil
	skm.keyCreatedAt = time.Now()
	skm.gracePeriodEnds = time.Now().Add(KeyGracePeriod)

	log.Printf("[KEY] [%s] New session key activated (grace period ends: %v)", skm.endpointName, skm.gracePeriodEnds)

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
	skm.previousKey = skm.currentKey
	skm.currentKey = skm.pendingKey
	skm.pendingKey = nil
	skm.keyCreatedAt = time.Now()
	skm.gracePeriodEnds = time.Now().Add(KeyGracePeriod)

	log.Printf("[KEY] [%s] New session key activated by initiator (grace period ends: %v)", skm.endpointName, skm.gracePeriodEnds)

	// Call rotation callback if set
	if skm.onKeyRotated != nil {
		skm.onKeyRotated(skm.currentKey)
	}

	return nil
}

// Encrypt encrypts data with the current key
func (skm *SessionKeyManager) Encrypt(plaintext []byte) ([]byte, error) {
	skm.mu.RLock()
	key := skm.currentKey
	skm.mu.RUnlock()

	if key == nil {
		return nil, errors.New("no encryption key available")
	}

	return skm.encryptWithKey(key, plaintext)
}

// Decrypt decrypts data, trying current key first, then previous key during grace period
func (skm *SessionKeyManager) Decrypt(ciphertext []byte) ([]byte, error) {
	skm.mu.RLock()
	currentKey := skm.currentKey
	previousKey := skm.previousKey
	gracePeriodEnds := skm.gracePeriodEnds
	skm.mu.RUnlock()

	// Try current key first
	if currentKey != nil {
		plaintext, err := skm.decryptWithKey(currentKey, ciphertext)
		if err == nil {
			return plaintext, nil
		}
	}

	// During grace period, try previous key
	if previousKey != nil && time.Now().Before(gracePeriodEnds) {
		plaintext, err := skm.decryptWithKey(previousKey, ciphertext)
		if err == nil {
			log.Printf("[KEY] [%s] Decrypted with previous key (grace period)", skm.endpointName)
			return plaintext, nil
		}
	}

	return nil, errors.New("failed to decrypt with any available key")
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
