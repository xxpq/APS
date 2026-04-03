package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	controlPlaneFrameVersion  = uint8(1)
	controlPlaneReplayWindow  = 2 * time.Minute
	controlPlaneReplayEntries = 32768
)

type ControlPlaneFrame struct {
	Version       uint8  `json:"v"`
	Sequence      uint64 `json:"seq"`
	Timestamp     int64  `json:"ts"`
	ConfigVersion int64  `json:"cfgVersion"`
	Nonce         []byte `json:"nonce"`
	AAD           []byte `json:"aad"`
	Ciphertext    []byte `json:"ct"`
	Signature     []byte `json:"sig"`
}

type ControlPlaneOutboundState struct {
	mu      sync.Mutex
	nextSeq uint64
}

func NewControlPlaneOutboundState() *ControlPlaneOutboundState {
	return &ControlPlaneOutboundState{nextSeq: 1}
}

func (s *ControlPlaneOutboundState) NextSequence() uint64 {
	if s == nil {
		return 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nextSeq == 0 {
		s.nextSeq = 1
	}
	seq := s.nextSeq
	s.nextSeq++
	return seq
}

type ControlPlaneInboundState struct {
	mu                sync.Mutex
	seenSeq           map[uint64]int64
	highestSeq        uint64
	lastConfigVersion int64
}

func NewControlPlaneInboundState() *ControlPlaneInboundState {
	return &ControlPlaneInboundState{
		seenSeq: make(map[uint64]int64, 1024),
	}
}

func (s *ControlPlaneInboundState) registerFrame(seq uint64, ts int64, configVersion int64) error {
	if s == nil {
		return nil
	}
	if seq == 0 {
		return errors.New("invalid control sequence")
	}

	now := time.Now().UTC().Unix()
	if !isControlPlaneTimestampFresh(ts) {
		return errors.New("control frame timestamp out of window")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for seenSeq, exp := range s.seenSeq {
		if exp < now {
			delete(s.seenSeq, seenSeq)
		}
	}

	if configVersion < s.lastConfigVersion {
		return fmt.Errorf("control config version rollback detected: %d < %d", configVersion, s.lastConfigVersion)
	}

	if s.highestSeq == 0 {
		if seq != 1 {
			return fmt.Errorf("unexpected initial control sequence: %d", seq)
		}
	} else if seq != s.highestSeq+1 {
		if seq <= s.highestSeq {
			return errors.New("control frame replay or out-of-order sequence detected")
		}
		return fmt.Errorf("control sequence gap detected: got %d want %d", seq, s.highestSeq+1)
	}

	if exp, exists := s.seenSeq[seq]; exists && exp >= now {
		return errors.New("control frame replay detected")
	}

	expiry := ts + int64((controlPlaneReplayWindow + time.Minute).Seconds())
	s.seenSeq[seq] = expiry
	if seq > s.highestSeq {
		s.highestSeq = seq
	}
	if configVersion > s.lastConfigVersion {
		s.lastConfigVersion = configVersion
	}

	if len(s.seenSeq) > controlPlaneReplayEntries {
		toDelete := len(s.seenSeq) - controlPlaneReplayEntries
		for seenSeq := range s.seenSeq {
			delete(s.seenSeq, seenSeq)
			toDelete--
			if toDelete <= 0 {
				break
			}
		}
	}

	return nil
}

func isControlPlaneTimestampFresh(ts int64) bool {
	now := time.Now().UTC().Unix()
	delta := now - ts
	if delta < 0 {
		delta = -delta
	}
	return time.Duration(delta)*time.Second <= controlPlaneReplayWindow
}

func controlPlaneAAD(version, msgType uint8, seq uint64, ts int64, configVersion int64) []byte {
	aad := make([]byte, 1+1+8+8+8)
	aad[0] = version
	aad[1] = msgType
	binary.BigEndian.PutUint64(aad[2:10], seq)
	binary.BigEndian.PutUint64(aad[10:18], uint64(ts))
	binary.BigEndian.PutUint64(aad[18:26], uint64(configVersion))
	return aad
}

func deriveControlPlaneKeys(baseKey []byte) (encKey []byte, sigKey []byte) {
	encHasher := sha256.New()
	encHasher.Write(baseKey)
	encHasher.Write([]byte(":control-plane:enc:v1"))
	encKey = encHasher.Sum(nil)

	sigHasher := sha256.New()
	sigHasher.Write(baseKey)
	sigHasher.Write([]byte(":control-plane:sig:v1"))
	sigKey = sigHasher.Sum(nil)
	return encKey, sigKey
}

func computeControlPlaneSignature(sigKey []byte, msgType uint8, frame *ControlPlaneFrame) []byte {
	mac := hmac.New(sha256.New, sigKey)
	mac.Write([]byte{msgType, frame.Version})

	buf8 := make([]byte, 8)
	binary.BigEndian.PutUint64(buf8, frame.Sequence)
	mac.Write(buf8)
	binary.BigEndian.PutUint64(buf8, uint64(frame.Timestamp))
	mac.Write(buf8)
	binary.BigEndian.PutUint64(buf8, uint64(frame.ConfigVersion))
	mac.Write(buf8)

	mac.Write(frame.Nonce)
	mac.Write(frame.AAD)
	mac.Write(frame.Ciphertext)
	return mac.Sum(nil)
}

func wrapControlPayloadWithKey(baseKey []byte, msgType uint8, payload []byte, configVersion int64, seq uint64, ts int64) ([]byte, error) {
	encKey, sigKey := deriveControlPlaneKeys(baseKey)
	block, err := aes.NewCipher(encKey[:KeySize])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	aad := controlPlaneAAD(controlPlaneFrameVersion, msgType, seq, ts, configVersion)
	ciphertext := gcm.Seal(nil, nonce, payload, aad)

	frame := &ControlPlaneFrame{
		Version:       controlPlaneFrameVersion,
		Sequence:      seq,
		Timestamp:     ts,
		ConfigVersion: configVersion,
		Nonce:         nonce,
		AAD:           aad,
		Ciphertext:    ciphertext,
	}
	frame.Signature = computeControlPlaneSignature(sigKey, msgType, frame)
	return json.Marshal(frame)
}

func WrapControlPlanePayload(km *SessionKeyManager, msgType uint8, payload []byte, configVersion int64, state *ControlPlaneOutboundState) ([]byte, error) {
	if km == nil {
		return nil, errors.New("session key manager is nil")
	}
	km.mu.RLock()
	baseKey := append([]byte(nil), km.currentKey...)
	km.mu.RUnlock()
	if len(baseKey) == 0 {
		return nil, errors.New("no active control-plane key")
	}

	if state == nil {
		state = NewControlPlaneOutboundState()
	}
	seq := state.NextSequence()
	ts := time.Now().UTC().Unix()
	return wrapControlPayloadWithKey(baseKey, msgType, payload, configVersion, seq, ts)
}

func unwrapControlPayloadWithKey(baseKey []byte, msgType uint8, frame *ControlPlaneFrame) ([]byte, error) {
	encKey, sigKey := deriveControlPlaneKeys(baseKey)
	expectedSig := computeControlPlaneSignature(sigKey, msgType, frame)
	if !hmac.Equal(frame.Signature, expectedSig) {
		return nil, errors.New("invalid control signature")
	}

	block, err := aes.NewCipher(encKey[:KeySize])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, frame.Nonce, frame.Ciphertext, frame.AAD)
}

func UnwrapControlPlanePayload(km *SessionKeyManager, msgType uint8, payload []byte, state *ControlPlaneInboundState) ([]byte, error) {
	if km == nil {
		return nil, errors.New("session key manager is nil")
	}
	if state == nil {
		state = NewControlPlaneInboundState()
	}

	var frame ControlPlaneFrame
	if err := json.Unmarshal(payload, &frame); err != nil {
		return nil, fmt.Errorf("invalid control frame: %w", err)
	}
	if frame.Version != controlPlaneFrameVersion {
		return nil, fmt.Errorf("unsupported control frame version: %d", frame.Version)
	}
	if len(frame.Nonce) != NonceSize {
		return nil, errors.New("invalid control nonce length")
	}
	expectedAAD := controlPlaneAAD(frame.Version, msgType, frame.Sequence, frame.Timestamp, frame.ConfigVersion)
	if !hmac.Equal(frame.AAD, expectedAAD) {
		return nil, errors.New("invalid control aad")
	}

	if !isSecureTimestampFresh(frame.Timestamp) {
		return nil, errors.New("control frame timestamp out of window")
	}

	km.mu.RLock()
	currentKey := append([]byte(nil), km.currentKey...)
	previousKey := append([]byte(nil), km.previousKey...)
	graceEnds := km.gracePeriodEnds
	km.mu.RUnlock()

	keyCandidates := make([][]byte, 0, 2)
	if len(currentKey) > 0 {
		keyCandidates = append(keyCandidates, currentKey)
	}
	if len(previousKey) > 0 && time.Now().Before(graceEnds) {
		keyCandidates = append(keyCandidates, previousKey)
	}
	if len(keyCandidates) == 0 {
		return nil, errors.New("no control-plane keys available")
	}

	var plaintext []byte
	var decryptErr error
	for _, key := range keyCandidates {
		plaintext, decryptErr = unwrapControlPayloadWithKey(key, msgType, &frame)
		if decryptErr == nil {
			break
		}
	}
	if decryptErr != nil {
		return nil, decryptErr
	}

	if err := state.registerFrame(frame.Sequence, frame.Timestamp, frame.ConfigVersion); err != nil {
		return nil, err
	}

	return plaintext, nil
}
