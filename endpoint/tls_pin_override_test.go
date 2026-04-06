package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func resetEndpointTLSPinCacheForTest() {
	endpointTLSPins.mu.Lock()
	defer endpointTLSPins.mu.Unlock()
	endpointTLSPins.byAddress = make(map[string]*endpointTLSPin)
}

func TestParseEndpointTLSPinHashHex(t *testing.T) {
	rawHex := strings.Repeat("ab", sha256.Size)
	hash, err := parseEndpointTLSPinHashHex("sha256:" + rawHex)
	if err != nil {
		t.Fatalf("parse pin hash failed: %v", err)
	}
	if got := hex.EncodeToString(hash); got != rawHex {
		t.Fatalf("unexpected hash decoded: got=%s want=%s", got, rawHex)
	}
}

func TestResolveEndpointTLSPinOverrideFromRawTokenHash(t *testing.T) {
	oldToken := *pinToken
	oldCID := *configID
	defer func() {
		*pinToken = oldToken
		*configID = oldCID
	}()

	rawHex := strings.Repeat("cd", sha256.Size)
	*pinToken = "sha256:" + rawHex
	*configID = "cid-test"
	t.Setenv(endpointTLSPinTokenEnv, "")

	hash, source, err := resolveEndpointTLSPinOverride("a.l-l.cn")
	if err != nil {
		t.Fatalf("resolve pin override failed: %v", err)
	}
	if len(hash) != sha256.Size {
		t.Fatalf("unexpected hash length: %d", len(hash))
	}
	if got := hex.EncodeToString(hash); got != rawHex {
		t.Fatalf("unexpected hash: got=%s want=%s", got, rawHex)
	}
	if source != "token(raw-hash)" {
		t.Fatalf("unexpected override source: %s", source)
	}
}

func TestResolveEndpointTLSPinOverrideFromEncryptedToken(t *testing.T) {
	oldToken := *pinToken
	oldCID := *configID
	defer func() {
		*pinToken = oldToken
		*configID = oldCID
	}()

	rawHex := strings.Repeat("ee", sha256.Size)
	hashBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		t.Fatalf("decode test hash failed: %v", err)
	}

	cid := "cid-token-1"
	authority := "a.l-l.cn"
	token, err := encodeEndpointTLSPinToken(hashBytes, cid, authority, time.Now().UTC().Add(10*time.Minute).Unix())
	if err != nil {
		t.Fatalf("encode token failed: %v", err)
	}

	*pinToken = token
	*configID = cid
	t.Setenv(endpointTLSPinTokenEnv, "")

	hash, source, err := resolveEndpointTLSPinOverride(authority)
	if err != nil {
		t.Fatalf("resolve pin override failed: %v", err)
	}
	if got := hex.EncodeToString(hash); got != rawHex {
		t.Fatalf("unexpected decoded hash: got=%s want=%s", got, rawHex)
	}
	if !strings.Contains(source, "token(encrypted)") {
		t.Fatalf("unexpected override source: %s", source)
	}
}

func TestResolveEndpointTLSPinOverrideEncryptedTokenCIDMismatch(t *testing.T) {
	oldToken := *pinToken
	oldCID := *configID
	defer func() {
		*pinToken = oldToken
		*configID = oldCID
	}()

	rawHex := strings.Repeat("9f", sha256.Size)
	hashBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		t.Fatalf("decode test hash failed: %v", err)
	}

	token, err := encodeEndpointTLSPinToken(hashBytes, "cid-correct", "a.l-l.cn", time.Now().UTC().Add(10*time.Minute).Unix())
	if err != nil {
		t.Fatalf("encode token failed: %v", err)
	}

	*pinToken = token
	*configID = "cid-wrong"
	t.Setenv(endpointTLSPinTokenEnv, "")

	_, _, err = resolveEndpointTLSPinOverride("a.l-l.cn")
	if err == nil {
		t.Fatal("expected token cid mismatch error")
	}
}

func TestEnsureEndpointTLSPinUsesTokenOverrideWithoutNetwork(t *testing.T) {
	oldToken := *pinToken
	oldCID := *configID
	defer func() {
		*pinToken = oldToken
		*configID = oldCID
	}()

	resetEndpointTLSPinCacheForTest()
	defer resetEndpointTLSPinCacheForTest()

	rawHex := strings.Repeat("11", sha256.Size)
	hashBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		t.Fatalf("decode test hash failed: %v", err)
	}
	cid := "cid-networkless"
	token, err := encodeEndpointTLSPinToken(hashBytes, cid, "example.invalid", time.Now().UTC().Add(10*time.Minute).Unix())
	if err != nil {
		t.Fatalf("encode token failed: %v", err)
	}

	*pinToken = token
	*configID = cid
	t.Setenv(endpointTLSPinTokenEnv, "")

	pin, err := ensureEndpointTLSPin("example.invalid:443")
	if err != nil {
		t.Fatalf("ensureEndpointTLSPin failed with token override: %v", err)
	}
	key, _, err := pin.getActiveKey()
	if err != nil {
		t.Fatalf("getActiveKey failed: %v", err)
	}
	if got := hex.EncodeToString(key); got != rawHex {
		t.Fatalf("unexpected active pin key: got=%s want=%s", got, rawHex)
	}
	if pin.isTLSPinEnforced() {
		t.Fatalf("expected TLS transport pin enforcement to be relaxed in token override mode")
	}

	_, regHash, enforceTLSPin, err := GetTLSPinRegistrationInfo("example.invalid:443")
	if err != nil {
		t.Fatalf("GetTLSPinRegistrationInfo failed: %v", err)
	}
	if enforceTLSPin {
		t.Fatalf("expected GetTLSPinRegistrationInfo to return relaxed TLS transport pin mode")
	}
	if got := hex.EncodeToString(regHash); got != rawHex {
		t.Fatalf("unexpected registration pin hash: got=%s want=%s", got, rawHex)
	}
}

func TestEnsureEndpointTLSPinExpiredTokenUsesCachedPin(t *testing.T) {
	oldToken := *pinToken
	oldCID := *configID
	defer func() {
		*pinToken = oldToken
		*configID = oldCID
	}()

	resetEndpointTLSPinCacheForTest()
	defer resetEndpointTLSPinCacheForTest()

	cid := "cid-expired-fallback"
	authority := "example.invalid"
	rawHex := strings.Repeat("22", sha256.Size)
	hashBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		t.Fatalf("decode test hash failed: %v", err)
	}

	validToken, err := encodeEndpointTLSPinToken(hashBytes, cid, authority, time.Now().UTC().Add(10*time.Minute).Unix())
	if err != nil {
		t.Fatalf("encode valid token failed: %v", err)
	}

	*configID = cid
	*pinToken = validToken
	t.Setenv(endpointTLSPinTokenEnv, "")

	pin, err := ensureEndpointTLSPin(authority + ":443")
	if err != nil {
		t.Fatalf("ensureEndpointTLSPin with valid token failed: %v", err)
	}
	key, _, err := pin.getActiveKey()
	if err != nil {
		t.Fatalf("getActiveKey failed: %v", err)
	}
	if got := hex.EncodeToString(key); got != rawHex {
		t.Fatalf("unexpected active pin key after valid token: got=%s want=%s", got, rawHex)
	}

	expiredToken, err := encodeEndpointTLSPinToken(hashBytes, cid, authority, time.Now().UTC().Add(-1*time.Minute).Unix())
	if err != nil {
		t.Fatalf("encode expired token failed: %v", err)
	}
	*pinToken = expiredToken

	pinAfterExpiry, err := ensureEndpointTLSPin(authority + ":443")
	if err != nil {
		t.Fatalf("ensureEndpointTLSPin should keep cached pin when token expired: %v", err)
	}
	keyAfterExpiry, _, err := pinAfterExpiry.getActiveKey()
	if err != nil {
		t.Fatalf("getActiveKey after expiry failed: %v", err)
	}
	if got := hex.EncodeToString(keyAfterExpiry); got != rawHex {
		t.Fatalf("unexpected active pin key after expiry fallback: got=%s want=%s", got, rawHex)
	}
}

func TestEnsureEndpointTLSPinExpiredTokenWithoutCacheFails(t *testing.T) {
	oldToken := *pinToken
	oldCID := *configID
	defer func() {
		*pinToken = oldToken
		*configID = oldCID
	}()

	resetEndpointTLSPinCacheForTest()
	defer resetEndpointTLSPinCacheForTest()

	cid := "cid-expired-coldstart"
	authority := "example.invalid"
	rawHex := strings.Repeat("33", sha256.Size)
	hashBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		t.Fatalf("decode test hash failed: %v", err)
	}
	expiredToken, err := encodeEndpointTLSPinToken(hashBytes, cid, authority, time.Now().UTC().Add(-1*time.Minute).Unix())
	if err != nil {
		t.Fatalf("encode expired token failed: %v", err)
	}

	*configID = cid
	*pinToken = expiredToken
	t.Setenv(endpointTLSPinTokenEnv, "")

	_, err = ensureEndpointTLSPin(authority + ":443")
	if err == nil {
		t.Fatal("expected expired token cold-start to fail")
	}
	if !isEndpointTLSPinTokenExpiredError(err) {
		t.Fatalf("expected token expired error, got: %v", err)
	}
}

func TestEnsureEndpointTLSPinTokenModeDoesNotOverrideActiveLiveHash(t *testing.T) {
	oldToken := *pinToken
	oldCID := *configID
	defer func() {
		*pinToken = oldToken
		*configID = oldCID
	}()

	resetEndpointTLSPinCacheForTest()
	defer resetEndpointTLSPinCacheForTest()

	cid := "cid-active-live"
	authority := "a.l-l.cn"
	tokenHex := strings.Repeat("49", sha256.Size)
	liveHex := strings.Repeat("79", sha256.Size)
	tokenHash, err := hex.DecodeString(tokenHex)
	if err != nil {
		t.Fatalf("decode token hash failed: %v", err)
	}
	liveHash, err := hex.DecodeString(liveHex)
	if err != nil {
		t.Fatalf("decode live hash failed: %v", err)
	}

	token, err := encodeEndpointTLSPinToken(tokenHash, cid, authority, time.Now().UTC().Add(10*time.Minute).Unix())
	if err != nil {
		t.Fatalf("encode token failed: %v", err)
	}
	*pinToken = token
	*configID = cid
	t.Setenv(endpointTLSPinTokenEnv, "")

	pin := &endpointTLSPin{
		serverAddress: authority,
		serverName:    authority,
		allowed:       make(map[string][]byte),
		enforceTLSPin: false,
	}
	pin.addAllowedHash(tokenHash)
	pin.addAllowedHash(liveHash) // live hash is current active key
	endpointTLSPins.mu.Lock()
	endpointTLSPins.byAddress[strings.ToLower(authority)] = pin
	endpointTLSPins.mu.Unlock()

	gotPin, err := ensureEndpointTLSPin(authority + ":443")
	if err != nil {
		t.Fatalf("ensureEndpointTLSPin failed: %v", err)
	}
	key, _, err := gotPin.getActiveKey()
	if err != nil {
		t.Fatalf("getActiveKey failed: %v", err)
	}
	if got := hex.EncodeToString(key); got != liveHex {
		t.Fatalf("token mode should preserve live active hash, got=%s want=%s", got, liveHex)
	}
}
