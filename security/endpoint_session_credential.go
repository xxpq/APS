package security

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	endpointSessionCredentialTTL        = 3 * time.Minute
	endpointSessionCredentialMaxEntries = 20000
)

type endpointSessionCredentialEntry struct {
	CID          string
	TunnelName   string
	EndpointName string
	Credential   string
	ExpiresAt    int64
	Used         bool
}

var endpointSessionCredentials = struct {
	mu    sync.Mutex
	byCID map[string]*endpointSessionCredentialEntry
}{
	byCID: make(map[string]*endpointSessionCredentialEntry),
}

func randomHexToken(size int) (string, error) {
	if size <= 0 {
		return "", errors.New("invalid token size")
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func pruneExpiredEndpointSessionCredentialsLocked(now int64) {
	for cid, entry := range endpointSessionCredentials.byCID {
		if entry == nil || entry.ExpiresAt < now {
			delete(endpointSessionCredentials.byCID, cid)
		}
	}
	if len(endpointSessionCredentials.byCID) <= endpointSessionCredentialMaxEntries {
		return
	}
	toDelete := len(endpointSessionCredentials.byCID) - endpointSessionCredentialMaxEntries
	for cid := range endpointSessionCredentials.byCID {
		delete(endpointSessionCredentials.byCID, cid)
		toDelete--
		if toDelete <= 0 {
			break
		}
	}
}

func IssueEndpointSessionCredential(cid, tunnelName, endpointName string) (string, int64, error) {
	cid = strings.TrimSpace(cid)
	tunnelName = strings.TrimSpace(tunnelName)
	endpointName = strings.TrimSpace(endpointName)
	if cid == "" || tunnelName == "" || endpointName == "" {
		return "", 0, errors.New("cid/tunnelName/endpointName are required")
	}

	nonce, err := randomHexToken(16)
	if err != nil {
		return "", 0, err
	}
	secret, err := randomHexToken(32)
	if err != nil {
		return "", 0, err
	}

	credential := fmt.Sprintf("v1.%s.%s", nonce, secret)
	expiresAt := time.Now().UTC().Add(endpointSessionCredentialTTL).Unix()

	endpointSessionCredentials.mu.Lock()
	defer endpointSessionCredentials.mu.Unlock()
	pruneExpiredEndpointSessionCredentialsLocked(time.Now().UTC().Unix())
	endpointSessionCredentials.byCID[cid] = &endpointSessionCredentialEntry{
		CID:          cid,
		TunnelName:   tunnelName,
		EndpointName: endpointName,
		Credential:   credential,
		ExpiresAt:    expiresAt,
		Used:         false,
	}

	return credential, expiresAt, nil
}

func PeekEndpointSessionCredential(cid, tunnelName, endpointName string) (string, error) {
	cid = strings.TrimSpace(cid)
	tunnelName = strings.TrimSpace(tunnelName)
	endpointName = strings.TrimSpace(endpointName)
	if cid == "" || tunnelName == "" || endpointName == "" {
		return "", errors.New("cid/tunnelName/endpointName are required")
	}

	now := time.Now().UTC().Unix()
	endpointSessionCredentials.mu.Lock()
	defer endpointSessionCredentials.mu.Unlock()
	pruneExpiredEndpointSessionCredentialsLocked(now)

	entry, ok := endpointSessionCredentials.byCID[cid]
	if !ok || entry == nil {
		return "", errors.New("session credential not issued")
	}
	if entry.Used {
		return "", errors.New("session credential already used")
	}
	if entry.ExpiresAt < now {
		delete(endpointSessionCredentials.byCID, cid)
		return "", errors.New("session credential expired")
	}
	if entry.TunnelName != tunnelName || entry.EndpointName != endpointName {
		return "", errors.New("session credential binding mismatch")
	}

	return entry.Credential, nil
}

func ConsumeEndpointSessionCredential(cid, tunnelName, endpointName, credential string) error {
	cid = strings.TrimSpace(cid)
	tunnelName = strings.TrimSpace(tunnelName)
	endpointName = strings.TrimSpace(endpointName)
	credential = strings.TrimSpace(credential)
	if cid == "" || tunnelName == "" || endpointName == "" || credential == "" {
		return errors.New("cid/tunnelName/endpointName/credential are required")
	}

	now := time.Now().UTC().Unix()
	endpointSessionCredentials.mu.Lock()
	defer endpointSessionCredentials.mu.Unlock()
	pruneExpiredEndpointSessionCredentialsLocked(now)

	entry, ok := endpointSessionCredentials.byCID[cid]
	if !ok || entry == nil {
		return errors.New("session credential not found")
	}
	if entry.Used {
		return errors.New("session credential already used")
	}
	if entry.ExpiresAt < now {
		delete(endpointSessionCredentials.byCID, cid)
		return errors.New("session credential expired")
	}
	if entry.TunnelName != tunnelName || entry.EndpointName != endpointName {
		return errors.New("session credential binding mismatch")
	}
	if entry.Credential != credential {
		return errors.New("session credential mismatch")
	}

	entry.Used = true
	return nil
}

