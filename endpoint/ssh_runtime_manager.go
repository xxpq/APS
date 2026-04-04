package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	endpointssh "aps/endpoint/utils/ssh"

	gossh "golang.org/x/crypto/ssh"
)

const defaultEndpointSSHPort = 22222

var endpointSSHManager = NewEndpointSSHRuntimeManager()

type EndpointSSHRuntimeManager struct {
	mu         sync.Mutex
	server     *endpointssh.SSH
	runDone    chan error
	runningCfg *normalizedEndpointSSHConfig
}

type normalizedEndpointSSHConfig struct {
	Enabled  bool
	Port     int
	PointKey string
	Users    []normalizedEndpointSSHUser
}

type normalizedEndpointSSHUser struct {
	Name     string
	Password string
	Keys     []string
}

func NewEndpointSSHRuntimeManager() *EndpointSSHRuntimeManager {
	return &EndpointSSHRuntimeManager{}
}

func (m *EndpointSSHRuntimeManager) Apply(cfg *EndpointSSHConfig) error {
	normalized, err := normalizeEndpointSSHConfig(cfg)
	if err != nil {
		return err
	}
	if err := validateEndpointSSHUsers(normalized.Users); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if !normalized.Enabled {
		if m.server != nil {
			m.stopLocked()
			log.Printf("[SSH] SSH server stopped (disabled by config)")
		}
		m.runningCfg = normalized
		return nil
	}

	sameListener := m.runningCfg != nil &&
		m.runningCfg.Enabled &&
		m.runningCfg.Port == normalized.Port &&
		m.runningCfg.PointKey == normalized.PointKey

	if m.server != nil && sameListener {
		if err := applyEndpointSSHUsers(m.server, normalized.Users); err != nil {
			return err
		}
		m.runningCfg = normalized
		log.Printf("[SSH] Authentication rules updated on 0.0.0.0:%d (users=%d)", normalized.Port, len(normalized.Users))
		return nil
	}

	if m.server != nil {
		m.stopLocked()
	}

	srv, runDone, err := startEndpointSSHServer(normalized)
	if err != nil {
		return err
	}

	m.server = srv
	m.runDone = runDone
	m.runningCfg = normalized
	log.Printf("[SSH] SSH server started on 0.0.0.0:%d (users=%d)", normalized.Port, len(normalized.Users))
	return nil
}

func (m *EndpointSSHRuntimeManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.server == nil {
		return
	}
	m.stopLocked()
	m.runningCfg = nil
	log.Printf("[SSH] SSH server stopped")
}

func (m *EndpointSSHRuntimeManager) stopLocked() {
	if m.server == nil {
		return
	}
	m.server.Stop()
	if m.runDone != nil {
		select {
		case <-m.runDone:
		case <-time.After(2 * time.Second):
			log.Printf("[SSH] Timed out while waiting for SSH server shutdown")
		}
	}
	m.server = nil
	m.runDone = nil
}

func startEndpointSSHServer(cfg *normalizedEndpointSSHConfig) (*endpointssh.SSH, chan error, error) {
	pointKeyBytes, err := loadOrCreateEndpointSSHHostKey(cfg.PointKey)
	if err != nil {
		return nil, nil, err
	}

	srv, err := endpointssh.NewServer()
	if err != nil {
		return nil, nil, fmt.Errorf("create ssh server: %w", err)
	}

	if err := srv.SetHostKey(pointKeyBytes); err != nil {
		return nil, nil, fmt.Errorf("set ssh host key: %w", err)
	}

	if err := applyEndpointSSHUsers(srv, cfg.Users); err != nil {
		return nil, nil, err
	}

	addr := fmt.Sprintf("0.0.0.0:%d", cfg.Port)
	runDone := make(chan error, 1)
	go func() {
		runDone <- srv.Run(addr)
	}()

	select {
	case runErr := <-runDone:
		if runErr != nil {
			return nil, nil, fmt.Errorf("start ssh listener on %s: %w", addr, runErr)
		}
		return nil, nil, fmt.Errorf("ssh listener on %s exited unexpectedly", addr)
	case <-time.After(200 * time.Millisecond):
	}

	return srv, runDone, nil
}

func applyEndpointSSHUsers(srv *endpointssh.SSH, users []normalizedEndpointSSHUser) error {
	srv.ClearAuthorizedKeys()
	srv.ClearAuthorizedPasswords()
	for _, user := range users {
		if strings.TrimSpace(user.Password) != "" {
			srv.SetAuthorizedPassword(user.Name, user.Password)
		}
		for _, key := range user.Keys {
			if err := srv.AddAuthorizedKey(user.Name, key); err != nil {
				return fmt.Errorf("invalid ssh key for user %q: %w", user.Name, err)
			}
		}
	}
	return nil
}

func normalizeEndpointSSHConfig(cfg *EndpointSSHConfig) (*normalizedEndpointSSHConfig, error) {
	if cfg == nil {
		return &normalizedEndpointSSHConfig{Enabled: false}, nil
	}

	enabled := true
	if cfg.Enabled != nil {
		enabled = *cfg.Enabled
	}
	if !enabled {
		return &normalizedEndpointSSHConfig{Enabled: false}, nil
	}

	port := cfg.Port
	if port == 0 {
		port = defaultEndpointSSHPort
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("ssh port must be between 1 and 65535")
	}
	if port == 22 {
		return nil, fmt.Errorf("ssh port 22 is forbidden for security reasons")
	}

	pointKey := strings.TrimSpace(cfg.PointKey)
	if pointKey == "" {
		pointKey = defaultEndpointSSHPointKeyPath()
	}

	users := normalizeEndpointSSHUsers(cfg.Users)

	return &normalizedEndpointSSHConfig{
		Enabled:  true,
		Port:     port,
		PointKey: pointKey,
		Users:    users,
	}, nil
}

func normalizeEndpointSSHUsers(users []EndpointSSHUser) []normalizedEndpointSSHUser {
	if len(users) == 0 {
		return nil
	}

	normalized := make([]normalizedEndpointSSHUser, 0, len(users))
	for _, user := range users {
		name := strings.TrimSpace(user.Name)
		if name == "" {
			continue
		}
		password := strings.TrimSpace(user.Password)

		seen := make(map[string]struct{})
		keys := make([]string, 0, len(user.Keys))
		for _, rawKey := range user.Keys {
			key := strings.TrimSpace(rawKey)
			if key == "" {
				continue
			}
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
		if len(keys) == 0 && password == "" {
			continue
		}

		sort.Strings(keys)
		normalized = append(normalized, normalizedEndpointSSHUser{
			Name:     name,
			Password: password,
			Keys:     keys,
		})
	}

	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].Name < normalized[j].Name
	})

	return normalized
}

func validateEndpointSSHUsers(users []normalizedEndpointSSHUser) error {
	for _, user := range users {
		if user.Password == "" && len(user.Keys) == 0 {
			return fmt.Errorf("ssh user %q has neither password nor keys", user.Name)
		}
		for _, key := range user.Keys {
			if _, _, _, _, err := gossh.ParseAuthorizedKey([]byte(key)); err != nil {
				return fmt.Errorf("invalid authorized key for user %q: %w", user.Name, err)
			}
		}
	}
	return nil
}

func defaultEndpointSSHPointKeyPath() string {
	if runtime.GOOS == "windows" {
		programData, err := os.UserHomeDir()
		if err != nil {
			programData = os.TempDir()
		}
		return filepath.Join(programData, ".ssh", "id_rsa")
	}
	return filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa")
}

func loadOrCreateEndpointSSHHostKey(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("ssh point key path is empty")
	}

	if keyBytes, err := os.ReadFile(path); err == nil {
		return keyBytes, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read ssh point key %s: %w", path, err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generate rsa host key: %w", err)
	}

	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if len(privatePEM) == 0 {
		return nil, errors.New("encode rsa host key: empty pem")
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("create ssh point key directory %s: %w", dir, err)
		}
	}

	if err := os.WriteFile(path, privatePEM, 0600); err != nil {
		return nil, fmt.Errorf("write ssh point key %s: %w", path, err)
	}

	return privatePEM, nil
}
