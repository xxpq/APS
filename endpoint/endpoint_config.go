package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// EndpointRuntimeConfig holds the configuration fetched from APS
type EndpointRuntimeConfig struct {
	ID                  string              `json:"id"`
	ServerName          string              `json:"serverName,omitempty"`
	TunnelName          string              `json:"tunnelName"`
	EndpointName        string              `json:"endpointName"`
	SessionCredential   string              `json:"sessionCredential,omitempty"`
	SessionExpiresAt    int64               `json:"sessionExpiresAt,omitempty"`
	KDFVersion          string              `json:"kdfVersion,omitempty"`
	KDFSalt             string              `json:"kdfSalt,omitempty"`
	PortMappings        []PortMappingConfig `json:"portMappings,omitempty"`
	GatewayListen       string              `json:"gatewayListen,omitempty"`
	GatewayAddress      string              `json:"gatewayAddress,omitempty"`
	GatewayDiscovery    bool                `json:"gatewayDiscovery,omitempty"`
	GatewayDiscoverPort int                 `json:"gatewayDiscoverPort,omitempty"`
	SSH                 *EndpointSSHConfig  `json:"ssh,omitempty"`
}

func decodeGatewayAddressField(raw json.RawMessage) (string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || strings.EqualFold(trimmed, "null") {
		return "", nil
	}

	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return strings.TrimSpace(asString), nil
	}

	var asList []string
	if err := json.Unmarshal(raw, &asList); err == nil {
		parts := make([]string, 0, len(asList))
		for _, item := range asList {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			parts = append(parts, item)
		}
		return strings.Join(parts, ","), nil
	}

	return "", fmt.Errorf("gatewayAddress must be string or []string")
}

func canonicalizeEndpointGatewayAddressField(raw string) string {
	normalized := normalizeEndpointGatewayAddresses(raw)
	if len(normalized) == 0 {
		return ""
	}
	return strings.Join(normalized, ",")
}

func (c *EndpointRuntimeConfig) UnmarshalJSON(data []byte) error {
	type alias EndpointRuntimeConfig
	var aux struct {
		alias
		GatewayAddress json.RawMessage `json:"gatewayAddress"`
	}
	aux.alias = alias{
		GatewayDiscovery:    true,
		GatewayDiscoverPort: defaultGatewayDiscoverPort,
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	defaulted := aux.alias
	decodedGatewayAddress, err := decodeGatewayAddressField(aux.GatewayAddress)
	if err != nil {
		return err
	}
	defaulted.GatewayListen = strings.TrimSpace(defaulted.GatewayListen)
	defaulted.GatewayAddress = canonicalizeEndpointGatewayAddressField(decodedGatewayAddress)
	if defaulted.GatewayDiscoverPort <= 0 {
		defaulted.GatewayDiscoverPort = defaultGatewayDiscoverPort
	}
	if defaulted.GatewayListen == "" {
		defaulted.GatewayListen = defaultGatewayListenAddress(defaulted.GatewayDiscoverPort)
	}
	*c = EndpointRuntimeConfig(defaulted)
	return nil
}

// PortMappingConfig defines a port mapping from local to remote endpoint
type PortMappingConfig struct {
	LocalListen    string `json:"localListen"`    // Listen address on this endpoint (e.g. 0.0.0.0:8080)
	RemoteTarget   string `json:"remoteTarget"`   // IP:Port on the remote endpoint's network
	TargetEndpoint string `json:"targetEndpoint"` // Which endpoint to forward traffic to
}

func (m *PortMappingConfig) UnmarshalJSON(data []byte) error {
	type portMappingAlias struct {
		LocalListen    json.RawMessage `json:"localListen"`
		RemoteTarget   string          `json:"remoteTarget"`
		TargetEndpoint string          `json:"targetEndpoint"`
	}
	var aux portMappingAlias
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	localListen, err := parsePortMappingLocalListen(aux.LocalListen)
	if err != nil {
		return err
	}

	m.LocalListen = localListen
	m.RemoteTarget = strings.TrimSpace(aux.RemoteTarget)
	m.TargetEndpoint = strings.TrimSpace(aux.TargetEndpoint)
	return nil
}

func parsePortMappingLocalListen(raw json.RawMessage) (string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return "", errors.New("localListen is required")
	}
	if strings.HasPrefix(trimmed, "\"") {
		var listen string
		if err := json.Unmarshal(raw, &listen); err != nil {
			return "", fmt.Errorf("invalid localListen string: %w", err)
		}
		return normalizePortMappingLocalListen(listen)
	}
	port, err := strconv.Atoi(trimmed)
	if err != nil {
		return "", fmt.Errorf("localListen must be port number or listen address, got %s", trimmed)
	}
	return normalizePortMappingLocalListen(strconv.Itoa(port))
}

func normalizePortMappingLocalListen(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("localListen is required")
	}

	if port, err := strconv.Atoi(raw); err == nil {
		if err := validatePortMappingLocalListenPort(port); err != nil {
			return "", err
		}
		return net.JoinHostPort("0.0.0.0", strconv.Itoa(port)), nil
	}

	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		return "", fmt.Errorf("invalid localListen %q: %w", raw, err)
	}
	port, err := strconv.Atoi(strings.TrimSpace(portText))
	if err != nil {
		return "", fmt.Errorf("invalid localListen port %q", portText)
	}
	if err := validatePortMappingLocalListenPort(port); err != nil {
		return "", err
	}

	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func validatePortMappingLocalListenPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("localListen port out of range: %d", port)
	}
	return nil
}

func splitEndpointGatewayAddressText(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func normalizeEndpointGatewayAddresses(gatewayAddress string) []string {
	parts := splitEndpointGatewayAddressText(gatewayAddress)
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		addr := normalizeGatewayAddress(raw)
		if addr == "" {
			return
		}
		if _, exists := seen[addr]; exists {
			return
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	for _, raw := range splitEndpointGatewayAddressText(gatewayAddress) {
		add(raw)
	}
	return out
}

// EndpointSSHConfig holds SSH plugin settings for endpoint runtime.
// It accepts both pointKey and point_key for compatibility.
type EndpointSSHConfig struct {
	Enabled  *bool             `json:"enabled,omitempty"`
	Port     int               `json:"port,omitempty"`
	PointKey string            `json:"pointKey,omitempty"`
	Users    []EndpointSSHUser `json:"users,omitempty"`
}

func (c *EndpointSSHConfig) UnmarshalJSON(data []byte) error {
	type endpointSSHConfigAlias struct {
		Enabled       *bool             `json:"enabled,omitempty"`
		Port          int               `json:"port,omitempty"`
		PointKey      string            `json:"pointKey,omitempty"`
		PointKeySnake string            `json:"point_key,omitempty"`
		Users         []EndpointSSHUser `json:"users,omitempty"`
	}
	var aux endpointSSHConfigAlias
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	c.Enabled = aux.Enabled
	c.Port = aux.Port
	c.PointKey = strings.TrimSpace(aux.PointKey)
	if c.PointKey == "" {
		c.PointKey = strings.TrimSpace(aux.PointKeySnake)
	}
	c.Users = aux.Users
	return nil
}

// EndpointSSHUser describes one SSH account and authorized keys.
type EndpointSSHUser struct {
	Name     string               `json:"name"`
	Password string               `json:"password,omitempty"`
	Keys     EndpointSSHKeyValues `json:"keys,omitempty"`
}

// EndpointSSHKeyValues accepts either a JSON string or []string.
type EndpointSSHKeyValues []string

func (k *EndpointSSHKeyValues) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		*k = nil
		return nil
	}

	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		single = strings.TrimSpace(single)
		if single == "" {
			*k = nil
			return nil
		}
		*k = EndpointSSHKeyValues{single}
		return nil
	}

	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("keys must be string or []string: %w", err)
	}

	out := make([]string, 0, len(many))
	for _, item := range many {
		key := strings.TrimSpace(item)
		if key == "" {
			continue
		}
		out = append(out, key)
	}
	*k = EndpointSSHKeyValues(out)
	return nil
}

// ConfigResponse is the APS response for endpoint configuration
type ConfigResponse struct {
	Success bool                   `json:"success"`
	Config  *EndpointRuntimeConfig `json:"config,omitempty"`
	Error   string                 `json:"error,omitempty"`
}

func shouldEnableBootstrapGatewayRuntimeForConfigFetch() bool {
	// Service lifecycle commands should not bind local gateway listener during config fetch.
	// They only need outbound gateway-client capability.
	if install != nil && *install {
		return false
	}
	if reinstall != nil && *reinstall {
		return false
	}
	if uninstall != nil && *uninstall {
		return false
	}
	return true
}

// FetchConfigFromAPS retrieves endpoint configuration from APS server
func FetchConfigFromAPS(apsAddr, configID string) (*EndpointRuntimeConfig, error) {
	if shouldEnableBootstrapGatewayRuntimeForConfigFetch() {
		ensureBootstrapGatewayRuntimeForConfigFetch(apsAddr, configID)
	} else {
		DebugLog("[CONN-INIT] Skip bootstrap gateway runtime during service lifecycle command")
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		encryptedID, requestSalt, pin, err := buildEncryptedConfigIDForServer(apsAddr, configID)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare encrypted config request: %w", err)
		}

		requestPath := fmt.Sprintf(
			"/.api/endpoints?%s=%s&%s=%s",
			TLSEncryptedConfigIDParam,
			url.QueryEscape(encryptedID),
			TLSEncryptedSaltParam,
			url.QueryEscape(requestSalt),
		)

		resp, pin, err := doPinnedAPSGet(apsAddr, requestPath)
		if err != nil {
			lastErr = fmt.Errorf("failed to connect to APS with pinned TLS: %w", err)
			continue
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("failed to read response: %w", readErr)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			if resp.StatusCode == http.StatusBadRequest &&
				strings.Contains(strings.ToLower(string(body)), "invalid encrypted config id") &&
				attempt == 0 {
				if _, refreshErr := refreshEndpointTLSPin(apsAddr); refreshErr != nil {
					lastErr = fmt.Errorf("APS returned encrypted-id error and pin refresh failed: %v", refreshErr)
					continue
				}
				// Re-encrypt config ID with the refreshed pin hash.
				continue
			}
			lastErr = fmt.Errorf("APS returned error status %d: %s", resp.StatusCode, string(body))
			continue
		}

		var envelope EncryptedPayloadEnvelope
		if err := json.Unmarshal(body, &envelope); err != nil {
			lastErr = fmt.Errorf("failed to parse encrypted envelope: %w", err)
			continue
		}

		decryptedBody, err := decodeEncryptedEnvelopeWithPin(pin, &envelope)
		if err != nil {
			lastErr = fmt.Errorf("failed to decrypt APS response: %w", err)
			continue
		}

		var configResp ConfigResponse
		if err := json.Unmarshal(decryptedBody, &configResp); err != nil {
			lastErr = fmt.Errorf("failed to parse config response: %w", err)
			continue
		}

		if !configResp.Success {
			lastErr = fmt.Errorf("APS error: %s", configResp.Error)
			continue
		}

		if configResp.Config == nil {
			lastErr = fmt.Errorf("no configuration found for requested id")
			continue
		}

		return configResp.Config, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("failed to fetch configuration from APS")
}

// ValidateConfig validates the endpoint configuration
func (c *EndpointRuntimeConfig) ValidateConfig() error {
	if c.TunnelName == "" {
		return fmt.Errorf("tunnel name is required")
	}
	if c.EndpointName == "" {
		return fmt.Errorf("endpoint name is required")
	}
	if strings.TrimSpace(c.SessionCredential) == "" {
		return fmt.Errorf("sessionCredential is required")
	}
	normalizedVersion, err := normalizeEndpointKDFVersion(c.KDFVersion)
	if err != nil {
		return err
	}
	if strings.TrimSpace(c.KDFSalt) == "" {
		return fmt.Errorf("kdfSalt is required")
	}
	c.KDFVersion = normalizedVersion
	c.KDFSalt = strings.TrimSpace(c.KDFSalt)
	if c.GatewayDiscoverPort <= 0 {
		c.GatewayDiscoverPort = defaultGatewayDiscoverPort
	}
	c.GatewayAddress = canonicalizeEndpointGatewayAddressField(c.GatewayAddress)
	return nil
}

// initializeConfiguration sets up the endpoint configuration.
// Secure mode requires -cid and disallows legacy plaintext registration flags.
func initializeConfiguration() error {
	// Secure mode: fetch runtime config by CID from APS.
	if *configID != "" {
		if *serverAddr == "" {
			return fmt.Errorf("when using -cid, you must specify -server <addr:port>")
		}

		if *serverAddr != "" {
			// Active mode: connect to APS and fetch config
			log.Printf("Fetching configuration from APS (%s)", *serverAddr)
			DebugLog("[CONFIG] Using encrypted config id flow")

			var config *EndpointRuntimeConfig
			var err error
			for {
				config, err = FetchConfigFromAPS(*serverAddr, *configID)
				if err == nil {
					break
				}
				log.Printf("Failed to fetch configuration: %v. Retrying in 10 seconds...", err)
				time.Sleep(10 * time.Second)
			}

			if err := config.ValidateConfig(); err != nil {
				return fmt.Errorf("invalid configuration: %w", err)
			}
			runtimeConfig = config
			usingLegacyMode = false
			log.Printf("Configuration loaded successfully")
			DebugLog("[CONFIG] Loaded tunnel=%s endpoint=%s", config.TunnelName, config.EndpointName)
			return nil
		}

	}

	return fmt.Errorf("secure mode requires -cid <config-id> and -server <addr:port>; legacy -tunnel/-password is disabled")
}

// printDeprecationWarning displays a warning about using deprecated flags
func printDeprecationWarning() {
	warning := `
╔════════════════════════════════════════════════════════════════════════════╗
║                          ⚠️  DEPRECATION WARNING  ⚠️                        ║
╠════════════════════════════════════════════════════════════════════════════╣
║  The -tunnel, -name, and -password flags are DEPRECATED and will be       ║
║  removed in a future version.                                              ║
║                                                                            ║
║  Recommended usage:                                                        ║
║    endpoint -server <aps-addr:port> -cid <config-id>                       ║
║                                                                            ║
║  Please use APS centralized configuration management for unified control. ║
╚════════════════════════════════════════════════════════════════════════════╝
`
	log.Print(warning)
}

// GetEffectiveTunnelName returns the tunnel name from runtime config or legacy flag
func GetEffectiveTunnelName() string {
	if runtimeConfig != nil {
		return runtimeConfig.TunnelName
	}
	return *tunnelName
}

// GetEffectiveEndpointName returns the endpoint name from runtime config or legacy flag
func GetEffectiveEndpointName() string {
	if runtimeConfig != nil {
		return runtimeConfig.EndpointName
	}
	return *name
}

// GetEffectivePassword returns the session credential from runtime config (or legacy fallback flag).
func GetEffectivePassword() string {
	if runtimeConfig != nil {
		return runtimeConfig.SessionCredential
	}
	return *tunnelPassword
}

// GetEffectiveConfigID returns the active CID for secure registration.
func GetEffectiveConfigID() string {
	if runtimeConfig != nil && strings.TrimSpace(runtimeConfig.ID) != "" {
		return strings.TrimSpace(runtimeConfig.ID)
	}
	return strings.TrimSpace(*configID)
}
