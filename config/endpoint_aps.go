package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// DefaultGatewayDiscoverPort is the UDP port used for LAN gateway discovery.
const DefaultGatewayDiscoverPort = 37990

// EndpointConfig_APS holds configuration for an APS endpoint (tunnel + leaf).
type EndpointConfig_APS struct {
	TunnelName          string                `json:"tunnelName"`
	EndpointName        string                `json:"endpointName"`
	Password            string                `json:"password,omitempty"`
	AllowMultiNode      bool                  `json:"allowMultiNode,omitempty"`
	Mirror              string                `json:"mirror,omitempty"`
	PortMappings        []EndpointPortMapping `json:"portMappings,omitempty"`
	GatewayListen       string                `json:"gatewayListen,omitempty"`
	GatewayAddress      string                `json:"gatewayAddress,omitempty"`
	GatewayDiscovery    bool                  `json:"gatewayDiscovery,omitempty"`
	GatewayDiscoverPort int                   `json:"gatewayDiscoverPort,omitempty"`
	SSH                 *EndpointSSHConfig    `json:"ssh,omitempty"`
	LogLevel            *int                  `json:"logLevel,omitempty"`
	LogRetentionHours   *int                  `json:"logRetentionHours,omitempty"`
}

// UnmarshalJSON applies defaults and decodes the gatewayAddress field
// (which accepts string or []string).
func (c *EndpointConfig_APS) UnmarshalJSON(data []byte) error {
	type alias EndpointConfig_APS
	var aux struct {
		alias
		GatewayAddress json.RawMessage `json:"gatewayAddress"`
	}
	aux.alias = alias{
		GatewayDiscovery:    true,
		GatewayDiscoverPort: DefaultGatewayDiscoverPort,
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	defaulted := aux.alias
	decodedGatewayAddress, err := decodeAPSGatewayAddressField(aux.GatewayAddress)
	if err != nil {
		return err
	}
	defaulted.GatewayListen = strings.TrimSpace(defaulted.GatewayListen)
	defaulted.GatewayAddress = canonicalizeAPSGatewayAddressField(decodedGatewayAddress)
	if defaulted.GatewayDiscoverPort <= 0 {
		defaulted.GatewayDiscoverPort = DefaultGatewayDiscoverPort
	}
	*c = EndpointConfig_APS(defaulted)
	return nil
}

func decodeAPSGatewayAddressField(raw json.RawMessage) (string, error) {
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

func canonicalizeAPSGatewayAddressField(raw string) string {
	normalized := NormalizeAPSConfiguredGatewayAddresses(raw)
	if len(normalized) == 0 {
		return ""
	}
	return strings.Join(normalized, ",")
}

func splitAPSGatewayAddressText(raw string) []string {
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

func normalizeAPSGatewayAddress(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(raw); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "missing port") {
			host := strings.Trim(strings.TrimSpace(raw), "[]")
			if host == "" {
				return ""
			}
			return net.JoinHostPort(host, strconv.Itoa(DefaultGatewayDiscoverPort))
		}
		return ""
	}
	return raw
}

// NormalizeAPSConfiguredGatewayAddresses parses the gatewayAddress field
// and returns a deduplicated, normalized slice.
func NormalizeAPSConfiguredGatewayAddresses(gatewayAddress string) []string {
	parts := splitAPSGatewayAddressText(gatewayAddress)
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	add := func(raw string) {
		addr := normalizeAPSGatewayAddress(raw)
		if addr == "" {
			return
		}
		if _, exists := seen[addr]; exists {
			return
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	for _, raw := range splitAPSGatewayAddressText(gatewayAddress) {
		add(raw)
	}
	return out
}

// EndpointPortMapping defines a port mapping between endpoints.
type EndpointPortMapping struct {
	LocalListen    string `json:"localListen"`
	RemoteTarget   string `json:"remoteTarget"`
	TargetEndpoint string `json:"targetEndpoint"`
}

// UnmarshalJSON decodes localListen which can be a port int or "host:port" string.
func (m *EndpointPortMapping) UnmarshalJSON(data []byte) error {
	type endpointPortMappingAlias struct {
		LocalListen    json.RawMessage `json:"localListen"`
		RemoteTarget   string          `json:"remoteTarget"`
		TargetEndpoint string          `json:"targetEndpoint"`
	}
	var aux endpointPortMappingAlias
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	localListen, err := parseLocalListenJSON(aux.LocalListen)
	if err != nil {
		return err
	}

	m.LocalListen = localListen
	m.RemoteTarget = strings.TrimSpace(aux.RemoteTarget)
	m.TargetEndpoint = strings.TrimSpace(aux.TargetEndpoint)
	return nil
}

func parseLocalListenJSON(raw json.RawMessage) (string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return "", errors.New("localListen is required")
	}
	if strings.HasPrefix(trimmed, "\"") {
		var listen string
		if err := json.Unmarshal(raw, &listen); err != nil {
			return "", fmt.Errorf("invalid localListen string: %w", err)
		}
		return normalizeLocalListenAddress(listen)
	}
	port, err := strconv.Atoi(trimmed)
	if err != nil {
		return "", fmt.Errorf("localListen must be port number or listen address, got %s", trimmed)
	}
	return normalizeLocalListenAddress(strconv.Itoa(port))
}

func normalizeLocalListenAddress(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("localListen is required")
	}

	if port, err := strconv.Atoi(raw); err == nil {
		if err := validateLocalListenPort(port); err != nil {
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
	if err := validateLocalListenPort(port); err != nil {
		return "", err
	}

	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func validateLocalListenPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("localListen port out of range: %d", port)
	}
	return nil
}

// EndpointSSHConfig holds SSH plugin settings for an endpoint.
// It accepts both pointKey and point_key for compatibility.
type EndpointSSHConfig struct {
	Enabled  *bool             `json:"enabled,omitempty"`
	Port     int               `json:"port,omitempty"`
	PointKey string            `json:"pointKey,omitempty"`
	Password string            `json:"password,omitempty"`
	Users    []EndpointSSHUser `json:"users,omitempty"`
}

// UnmarshalJSON tolerates point_key (snake_case) as a fallback for pointKey.
func (c *EndpointSSHConfig) UnmarshalJSON(data []byte) error {
	type endpointSSHConfigAlias struct {
		Enabled       *bool             `json:"enabled,omitempty"`
		Port          int               `json:"port,omitempty"`
		PointKey      string            `json:"pointKey,omitempty"`
		Password      string            `json:"password,omitempty"`
		PointKeySnake string            `json:"point_key,omitempty"`
		Users         []EndpointSSHUser `json:"users,omitempty"`
	}
	var aux endpointSSHConfigAlias
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	c.Enabled = aux.Enabled
	c.Port = aux.Port
	c.Password = strings.TrimSpace(aux.Password)
	c.PointKey = strings.TrimSpace(aux.PointKey)
	if c.PointKey == "" {
		c.PointKey = strings.TrimSpace(aux.PointKeySnake)
	}
	c.Users = aux.Users
	return nil
}

// EndpointSSHUser describes one SSH account and its authorized keys.
type EndpointSSHUser struct {
	Name     string               `json:"name"`
	Password string               `json:"password,omitempty"`
	Keys     EndpointSSHKeyValues `json:"keys,omitempty"`
}

// EndpointSSHKeyValues accepts either a JSON string or []string.
type EndpointSSHKeyValues []string

// UnmarshalJSON handles both a single string and a []string.
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
