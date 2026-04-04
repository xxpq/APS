package main

import (
	"errors"
	"fmt"
	"strings"
)

const (
	GridDeploymentModeStandalone = "standalone"
	GridDeploymentModeCluster    = "cluster"

	GridRoutingStrategyReliability = "reliability"
)

type GridConfig struct {
	Deployment *GridDeploymentConfig `json:"deployment,omitempty"`
	Routing    *GridRoutingConfig    `json:"routing,omitempty"`
	Security   *GridSecurityConfig   `json:"security,omitempty"`
	Relay      *GridRelayConfig      `json:"relay,omitempty"`
	Transport  *GridTransportConfig  `json:"transport,omitempty"`
	ICE        *GridICEConfig        `json:"ice,omitempty"`
}

type GridDeploymentConfig struct {
	Enabled       *bool    `json:"enabled,omitempty"`
	Mode          string   `json:"mode,omitempty"`
	SQLitePath    string   `json:"sqlite_path,omitempty"`
	EtcdEndpoints []string `json:"etcd_endpoints,omitempty"`
	NatsURL       string   `json:"nats_url,omitempty"`
}

type GridRoutingConfig struct {
	Strategy       string `json:"strategy,omitempty"`
	HopGuard       *bool  `json:"hop_guard,omitempty"`
	MaxHop         *int   `json:"max_hop,omitempty"`
	PathTTLSeconds *int   `json:"path_ttl_seconds,omitempty"`
}

type GridSecurityConfig struct {
	DefaultTokenTTLSeconds *int `json:"default_token_ttl_seconds,omitempty"`
}

type GridRelayConfig struct {
	Enabled           *bool `json:"enabled,omitempty"`
	MaxRelayHops      *int  `json:"max_relay_hops,omitempty"`
	FallbackTimeoutMs *int  `json:"fallback_timeout_ms,omitempty"`
}

type GridTransportConfig struct {
	EnableQUIC *bool `json:"enable_quic,omitempty"`
	EnableTCP  *bool `json:"enable_tcp,omitempty"`
	Parallel   *bool `json:"parallel,omitempty"`
}

type GridICEConfig struct {
	Enabled           *bool    `json:"enabled,omitempty"`
	StaticCandidates  []string `json:"static_candidates,omitempty"`
	STUNServers       []string `json:"stun_servers,omitempty"`
	TURNServers       []string `json:"turn_servers,omitempty"`
	SessionTTLSeconds *int     `json:"session_ttl_seconds,omitempty"`
}

func isGridEnabled(config *Config) bool {
	if config == nil {
		return false
	}
	// Grid is enabled by default for latest APS deployments.
	// Explicit `grid.deployment.enabled=false` is required to disable it.
	if config.Grid == nil || config.Grid.Deployment == nil || config.Grid.Deployment.Enabled == nil {
		return true
	}
	return *config.Grid.Deployment.Enabled
}

func ensureGridConfigSettings(config *Config) error {
	if config == nil {
		return nil
	}
	if config.Grid == nil {
		config.Grid = &GridConfig{}
	}

	if config.Grid.Deployment == nil {
		config.Grid.Deployment = &GridDeploymentConfig{}
	}
	if config.Grid.Routing == nil {
		config.Grid.Routing = &GridRoutingConfig{}
	}
	if config.Grid.Security == nil {
		config.Grid.Security = &GridSecurityConfig{}
	}
	if config.Grid.Relay == nil {
		config.Grid.Relay = &GridRelayConfig{}
	}
	if config.Grid.Transport == nil {
		config.Grid.Transport = &GridTransportConfig{}
	}
	if config.Grid.ICE == nil {
		config.Grid.ICE = &GridICEConfig{}
	}

	enabled := true
	if config.Grid.Deployment.Enabled != nil {
		enabled = *config.Grid.Deployment.Enabled
	}
	if !enabled {
		return nil
	}

	mode := strings.ToLower(strings.TrimSpace(config.Grid.Deployment.Mode))
	if mode == "" {
		mode = GridDeploymentModeStandalone
	}
	switch mode {
	case GridDeploymentModeStandalone:
		if strings.TrimSpace(config.Grid.Deployment.SQLitePath) == "" {
			config.Grid.Deployment.SQLitePath = "aps_grid.db"
		}
	case GridDeploymentModeCluster:
		if len(config.Grid.Deployment.EtcdEndpoints) == 0 {
			return errors.New("grid.deployment.etcd_endpoints is required in cluster mode")
		}
		for i := range config.Grid.Deployment.EtcdEndpoints {
			config.Grid.Deployment.EtcdEndpoints[i] = strings.TrimSpace(config.Grid.Deployment.EtcdEndpoints[i])
			if config.Grid.Deployment.EtcdEndpoints[i] == "" {
				return fmt.Errorf("grid.deployment.etcd_endpoints[%d] is empty", i)
			}
		}
		if strings.TrimSpace(config.Grid.Deployment.NatsURL) == "" {
			return errors.New("grid.deployment.nats_url is required in cluster mode")
		}
	default:
		return fmt.Errorf("unsupported grid.deployment.mode: %s", mode)
	}
	config.Grid.Deployment.Mode = mode

	strategy := strings.ToLower(strings.TrimSpace(config.Grid.Routing.Strategy))
	if strategy == "" {
		strategy = GridRoutingStrategyReliability
	}
	if strategy != GridRoutingStrategyReliability {
		return fmt.Errorf("unsupported grid.routing.strategy: %s", strategy)
	}
	config.Grid.Routing.Strategy = strategy

	if config.Grid.Routing.HopGuard == nil {
		v := true
		config.Grid.Routing.HopGuard = &v
	}
	if config.Grid.Routing.MaxHop == nil {
		v := 128
		config.Grid.Routing.MaxHop = &v
	}
	if config.Grid.Routing.PathTTLSeconds == nil {
		v := 120
		config.Grid.Routing.PathTTLSeconds = &v
	}
	if *config.Grid.Routing.MaxHop <= 0 {
		return errors.New("grid.routing.max_hop must be > 0")
	}
	if *config.Grid.Routing.PathTTLSeconds <= 0 {
		return errors.New("grid.routing.path_ttl_seconds must be > 0")
	}

	if config.Grid.Security.DefaultTokenTTLSeconds == nil {
		v := 300
		config.Grid.Security.DefaultTokenTTLSeconds = &v
	}
	if *config.Grid.Security.DefaultTokenTTLSeconds <= 0 {
		return errors.New("grid.security.default_token_ttl_seconds must be > 0")
	}

	if config.Grid.Relay.Enabled == nil {
		v := true
		config.Grid.Relay.Enabled = &v
	}
	if config.Grid.Relay.MaxRelayHops == nil {
		v := 6
		config.Grid.Relay.MaxRelayHops = &v
	}
	if config.Grid.Relay.FallbackTimeoutMs == nil {
		v := 3000
		config.Grid.Relay.FallbackTimeoutMs = &v
	}
	if *config.Grid.Relay.MaxRelayHops <= 0 {
		return errors.New("grid.relay.max_relay_hops must be > 0")
	}
	if *config.Grid.Relay.FallbackTimeoutMs <= 0 {
		return errors.New("grid.relay.fallback_timeout_ms must be > 0")
	}

	if config.Grid.Transport.EnableQUIC == nil {
		v := true
		config.Grid.Transport.EnableQUIC = &v
	}
	if config.Grid.Transport.EnableTCP == nil {
		v := true
		config.Grid.Transport.EnableTCP = &v
	}
	if config.Grid.Transport.Parallel == nil {
		v := true
		config.Grid.Transport.Parallel = &v
	}

	if config.Grid.ICE.Enabled == nil {
		v := true
		config.Grid.ICE.Enabled = &v
	}
	if config.Grid.ICE.SessionTTLSeconds == nil {
		v := 300
		config.Grid.ICE.SessionTTLSeconds = &v
	}
	if *config.Grid.ICE.SessionTTLSeconds <= 0 {
		return errors.New("grid.ice.session_ttl_seconds must be > 0")
	}

	return nil
}
