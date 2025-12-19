package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// EndpointRuntimeConfig holds the configuration fetched from APS
type EndpointRuntimeConfig struct {
	ID           string              `json:"id"`
	TunnelName   string              `json:"tunnelName"`
	EndpointName string              `json:"endpointName"`
	Password     string              `json:"password,omitempty"`
	PortMappings []PortMappingConfig `json:"portMappings,omitempty"`
}

// PortMappingConfig defines a port mapping from local to remote endpoint
type PortMappingConfig struct {
	LocalPort      int    `json:"localPort"`      // Port this endpoint listens on
	RemoteTarget   string `json:"remoteTarget"`   // IP:Port on the remote endpoint's network
	TargetEndpoint string `json:"targetEndpoint"` // Which endpoint to forward traffic to
}

// ConfigResponse is the APS response for endpoint configuration
type ConfigResponse struct {
	Success bool                   `json:"success"`
	Config  *EndpointRuntimeConfig `json:"config,omitempty"`
	Error   string                 `json:"error,omitempty"`
}

// FetchConfigFromAPS retrieves endpoint configuration from APS server
func FetchConfigFromAPS(apsAddr, configID string) (*EndpointRuntimeConfig, error) {
	url := fmt.Sprintf("http://%s/.api/endpoints?id=%s", apsAddr, configID)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to APS: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("APS returned error status %d: %s", resp.StatusCode, string(body))
	}

	var configResp ConfigResponse
	if err := json.Unmarshal(body, &configResp); err != nil {
		return nil, fmt.Errorf("failed to parse config response: %w", err)
	}

	if !configResp.Success {
		return nil, fmt.Errorf("APS error: %s", configResp.Error)
	}

	if configResp.Config == nil {
		return nil, fmt.Errorf("no configuration found for ID: %s", configID)
	}

	return configResp.Config, nil
}

// ValidateConfig validates the endpoint configuration
func (c *EndpointRuntimeConfig) ValidateConfig() error {
	if c.TunnelName == "" {
		return fmt.Errorf("tunnel name is required")
	}
	if c.EndpointName == "" {
		return fmt.Errorf("endpoint name is required")
	}
	return nil
}

// initializeConfiguration sets up the endpoint configuration based on provided flags
// Supports both new -cid mode and legacy -tunnel mode
func initializeConfiguration() error {
	// Check for new configuration mode: -cid with -server or -listen
	if *configID != "" {
		// New mode: fetch config from APS
		if *serverAddr == "" {
			return fmt.Errorf("when using -cid, you must specify -server <addr:port>")
		}

		if *serverAddr != "" {
			// Active mode: connect to APS and fetch config
			log.Printf("Fetching configuration from APS (%s) with ID: %s", *serverAddr, *configID)
			config, err := FetchConfigFromAPS(*serverAddr, *configID)
			if err != nil {
				return fmt.Errorf("failed to fetch configuration: %w", err)
			}
			if err := config.ValidateConfig(); err != nil {
				return fmt.Errorf("invalid configuration: %w", err)
			}
			runtimeConfig = config
			usingLegacyMode = false
			log.Printf("Configuration loaded: tunnel=%s, endpoint=%s", config.TunnelName, config.EndpointName)
			return nil
		}

	}

	// Legacy mode: use -tunnel, -name, -password flags (deprecated)
	if *tunnelName != "" {
		printDeprecationWarning()
		// Create runtime config from legacy flags
		runtimeConfig = &EndpointRuntimeConfig{
			TunnelName:   *tunnelName,
			EndpointName: *name,
			Password:     *tunnelPassword,
			
		}
		usingLegacyMode = true
		return nil
	}

	return fmt.Errorf("configuration required: use -cid <config-id> -server <addr:port> OR -tunnel <name> (deprecated)")
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

// GetEffectivePassword returns the password from runtime config or legacy flag
func GetEffectivePassword() string {
	if runtimeConfig != nil {
		return runtimeConfig.Password
	}
	return *tunnelPassword
}
