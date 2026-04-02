package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
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
