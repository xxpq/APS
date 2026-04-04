package main

import (
	"fmt"
	"net"
	"strings"
)

// ImmutableConnectionContext contains all immutable inputs required to establish one tunnel session.
type ImmutableConnectionContext struct {
	ServerAddress     string
	ConfigID          string
	ServerName        string
	TunnelName        string
	EndpointName      string
	SessionCredential string
	SessionExpiresAt  int64
	KDFVersion        string
	KDFSalt           string
	PortMappings      []PortMappingConfig
	SSH               *EndpointSSHConfig
	MTLSCertFile      string
	MTLSKeyFile       string
	MTLSCAFile        string
}

func normalizeServerAddressForSession(serverAddress string) string {
	serverAddress = strings.TrimSpace(serverAddress)
	if serverAddress == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(serverAddress); err != nil {
		if strings.Contains(err.Error(), "missing port") {
			return serverAddress + ":443"
		}
		if strings.Contains(err.Error(), "too many colons") {
			return net.JoinHostPort(serverAddress, "443")
		}
	}
	return serverAddress
}

func clonePortMappingsForContext(src []PortMappingConfig) []PortMappingConfig {
	if len(src) == 0 {
		return nil
	}
	dst := make([]PortMappingConfig, len(src))
	copy(dst, src)
	return dst
}

func cloneEndpointSSHConfigForContext(src *EndpointSSHConfig) *EndpointSSHConfig {
	if src == nil {
		return nil
	}

	dst := &EndpointSSHConfig{
		Port:     src.Port,
		PointKey: strings.TrimSpace(src.PointKey),
	}

	if src.Enabled != nil {
		enabled := *src.Enabled
		dst.Enabled = &enabled
	}

	if len(src.Users) > 0 {
		dst.Users = make([]EndpointSSHUser, 0, len(src.Users))
		for _, user := range src.Users {
			copied := EndpointSSHUser{
				Name:     strings.TrimSpace(user.Name),
				Password: user.Password,
			}
			if len(user.Keys) > 0 {
				copied.Keys = make(EndpointSSHKeyValues, 0, len(user.Keys))
				for _, key := range user.Keys {
					k := strings.TrimSpace(key)
					if k == "" {
						continue
					}
					copied.Keys = append(copied.Keys, k)
				}
			}
			dst.Users = append(dst.Users, copied)
		}
	}

	return dst
}

func BuildImmutableConnectionContext(serverAddress, configID string) (*ImmutableConnectionContext, error) {
	serverAddress = normalizeServerAddressForSession(serverAddress)
	configID = strings.TrimSpace(configID)
	if serverAddress == "" {
		return nil, fmt.Errorf("server address is required")
	}
	if configID == "" {
		return nil, fmt.Errorf("config id is required")
	}

	cfg, err := FetchConfigFromAPS(serverAddress, configID)
	if err != nil {
		return nil, err
	}
	if err := cfg.ValidateConfig(); err != nil {
		return nil, err
	}

	return &ImmutableConnectionContext{
		ServerAddress:     serverAddress,
		ConfigID:          configID,
		ServerName:        strings.TrimSpace(cfg.ServerName),
		TunnelName:        strings.TrimSpace(cfg.TunnelName),
		EndpointName:      strings.TrimSpace(cfg.EndpointName),
		SessionCredential: strings.TrimSpace(cfg.SessionCredential),
		SessionExpiresAt:  cfg.SessionExpiresAt,
		KDFVersion:        strings.TrimSpace(cfg.KDFVersion),
		KDFSalt:           strings.TrimSpace(cfg.KDFSalt),
		PortMappings:      clonePortMappingsForContext(cfg.PortMappings),
		SSH:               cloneEndpointSSHConfigForContext(cfg.SSH),
		MTLSCertFile:      strings.TrimSpace(*mtlsCertFile),
		MTLSKeyFile:       strings.TrimSpace(*mtlsKeyFile),
		MTLSCAFile:        strings.TrimSpace(*mtlsCAFile),
	}, nil
}
