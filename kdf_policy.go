package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	KDFVersionArgon2idV1     = "argon2id-v1"
	KDFVersionPBKDF2SHA256V3 = "pbkdf2-sha256-v3"
	DefaultTunnelKDFVersion  = KDFVersionArgon2idV1
	tunnelKDFSaltBytes       = 16
)

func normalizeKDFVersion(version string) (string, error) {
	version = strings.ToLower(strings.TrimSpace(version))
	if version == "" {
		return DefaultTunnelKDFVersion, nil
	}
	switch version {
	case KDFVersionArgon2idV1, KDFVersionPBKDF2SHA256V3:
		return version, nil
	default:
		return "", fmt.Errorf("unsupported kdfVersion: %s", version)
	}
}

func generateTunnelKDFSalt() (string, error) {
	salt := make([]byte, tunnelKDFSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return hex.EncodeToString(salt), nil
}

func ensureTunnelKDFSettings(config *Config) error {
	if config == nil || config.Tunnels == nil {
		return nil
	}

	for tunnelName, tunnel := range config.Tunnels {
		if tunnel == nil {
			continue
		}

		normalizedVersion, err := normalizeKDFVersion(tunnel.KDFVersion)
		if err != nil {
			return fmt.Errorf("tunnel %s: %w", tunnelName, err)
		}
		tunnel.KDFVersion = normalizedVersion

		if strings.TrimSpace(tunnel.KDFSalt) == "" {
			salt, genErr := generateTunnelKDFSalt()
			if genErr != nil {
				return fmt.Errorf("tunnel %s: failed to generate kdfSalt: %w", tunnelName, genErr)
			}
			tunnel.KDFSalt = salt
		}
	}

	return nil
}
