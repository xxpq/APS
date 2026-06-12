package security

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

func NormalizeKDFVersion(version string) (string, error) {
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

func GenerateTunnelKDFSalt() (string, error) {
	salt := make([]byte, tunnelKDFSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return hex.EncodeToString(salt), nil
}

// ensureTunnelKDFSettings 在调用方传入的 tunnels map 上设置 KDF 默认值。
// 接受 map[string]*TunnelKDFConfig 而不是 *Config 以解耦 security 包对 config 包的依赖。
func EnsureTunnelKDFSettings(tunnels map[string]*TunnelKDFConfig) error {
	if tunnels == nil {
		return nil
	}

	for tunnelName, tunnel := range tunnels {
		if tunnel == nil {
			continue
		}

		normalizedVersion, err := NormalizeKDFVersion(tunnel.KDFVersion)
		if err != nil {
			return fmt.Errorf("tunnel %s: %w", tunnelName, err)
		}
		tunnel.KDFVersion = normalizedVersion

		if tunnel.KDFSalt == nil || strings.TrimSpace(*tunnel.KDFSalt) == "" {
			salt, genErr := GenerateTunnelKDFSalt()
			if genErr != nil {
				return fmt.Errorf("tunnel %s: failed to generate kdfSalt: %w", tunnelName, genErr)
			}
			tunnel.KDFSalt = &salt
		}
	}

	return nil
}

// TunnelKDFConfig 描述 KDF 策略所需的最小配置结构。
// 解耦 security 包对 config 包的依赖。
type TunnelKDFConfig struct {
	KDFVersion string
	KDFSalt    *string
}
