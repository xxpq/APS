package logging

import (
	"aps/config"
	"aps/firewall"
)

// LoggingConfig holds the effective logging configuration for a request.
type LoggingConfig struct {
	LogLevel       int
	RetentionHours int
}

// Collect merges logging settings from all matched dimension configs.
// Returns: highest LogLevel, longest RetentionHours.
// Falls back to global config if no dimension has values set.
//
// Stage 9.2 moved this from root main into the logging sub-package.
// Callers invoke logging.Collect(global, server, mapping, user, groups,
// tunnel, proxy, firewall) directly.
func Collect(
	globalConfig *config.Config,
	server *config.ListenConfig,
	mapping *config.Mapping,
	user *config.User,
	groups []*config.Group,
	tunnel *config.TunnelConfig,
	proxy *config.ProxyConfig,
	firewall *firewall.FirewallRule,
) LoggingConfig {
	// Default values from global config
	logLevel := 0
	retentionHours := 24

	if globalConfig != nil {
		if globalConfig.LogLevel != nil {
			logLevel = *globalConfig.LogLevel
		}
		if globalConfig.LogRetentionHours != nil {
			retentionHours = *globalConfig.LogRetentionHours
		}
	}

	updateConfig := func(dimLogLevel, dimRetention *int) {
		if dimLogLevel != nil && *dimLogLevel > logLevel {
			logLevel = *dimLogLevel
		}
		if dimRetention != nil && *dimRetention > retentionHours {
			retentionHours = *dimRetention
		}
	}

	if server != nil {
		updateConfig(server.LogLevel, server.LogRetentionHours)
	}
	if mapping != nil {
		updateConfig(mapping.LogLevel, mapping.LogRetentionHours)
	}
	if user != nil {
		updateConfig(user.LogLevel, user.LogRetentionHours)
	}
	if groups != nil {
		for _, group := range groups {
			if group != nil {
				updateConfig(group.LogLevel, group.LogRetentionHours)
			}
		}
	}
	if tunnel != nil {
		updateConfig(tunnel.LogLevel, tunnel.LogRetentionHours)
	}
	if proxy != nil {
		updateConfig(proxy.LogLevel, proxy.LogRetentionHours)
	}
	if firewall != nil {
		updateConfig(firewall.LogLevel, firewall.LogRetentionHours)
	}

	return LoggingConfig{
		LogLevel:       logLevel,
		RetentionHours: retentionHours,
	}
}

// MaxRetentionHours scans all configs and returns the maximum retention
// hours. Used for cleanup to ensure we don't delete logs that should be
// retained.
//
// Stage 9.2: this used to be getMaxRetentionHours in root main. Renamed
// to logging.MaxRetentionHours to expose a clearer public name.
func MaxRetentionHours(c *config.Config) int {
	maxRetention := 24 // default

	if c.LogRetentionHours != nil && *c.LogRetentionHours > maxRetention {
		maxRetention = *c.LogRetentionHours
	}

	for _, server := range c.Servers {
		if server != nil && server.LogRetentionHours != nil && *server.LogRetentionHours > maxRetention {
			maxRetention = *server.LogRetentionHours
		}
	}

	for i := range c.Mappings {
		mapping := &c.Mappings[i]
		if mapping.LogRetentionHours != nil && *mapping.LogRetentionHours > maxRetention {
			maxRetention = *mapping.LogRetentionHours
		}
	}

	if c.Auth != nil && c.Auth.Users != nil {
		for _, user := range c.Auth.Users {
			if user != nil && user.LogRetentionHours != nil && *user.LogRetentionHours > maxRetention {
				maxRetention = *user.LogRetentionHours
			}
		}
	}

	if c.Auth != nil && c.Auth.Groups != nil {
		for _, group := range c.Auth.Groups {
			if group != nil && group.LogRetentionHours != nil && *group.LogRetentionHours > maxRetention {
				maxRetention = *group.LogRetentionHours
			}
		}
	}

	for _, tunnel := range c.Tunnels {
		if tunnel != nil && tunnel.LogRetentionHours != nil && *tunnel.LogRetentionHours > maxRetention {
			maxRetention = *tunnel.LogRetentionHours
		}
	}

	for _, proxy := range c.Proxies {
		if proxy != nil && proxy.LogRetentionHours != nil && *proxy.LogRetentionHours > maxRetention {
			maxRetention = *proxy.LogRetentionHours
		}
	}

	for _, fw := range c.Firewalls {
		if fw != nil && fw.LogRetentionHours != nil && *fw.LogRetentionHours > maxRetention {
			maxRetention = *fw.LogRetentionHours
		}
	}

	return maxRetention
}
