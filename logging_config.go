package main

// LoggingConfig holds the effective logging configuration for a request
type LoggingConfig struct {
	LogLevel       int
	RetentionHours int
}

// collectLoggingConfig merges logging settings from all matched dimension configs
// Returns: highest LogLevel, longest RetentionHours
// Falls back to global config if no dimension has values set
func collectLoggingConfig(
	globalConfig *Config,
	server *ListenConfig,
	mapping *Mapping,
	user *User,
	groups []*Group,
	tunnel *TunnelConfig,
	proxy *ProxyConfig,
	firewall *FirewallRule,
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

	// Helper to update with max LogLevel and max RetentionHours
	updateConfig := func(dimLogLevel, dimRetention *int) {
		if dimLogLevel != nil {
			if *dimLogLevel > logLevel {
				logLevel = *dimLogLevel
			}
		}
		if dimRetention != nil {
			if *dimRetention > retentionHours {
				retentionHours = *dimRetention
			}
		}
	}
	// Collect from all dimensions
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

// getMaxRetentionHours scans all configs and returns the maximum retention hours
// Used for cleanup to ensure we don't delete logs that should be retained
func getMaxRetentionHours(config *Config) int {
	maxRetention := 24 // default

	// Global config
	if config.LogRetentionHours != nil && *config.LogRetentionHours > maxRetention {
		maxRetention = *config.LogRetentionHours
	}

	// Servers
	for _, server := range config.Servers {
		if server != nil && server.LogRetentionHours != nil && *server.LogRetentionHours > maxRetention {
			maxRetention = *server.LogRetentionHours
		}
	}

	// Mappings
	for i := range config.Mappings {
		mapping := &config.Mappings[i]
		if mapping.LogRetentionHours != nil && *mapping.LogRetentionHours > maxRetention {
			maxRetention = *mapping.LogRetentionHours
		}
	}

	// Users
	if config.Auth != nil && config.Auth.Users != nil {
		for _, user := range config.Auth.Users {
			if user != nil && user.LogRetentionHours != nil && *user.LogRetentionHours > maxRetention {
				maxRetention = *user.LogRetentionHours
			}
		}
	}

	// Groups
	if config.Auth != nil && config.Auth.Groups != nil {
		for _, group := range config.Auth.Groups {
			if group != nil && group.LogRetentionHours != nil && *group.LogRetentionHours > maxRetention {
				maxRetention = *group.LogRetentionHours
			}
		}
	}

	// Tunnels
	for _, tunnel := range config.Tunnels {
		if tunnel != nil && tunnel.LogRetentionHours != nil && *tunnel.LogRetentionHours > maxRetention {
			maxRetention = *tunnel.LogRetentionHours
		}
	}

	// Proxies
	for _, proxy := range config.Proxies {
		if proxy != nil && proxy.LogRetentionHours != nil && *proxy.LogRetentionHours > maxRetention {
			maxRetention = *proxy.LogRetentionHours
		}
	}

	// Firewalls
	for _, fw := range config.Firewalls {
		if fw != nil && fw.LogRetentionHours != nil && *fw.LogRetentionHours > maxRetention {
			maxRetention = *fw.LogRetentionHours
		}
	}

	return maxRetention
}
