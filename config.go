// Root config.go (Stage 9.1b)
//
// All type definitions and their methods now live in the aps/config
// sub-package (see config/types.go, config/process.go, config/endpoint_aps.go,
// config/helpers.go). This file keeps a thin compatibility layer for
// root main:
//
//   1. LoadConfig wrapper that delegates to config.LoadConfig and also
//      sets the global debug flag (Stage 8: util.IsDebugMode is canonical).
//   2. An init() that wires the root's *ProxyManager into
//      aps/config.NewProxyManagerFn so processConfig can resolve
//      mapping proxy lists without depending on the concrete type.
//   3. parseStringOrArray, stringPtr, maskToken, normalizeAPSConfiguredGatewayAddresses
//      wrappers so root-main call-sites (http_handler.go, proxy.go,
//      webserver.go, config_gateway_defaults_test.go) compile without
//      forcing them to import aps/config directly.
package main

import (
	"aps/config"
	"aps/util"
)

// IsDebugMode mirrors util.IsDebugMode for backwards compatibility.
// See Stage 8 cleanup: util.IsDebugMode is the canonical source.
var IsDebugMode = util.IsDebugMode

func init() {
	// Inject the root main's *ProxyManager into aps/config so the
	// mapping processor can resolve ResolvedProxy without importing
	// the concrete type. Stage 9.2 will move *ProxyManager into
	// aps/proxy, at which point this binding is no longer needed.
	config.NewProxyManagerFn = func(urls []string) config.ProxyResolver {
		return NewProxyManager(urls)
	}
}

// LoadConfig reads the JSON file, processes it, and sets the global
// debug flag. The actual loading + processing happens in
// aps/config.LoadConfig; this wrapper additionally updates the root
// IsDebugMode var and util.IsDebugMode.
func LoadConfig(filename string) (*config.Config, error) {
	cfg, err := config.LoadConfig(filename)
	if err != nil {
		return nil, err
	}
	if cfg.Debug != nil && *cfg.Debug {
		IsDebugMode = true
		util.IsDebugMode = true
	} else {
		IsDebugMode = false
		util.IsDebugMode = false
	}
	return cfg, nil
}

// parseStringOrArray accepts string or []string and returns []string.
// Wrapper around aps/config.ParseStringOrArray so root main's call-sites
// (http_handler.go, proxy.go) compile unchanged.
func parseStringOrArray(data interface{}) []string {
	return config.ParseStringOrArray(data)
}

// maskToken hides part of a token for safe log output.
func maskToken(token string) string {
	return config.MaskToken(token)
}

// stringPtr returns a pointer to s. Kept private in root main because
// the only call-site is webserver.go (KDF salt), and *string is the same
// type across packages.
func stringPtr(s string) *string { return &s }

// normalizeAPSConfiguredGatewayAddresses wraps config.NormalizeAPSConfiguredGatewayAddresses
// for root main's test files (config_gateway_defaults_test.go).
func normalizeAPSConfiguredGatewayAddresses(addr string) []string {
	return config.NormalizeAPSConfiguredGatewayAddresses(addr)
}
