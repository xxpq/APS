// Root config.go (Stage 9.1a)
//
// Most type definitions and their methods now live in the aps/config
// sub-package (see config/types.go, config/process.go, config/endpoint_aps.go,
// config/helpers.go). This file keeps a thin compatibility layer for
// root main:
//
//   1. Go type aliases (so existing call-sites that reference the bare
//      names like `Config`, `Mapping`, `*ListenConfig` compile unchanged).
//   2. Wrapper functions for the few helpers that the root main's
//      http_handler.go / proxy.go / webserver.go / main.go still call
//      by their old unexported names (parseStringOrArray, maskToken).
//   3. LoadConfig wrapper that delegates to config.LoadConfig and also
//      sets the global debug flag (Stage 8: util.IsDebugMode is canonical).
//   4. An init() that wires the root's *ProxyManager into
//      aps/config.NewProxyManagerFn so processConfig can resolve
//      mapping proxy lists without depending on the concrete type.
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

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

type (
	Config                 = config.Config
	ListenConfig           = config.ListenConfig
	ServerAuth             = config.ServerAuth
	CertFiles              = config.CertFiles
	Mapping                = config.Mapping
	ViaConfig              = config.ViaConfig
	RuleAuth               = config.RuleAuth
	EndpointConfig         = config.EndpointConfig
	EndpointConfig_APS     = config.EndpointConfig_APS
	EndpointPortMapping    = config.EndpointPortMapping
	EndpointSSHConfig      = config.EndpointSSHConfig
	EndpointSSHUser        = config.EndpointSSHUser
	EndpointSSHKeyValues   = config.EndpointSSHKeyValues
	User                   = config.User
	Group                  = config.Group
	ProxyConfig            = config.ProxyConfig
	TunnelConfig           = config.TunnelConfig
	AuthConfig             = config.AuthConfig
	AuthProviderConfig     = config.AuthProviderConfig
	TokenLocation          = config.TokenLocation
	StaticCacheConfig      = config.StaticCacheConfig
	CacheSizeLimit         = config.CacheSizeLimit
	ScriptingConfig        = config.ScriptingConfig
	P12Config              = config.P12Config
	ConnectionPolicies     = config.ConnectionPolicies
	TrafficPolicies        = config.TrafficPolicies
	GRPCConfig             = config.GRPCConfig
	RestToGrpcConfig       = config.RestToGrpcConfig
	WebSocketConfig        = config.WebSocketConfig
	WebSocketMessageConfig = config.WebSocketMessageConfig
	FinalPolicies          = config.FinalPolicies
	ProxyResolver          = config.ProxyResolver
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	ServerTypeTCP             = config.ServerTypeTCP
	ServerTypeHTTP            = config.ServerTypeHTTP
	ServerTypeUDP             = config.ServerTypeUDP
	ServerTypeTCPUDP          = config.ServerTypeTCPUDP
	ServerTypeHTTPUDP         = config.ServerTypeHTTPUDP
	ServerTypeHTTP3           = config.ServerTypeHTTP3
	DefaultGatewayDiscoverPort = config.DefaultGatewayDiscoverPort
)

// ---------------------------------------------------------------------------
// Wrappers for the helpers still used by root-main call-sites
// (http_handler.go, proxy.go, webserver.go, main.go).
// ---------------------------------------------------------------------------

// LoadConfig reads the JSON file, processes it, and sets the global
// debug flag. The actual loading + processing happens in
// aps/config.LoadConfig; this wrapper additionally updates the root
// IsDebugMode var and util.IsDebugMode.
func LoadConfig(filename string) (*Config, error) {
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
