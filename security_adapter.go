package main

import (
	"aps/security"
	cfg "aps/config"
)

// shouldUseInsecureBackendMode is a thin main-package wrapper that projects
// main.EndpointConfig into security.EndpointConfigProjection and then calls
// security.ShouldUseInsecureBackendMode. It exists so the gateway files do not
// have to import the security package directly and so the conversion logic
// stays in one place.
//
// Projecting (rather than letting security import main.EndpointConfig) keeps
// the aps/security package free of main-package types and lets it be reused
// from other call sites in the future.
func shouldUseInsecureBackendMode(toConfig *cfg.EndpointConfig, rawTargetURL string) bool {
	var projection *security.EndpointConfigProjection
	if toConfig != nil {
		projection = &security.EndpointConfigProjection{
			Insecure: toConfig.Insecure,
		}
	}
	return security.ShouldUseInsecureBackendMode(projection, rawTargetURL)
}

// isInternalTLSBackendTarget is a thin main-package wrapper around
// security.IsInternalTLSBackendTarget.
func isInternalTLSBackendTarget(rawTargetURL string) bool {
	return security.IsInternalTLSBackendTarget(rawTargetURL)
}
