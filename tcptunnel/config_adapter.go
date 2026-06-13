package tcptunnel

import (
	cfg "aps/config"
)

// BuildConfig projects the main package's monolithic *config.Config into the
// minimal tcptunnel.Config projection that the tunnel manager and TCP server
// need. Adding new fields here is the integration point for any additional
// configuration the tunnel server needs to read.
//
// Stage 9.2 moved this from root main into the tcptunnel sub-package so the
// tunnel implementation owns the projection. The aps/config package remains
// the canonical source for *Config.
func BuildConfig(c *cfg.Config) *Config {
	if c == nil {
		return nil
	}
	tunnels := make(map[string]*TunnelConfig, len(c.Tunnels))
	for k, v := range c.Tunnels {
		if v == nil {
			continue
		}
		tunnels[k] = &TunnelConfig{
			Servers:    append([]string(nil), v.Servers...),
			KDFVersion: v.KDFVersion,
			KDFSalt:    v.KDFSalt,
		}
	}
	endpoints := make(map[string]*EndpointConfig, len(c.Endpoints))
	for k, v := range c.Endpoints {
		if v == nil {
			continue
		}
		endpoints[k] = &EndpointConfig{
			TunnelName:     v.TunnelName,
			EndpointName:   v.EndpointName,
			AllowMultiNode: v.AllowMultiNode,
			Mirror:         v.Mirror,
		}
	}
	mirrors := make(map[string][]string, len(c.Mirrors))
	for k, v := range c.Mirrors {
		mirrors[k] = append([]string(nil), v...)
	}
	return &Config{
		Tunnels:   tunnels,
		Endpoints: endpoints,
		Mirrors:   mirrors,
		Version:   c.Version,
	}
}
