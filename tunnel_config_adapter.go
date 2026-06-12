package main

import (
	"aps/tcptunnel"
)

// buildTCPTunnelConfig projects the main package's monolithic *Config into the
// minimal tcptunnel.Config projection that the tunnel manager and TCP server
// need. Adding new fields here is the integration point for any additional
// configuration the tunnel server needs to read.
func buildTCPTunnelConfig(c *Config) *tcptunnel.Config {
	if c == nil {
		return nil
	}
	tunnels := make(map[string]*tcptunnel.TunnelConfig, len(c.Tunnels))
	for k, v := range c.Tunnels {
		if v == nil {
			continue
		}
		tunnels[k] = &tcptunnel.TunnelConfig{
			Servers:    append([]string(nil), v.Servers...),
			KDFVersion: v.KDFVersion,
			KDFSalt:    v.KDFSalt,
		}
	}
	endpoints := make(map[string]*tcptunnel.EndpointConfig, len(c.Endpoints))
	for k, v := range c.Endpoints {
		if v == nil {
			continue
		}
		endpoints[k] = &tcptunnel.EndpointConfig{
			TunnelName:    v.TunnelName,
			EndpointName:  v.EndpointName,
			AllowMultiNode: v.AllowMultiNode,
			Mirror:        v.Mirror,
		}
	}
	mirrors := make(map[string][]string, len(c.Mirrors))
	for k, v := range c.Mirrors {
		mirrors[k] = append([]string(nil), v...)
	}
	return &tcptunnel.Config{
		Tunnels:   tunnels,
		Endpoints: endpoints,
		Mirrors:   mirrors,
		Version:   c.Version,
	}
}
