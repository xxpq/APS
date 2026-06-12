package tcptunnel

// Config is a minimal projection of the project's main config containing only
// the fields that the TCP tunnel server and manager need to read at runtime.
// It is constructed by the main package (via a helper, e.g. SnapshotForTCPTunnel)
// so that this package does not have to import the main package's monolithic
// Config struct.
type Config struct {
	// Tunnels maps tunnel name -> TunnelConfig. The server consults this to
	// validate which endpoints may register and to look up KDF parameters.
	Tunnels map[string]*TunnelConfig
	// Endpoints maps config id (cid) -> EndpointConfig. The server uses the
	// cid binding to authenticate endpoint registrations.
	Endpoints map[string]*EndpointConfig
	// Mirrors maps mirror group name -> list of mirror addresses.
	Mirrors map[string][]string
	// Version is the config version; used to tag control-plane payloads.
	Version int64
}

// TunnelConfig is a minimal projection of the project's main TunnelConfig
// holding only the fields read by the TCP tunnel server.
type TunnelConfig struct {
	// Servers is the list of server names this tunnel is bound to.
	Servers []string
	// KDFVersion is the key-derivation version advertised by the tunnel.
	KDFVersion string
	// KDFSalt is the KDF salt advertised by the tunnel.
	KDFSalt string
}

// EndpointConfig is a minimal projection of the project's main
// EndpointConfig_APS holding only the fields read by the TCP tunnel server.
type EndpointConfig struct {
	// TunnelName is the tunnel this endpoint is registered under.
	TunnelName string
	// EndpointName is the human-friendly endpoint name.
	EndpointName string
	// AllowMultiNode permits multiple concurrent nodes for the same
	// (tunnel, endpoint) pair. When false the server rejects duplicate
	// registrations.
	AllowMultiNode bool
	// Mirror is the name of the mirror group that should be pushed to
	// the endpoint after registration completes.
	Mirror string
}
