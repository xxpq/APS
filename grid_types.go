package main

const (
	GridScopeAll               = "*"
	GridScopeNodeRegister      = "node:register"
	GridScopeNodeHeartbeat     = "node:heartbeat"
	GridScopeRouteAnnounce     = "route:announce"
	GridScopeRouteQuery        = "route:query"
	GridScopeICEPublish        = "ice:publish"
	GridScopeICEQuery          = "ice:query"
	GridScopeICESessionIssue   = "ice:session:issue"
	GridScopeICESessionRefresh = "ice:session:refresh"
	GridScopeSessionRefresh    = "session:refresh"
	GridScopeEventPull         = "event:pull"
)

func defaultGridEndpointControlScopes() string {
	return GridScopeNodeRegister + "," +
		GridScopeNodeHeartbeat + "," +
		GridScopeRouteAnnounce + "," +
		GridScopeRouteQuery + "," +
		GridScopeICEPublish + "," +
		GridScopeICEQuery + "," +
		GridScopeICESessionIssue + "," +
		GridScopeICESessionRefresh + "," +
		GridScopeSessionRefresh + "," +
		GridScopeEventPull
}

type NodeIdentity struct {
	NodeID       string            `json:"node_id"`
	PublicKey    string            `json:"public_key,omitempty"`
	TunnelName   string            `json:"tunnel_name,omitempty"`
	EndpointName string            `json:"endpoint_name,omitempty"`
	Region       string            `json:"region,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	UpdatedAt    int64             `json:"updated_at,omitempty"`
}

type NodeLease struct {
	NodeID    string `json:"node_id"`
	ExpiresAt int64  `json:"expires_at"`
}

type ICECandidateSet struct {
	NodeID      string            `json:"node_id"`
	Candidates  []string          `json:"candidates,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	ExpiresAt   int64             `json:"expires_at"`
	UpdatedAt   int64             `json:"updated_at,omitempty"`
	PublishedBy string            `json:"published_by,omitempty"`
}

type ICESessionDescriptor struct {
	NodeID      string            `json:"node_id"`
	SessionID   string            `json:"session_id"`
	Username    string            `json:"username,omitempty"`
	Password    string            `json:"password,omitempty"`
	Candidates  []string          `json:"candidates,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	IssuedAt    int64             `json:"issued_at"`
	ExpiresAt   int64             `json:"expires_at"`
	PublishedBy string            `json:"published_by,omitempty"`
}

type SessionToken struct {
	Token     string `json:"token"`
	NodeID    string `json:"node_id"`
	Scope     string `json:"scope,omitempty"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
	Revoked   bool   `json:"revoked,omitempty"`
}

type RouteDescriptor struct {
	RouteID          string            `json:"route_id"`
	SourceNode       string            `json:"source_node"`
	DestinationNode  string            `json:"destination_node"`
	Hops             []string          `json:"hops"`
	ReliabilityScore float64           `json:"reliability_score"`
	LatencyMs        int64             `json:"latency_ms,omitempty"`
	Epoch            int64             `json:"epoch"`
	ExpiresAt        int64             `json:"expires_at"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

type PathCandidate struct {
	RouteID       string   `json:"route_id,omitempty"`
	NextHop       string   `json:"next_hop"`
	Hops          []string `json:"hops,omitempty"`
	Transport     string   `json:"transport,omitempty"`
	IsRelay       bool     `json:"is_relay"`
	Score         float64  `json:"score"`
	LatencyMs     int64    `json:"latency_ms,omitempty"`
	MaxHop        int      `json:"max_hop,omitempty"`
	RouteEpoch    int64    `json:"route_epoch,omitempty"`
	Priority      int      `json:"priority,omitempty"`
	Role          string   `json:"role,omitempty"`
	ICECandidates []string `json:"ice_candidates,omitempty"`
}

type ForwardFrame struct {
	RouteID    string `json:"route_id"`
	RouteEpoch int64  `json:"route_epoch"`
	HopCount   int    `json:"hop_count"`
	TraceID    string `json:"trace_id"`
	Payload    []byte `json:"payload,omitempty"`
}

type RelayFallbackPolicy struct {
	Enabled           bool `json:"enabled"`
	MaxRelayHops      int  `json:"max_relay_hops"`
	FallbackTimeoutMs int  `json:"fallback_timeout_ms"`
}

type GridRegisterRequest struct {
	Node           NodeIdentity `json:"node"`
	LeaseTTLSecond int          `json:"lease_ttl_seconds,omitempty"`
}

type GridRegisterResponse struct {
	Success   bool         `json:"success"`
	Node      NodeIdentity `json:"node,omitempty"`
	Lease     *NodeLease   `json:"lease,omitempty"`
	Error     string       `json:"error,omitempty"`
	ServerUTC int64        `json:"server_utc"`
}

type GridHeartbeatRequest struct {
	NodeID          string `json:"node_id"`
	LeaseTTLSeconds int    `json:"lease_ttl_seconds,omitempty"`
}

type GridHeartbeatResponse struct {
	Success bool       `json:"success"`
	Lease   *NodeLease `json:"lease,omitempty"`
	Error   string     `json:"error,omitempty"`
}

type GridAnnounceRouteRequest struct {
	Route RouteDescriptor `json:"route"`
}

type GridAnnounceRouteResponse struct {
	Success bool             `json:"success"`
	Route   *RouteDescriptor `json:"route,omitempty"`
	Error   string           `json:"error,omitempty"`
}

type GridQueryRouteRequest struct {
	SourceNode      string `json:"source_node"`
	DestinationNode string `json:"destination_node"`
	Limit           int    `json:"limit,omitempty"`
}

type GridQueryRouteResponse struct {
	Success     bool                `json:"success"`
	Routes      []RouteDescriptor   `json:"routes,omitempty"`
	Candidates  []PathCandidate     `json:"candidates,omitempty"`
	Relay       RelayFallbackPolicy `json:"relay"`
	Error       string              `json:"error,omitempty"`
	ErrorCode   string              `json:"error_code,omitempty"`
	Unreachable bool                `json:"unreachable,omitempty"`
}

type GridIssueTokenRequest struct {
	NodeID     string `json:"node_id"`
	Scope      string `json:"scope,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
}

type GridIssueTokenResponse struct {
	Success bool          `json:"success"`
	Token   *SessionToken `json:"token,omitempty"`
	Error   string        `json:"error,omitempty"`
}

type GridRevokeTokenRequest struct {
	Token string `json:"token"`
}

type GridRevokeTokenResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type GridRefreshTokenRequest struct {
	NodeID     string `json:"node_id,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
}

type GridRefreshTokenResponse struct {
	Success bool          `json:"success"`
	Token   *SessionToken `json:"token,omitempty"`
	Error   string        `json:"error,omitempty"`
}

type GridICEPublishRequest struct {
	NodeID      string            `json:"node_id"`
	Candidates  []string          `json:"candidates,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	TTLSeconds  int               `json:"ttl_seconds,omitempty"`
	PublishedBy string            `json:"published_by,omitempty"`
}

type GridICEPublishResponse struct {
	Success bool             `json:"success"`
	Set     *ICECandidateSet `json:"set,omitempty"`
	Error   string           `json:"error,omitempty"`
}

type GridICEQueryRequest struct {
	NodeID string `json:"node_id"`
}

type GridICEQueryResponse struct {
	Success     bool             `json:"success"`
	Set         *ICECandidateSet `json:"set,omitempty"`
	Candidates  []string         `json:"candidates,omitempty"`
	Error       string           `json:"error,omitempty"`
	ErrorCode   string           `json:"error_code,omitempty"`
	Unreachable bool             `json:"unreachable,omitempty"`
}

type GridICEIssueSessionRequest struct {
	NodeID      string            `json:"node_id"`
	TTLSeconds  int               `json:"ttl_seconds,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	PublishedBy string            `json:"published_by,omitempty"`
}

type GridICEIssueSessionResponse struct {
	Success bool                  `json:"success"`
	Session *ICESessionDescriptor `json:"session,omitempty"`
	Error   string                `json:"error,omitempty"`
}

type GridICERefreshSessionRequest struct {
	NodeID      string            `json:"node_id"`
	TTLSeconds  int               `json:"ttl_seconds,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	PublishedBy string            `json:"published_by,omitempty"`
}

type GridICERefreshSessionResponse struct {
	Success bool                  `json:"success"`
	Session *ICESessionDescriptor `json:"session,omitempty"`
	Error   string                `json:"error,omitempty"`
}

type GridEvent struct {
	Seq            int64    `json:"seq"`
	Type           string   `json:"type"`
	NodeID         string   `json:"node_id,omitempty"`
	OfflineNodeID  string   `json:"offline_node_id,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	AffectedRoutes []string `json:"affected_routes,omitempty"`
	GeneratedAt    int64    `json:"generated_at"`
	ExpiresAt      int64    `json:"expires_at,omitempty"`
}

type GridEventsPullRequest struct {
	NodeID string `json:"node_id"`
	Cursor int64  `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

type GridEventsPullResponse struct {
	Success bool        `json:"success"`
	Cursor  int64       `json:"cursor,omitempty"`
	Events  []GridEvent `json:"events,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type GridTopologyRequest struct {
	Limit int `json:"limit,omitempty"`
}

type GridTopologyNode struct {
	NodeID       string            `json:"node_id"`
	TunnelName   string            `json:"tunnel_name,omitempty"`
	EndpointName string            `json:"endpoint_name,omitempty"`
	Online       bool              `json:"online"`
	LeaseExpires int64             `json:"lease_expires,omitempty"`
	UpdatedAt    int64             `json:"updated_at,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type GridTopologyEdge struct {
	RouteID          string  `json:"route_id"`
	From             string  `json:"from"`
	To               string  `json:"to"`
	ReliabilityScore float64 `json:"reliability_score,omitempty"`
	LatencyMs        int64   `json:"latency_ms,omitempty"`
	Epoch            int64   `json:"epoch,omitempty"`
	ExpiresAt        int64   `json:"expires_at,omitempty"`
}

type GridTopologyResponse struct {
	Success     bool               `json:"success"`
	GeneratedAt int64              `json:"generated_at"`
	Nodes       []GridTopologyNode `json:"nodes,omitempty"`
	Edges       []GridTopologyEdge `json:"edges,omitempty"`
	Error       string             `json:"error,omitempty"`
}
