package stats

// 注释：以下 3 个类型原本在 config.go，因 stats 包需要而迁出。
// Stage 2c/3 后 config 移入 config/ 包时可继续引用 stats.* 即可。

// TimeSeriesSnapshot represents a point-in-time statistics snapshot with dimensional data
type TimeSeriesSnapshot struct {
	Timestamp int64 `json:"timestamp"` // Unix timestamp in seconds

	// Global statistics
	Global GlobalStats `json:"global"`

	// Dimensional statistics (only store top active dimensions to limit storage)
	Rules   map[string]*DimensionStats `json:"rules,omitempty"`
	Users   map[string]*DimensionStats `json:"users,omitempty"`
	Servers map[string]*DimensionStats `json:"servers,omitempty"`
	Tunnels map[string]*DimensionStats `json:"tunnels,omitempty"`
	Proxies map[string]*DimensionStats `json:"proxies,omitempty"`
	IPs     map[string]*DimensionStats `json:"ips,omitempty"`
}

// GlobalStats contains system-wide statistics
type GlobalStats struct {
	TotalRequests     uint64  `json:"totalRequests"`
	ActiveConnections int64   `json:"activeConnections"`
	RequestsPerSecond float64 `json:"requestsPerSecond"`
	BytesReceived     uint64  `json:"bytesReceived"`
	BytesSent         uint64  `json:"bytesSent"`
}

// DimensionStats contains statistics for a specific dimension (rule, user, etc.)
type DimensionStats struct {
	Requests    uint64  `json:"requests"`
	BytesRecv   uint64  `json:"bytesRecv"`
	BytesSent   uint64  `json:"bytesSent"`
	Errors      uint64  `json:"errors"`
	AvgRespTime float64 `json:"avgRespTime"` // milliseconds

	// Protocol-specific statistics
	HTTPRequests    uint64 `json:"httpRequests"`
	HTTPSuccess     uint64 `json:"httpSuccess"`
	HTTPFailure     uint64 `json:"httpFailure"`
	RawTCPRequests  uint64 `json:"rawTcpRequests"`
	HTTPBytesSent   uint64 `json:"httpBytesSent"`
	HTTPBytesRecv   uint64 `json:"httpBytesRecv"`
	RawTCPBytesSent uint64 `json:"rawTcpBytesSent"`
	RawTCPBytesRecv uint64 `json:"rawTcpBytesRecv"`
	RawUDPBytesSent uint64 `json:"rawUdpBytesSent"`
	RawUDPBytesRecv uint64 `json:"rawUdpBytesRecv"`
}
