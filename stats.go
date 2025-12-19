package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// NumericMetric holds aggregated values for a numeric metric like response time or bytes sent.
type NumericMetric struct {
	Total uint64
	Min   uint64
	Max   uint64
}

// TimeMetric holds aggregated values for time-based metrics in nanoseconds.
type TimeMetric struct {
	Total int64
	Min   int64
	Max   int64
}

// QPSMetric holds aggregated values for QPS (Queries Per Second) metrics.
type QPSMetric struct {
	Total float64 // 总QPS值
	Avg   float64 // 平均QPS值
	Min   float64 // 最小QPS值
	Max   float64 // 最大QPS值
}

// Metrics holds all metrics for a specific entity (like a rule, user, etc.).
type Metrics struct {
	RequestCount uint64
	Errors       uint64
	Intercepted  uint64 // 拦截数

	// Protocol-specific counters
	HTTPRequests   uint64 // HTTP请求数
	HTTPSuccess    uint64 // HTTP成功 (状态码 100-399)
	HTTPFailure    uint64 // HTTP失败 (状态码 400-599)
	RawTCPRequests uint64 // RawTCP请求数

	// Traffic metrics (original, for backward compatibility)
	BytesSent NumericMetric
	BytesRecv NumericMetric

	// Protocol-separated traffic
	HTTPBytesSent   uint64 // HTTP发送流量
	HTTPBytesRecv   uint64 // HTTP接收流量
	RawTCPBytesSent uint64 // RawTCP发送流量
	RawTCPBytesRecv uint64 // RawTCP接收流量

	ResponseTime TimeMetric
	QPS          QPSMetric // QPS统计信息

	firstRequestTime time.Time
	lastRequestTime  time.Time
	mutex            sync.Mutex
}

// StatsCollector handles the collection and aggregation of statistics.
type StatsCollector struct {
	StartTime         time.Time
	TotalRequests     uint64
	ActiveConnections int64
	TotalBytesSent    uint64
	TotalBytesRecv    uint64

	RuleStats     sync.Map // map[string]*Metrics
	UserStats     sync.Map // map[string]*Metrics
	ServerStats   sync.Map // map[string]*Metrics
	TunnelStats   sync.Map // map[string]*Metrics
	ProxyStats    sync.Map // map[string]*Metrics
	EndpointStats sync.Map // map[string]*Metrics - per endpoint statistics

	// For auth-aware masking in stats
	Config *Config

	// Asynchronous processing
	recordChan chan RecordData // Channel for async stats processing
	wg         sync.WaitGroup  // Wait for all workers to finish
	closed     atomic.Bool     // Closed flag for graceful shutdown

	// IP statistics (24-hour rolling window)
	IPStats sync.Map // map[string]*[]time.Time
}

// NewStatsCollector creates and initializes a new StatsCollector.
func NewStatsCollector(config *Config) *StatsCollector {
	sc := &StatsCollector{
		StartTime:  time.Now(),
		Config:     config,
		recordChan: make(chan RecordData, 10000), // Buffer 10000 records
	}

	// Start worker goroutines for async stats processing
	workerCount := 4 // Parallel workers for better throughput
	for i := 0; i < workerCount; i++ {
		sc.wg.Add(1)
		go sc.statsWorker()
	}

	// Start periodic cleanup goroutine for IP stats
	sc.wg.Add(1)
	go sc.ipStatsCleanupWorker()

	return sc
}

// getMetrics retrieves or creates a Metrics object for a given key from a given map.
func (sc *StatsCollector) getMetrics(m *sync.Map, key string) *Metrics {
	if key == "" {
		return nil
	}
	metrics, _ := m.LoadOrStore(key, &Metrics{
		ResponseTime: TimeMetric{Min: -1},
		BytesSent:    NumericMetric{Min: ^uint64(0)},
		BytesRecv:    NumericMetric{Min: ^uint64(0)},
		QPS:          QPSMetric{Min: -1}, // QPS初始值设为-1表示未初始化
	})
	return metrics.(*Metrics)
}

// IncTotalRequests increments the total number of requests.
func (sc *StatsCollector) IncTotalRequests() {
	atomic.AddUint64(&sc.TotalRequests, 1)
}

// IncActiveConnections increments the number of active connections.
func (sc *StatsCollector) IncActiveConnections() {
	atomic.AddInt64(&sc.ActiveConnections, 1)
}

// DecActiveConnections decrements the number of active connections.
func (sc *StatsCollector) DecActiveConnections() {
	atomic.AddInt64(&sc.ActiveConnections, -1)
}

// AddBytesSent adds to the total bytes sent.
func (sc *StatsCollector) AddBytesSent(n uint64) {
	atomic.AddUint64(&sc.TotalBytesSent, n)
}

// AddBytesRecv adds to the total bytes received.
func (sc *StatsCollector) AddBytesRecv(n uint64) {
	atomic.AddUint64(&sc.TotalBytesRecv, n)
}

// RecordData holds all the data for a single request event to be recorded.
type RecordData struct {
	RuleKey      string
	UserKey      string
	ServerKey    string
	TunnelKey    string
	EndpointKey  string // Format: "tunnelName:endpointName"
	ProxyKey     string
	BytesSent    uint64
	BytesRecv    uint64
	ResponseTime time.Duration
	IsError      bool
	Intercepted  bool // 是否被拦截

	// Protocol-specific fields
	Protocol   string // "http" or "rawtcp"
	StatusCode int    // HTTP status code (only valid for HTTP)

	// Client information
	ClientIP string // Client IP address for IP statistics
}

// Record processes a RecordData event asynchronously.
// This method is non-blocking and will drop data if the channel is full
// to avoid impacting request performance.
func (sc *StatsCollector) Record(data RecordData) {
	// If collector is closed, ignore
	if sc.closed.Load() {
		return
	}

	// Non-blocking send to avoid blocking request processing
	select {
	case sc.recordChan <- data:
		// Successfully queued for async processing
	default:
		// Channel is full, drop the data to avoid blocking
		// This is acceptable for statistics - we prioritize performance
		DebugLog("[STATS] Record channel full, dropping stats data")
	}
}

// statsWorker processes stats updates in the background.
func (sc *StatsCollector) statsWorker() {
	defer sc.wg.Done()

	for data := range sc.recordChan {
		sc.updateMetricsForDim(&sc.RuleStats, data.RuleKey, data)
		sc.updateMetricsForDim(&sc.UserStats, data.UserKey, data)
		sc.updateMetricsForDim(&sc.ServerStats, data.ServerKey, data)
		sc.updateMetricsForDim(&sc.TunnelStats, data.TunnelKey, data)
		sc.updateMetricsForDim(&sc.EndpointStats, data.EndpointKey, data)
		sc.updateMetricsForDim(&sc.ProxyStats, data.ProxyKey, data)

		// Record IP statistics with traffic data
		if data.ClientIP != "" {
			sc.recordIPRequest(data.ClientIP, data.Protocol, data.BytesSent, data.BytesRecv)
		}
	}
}

// Close gracefully shuts down the stats collector.
// It closes the channel and waits for all workers to finish processing.
func (sc *StatsCollector) Close() {
	// Set closed flag using atomic swap
	if sc.closed.Swap(true) {
		return // Already closed
	}

	// Close the channel to signal workers to exit
	close(sc.recordChan)

	// Wait for all workers to finish processing remaining data
	sc.wg.Wait()
}

// IPStatsData holds per-IP statistics including timestamps and traffic by protocol
type IPStatsData struct {
	// Timestamps      []time.Time // Removed to save memory
	RequestCounts   map[int64]uint32 // Key: Unix timestamp / 60 (minute bucket), Value: Request count
	FirstSeen       time.Time
	LastSeen        time.Time
	TotalRequests   uint64 // Total accumulated requests
	HTTPBytesSent   uint64
	HTTPBytesRecv   uint64
	RawTCPBytesSent uint64
	RawTCPBytesRecv uint64
	RawUDPBytesSent uint64
	RawUDPBytesRecv uint64
	mutex           sync.Mutex // Protects RequestCounts map
}

// recordIPRequest records a request from a specific IP address with traffic data.
// It increments the count in the current minute bucket.
func (sc *StatsCollector) recordIPRequest(ip string, protocol string, bytesSent, bytesRecv uint64) {
	if ip == "" {
		return
	}

	now := time.Now()
	minuteBucket := now.Unix() / 60

	// Load or create the stats data for this IP
	value, ok := sc.IPStats.Load(ip)
	if !ok {
		value, _ = sc.IPStats.LoadOrStore(ip, &IPStatsData{
			RequestCounts: make(map[int64]uint32),
			FirstSeen:     now,
			LastSeen:      now,
		})
	}
	data := value.(*IPStatsData)

	// Increment total requests
	atomic.AddUint64(&data.TotalRequests, 1)

	// Update minute bucket with mutex protection
	data.mutex.Lock()
	data.RequestCounts[minuteBucket]++
	data.LastSeen = now
	if data.FirstSeen.IsZero() {
		data.FirstSeen = now
	}
	data.mutex.Unlock()

	// Update traffic stats by protocol
	if protocol == "http" {
		atomic.AddUint64(&data.HTTPBytesSent, bytesSent)
		atomic.AddUint64(&data.HTTPBytesRecv, bytesRecv)
	} else if protocol == "rawtcp" {
		atomic.AddUint64(&data.RawTCPBytesSent, bytesSent)
		atomic.AddUint64(&data.RawTCPBytesRecv, bytesRecv)
	} else if protocol == "rawudp" {
		atomic.AddUint64(&data.RawUDPBytesSent, bytesSent)
		atomic.AddUint64(&data.RawUDPBytesRecv, bytesRecv)
	}
}

// ipStatsCleanupWorker periodically cleans up old timestamps from IP statistics.
func (sc *StatsCollector) ipStatsCleanupWorker() {
	defer sc.wg.Done()

	ticker := time.NewTicker(5 * time.Minute) // Cleanup every 5 minutes
	defer ticker.Stop()

	for {
		// Block until ticker fires or we need to shut down
		if sc.closed.Load() {
			return
		}

		select {
		case <-ticker.C:
			sc.cleanupOldIPTimestamps()
		}
	}
}

// cleanupOldIPTimestamps removes buckets older than 24 hours from all IP stats.
func (sc *StatsCollector) cleanupOldIPTimestamps() {
	cutoffBucket := time.Now().Add(-24*time.Hour).Unix() / 60

	sc.IPStats.Range(func(key, value interface{}) bool {
		data := value.(*IPStatsData)

		data.mutex.Lock()
		defer data.mutex.Unlock()

		// Filter out old buckets
		for bucket := range data.RequestCounts {
			if bucket < cutoffBucket {
				delete(data.RequestCounts, bucket)
			}
		}

		// If no recent activity and older than 24h, we could potentially remove the IP entry entirely
		// But for now, just cleaning buckets is enough to save memory

		return true
	})
}

// GetTopIPsAsDimensionStats retrieves the top N active IPs as DimensionStats for storage.
func (sc *StatsCollector) GetTopIPsAsDimensionStats(limit int) map[string]*DimensionStats {
	type ipItem struct {
		IP   string
		Reqs uint64
		Data *IPStatsData
	}

	items := make([]ipItem, 0)
	cutoffBucket := time.Now().Add(-24*time.Hour).Unix() / 60

	sc.IPStats.Range(func(key, value interface{}) bool {
		ip := key.(string)
		data := value.(*IPStatsData)

		data.mutex.Lock()
		var recentReqs uint64
		for bucket, count := range data.RequestCounts {
			if bucket >= cutoffBucket {
				recentReqs += uint64(count)
			}
		}
		data.mutex.Unlock()

		if recentReqs > 0 {
			items = append(items, ipItem{IP: ip, Reqs: recentReqs, Data: data})
		}
		return true
	})

	// Sort by recent request count
	sort.Slice(items, func(i, j int) bool {
		return items[i].Reqs > items[j].Reqs
	})

	// Take top N
	if len(items) > limit {
		items = items[:limit]
	}

	result := make(map[string]*DimensionStats)
	for _, item := range items {
		d := item.Data
		result[item.IP] = &DimensionStats{
			Requests:        item.Reqs, // Use calculated recent requests
			HTTPBytesSent:   atomic.LoadUint64(&d.HTTPBytesSent),
			HTTPBytesRecv:   atomic.LoadUint64(&d.HTTPBytesRecv),
			RawTCPBytesSent: atomic.LoadUint64(&d.RawTCPBytesSent),
			RawTCPBytesRecv: atomic.LoadUint64(&d.RawTCPBytesRecv),
			// Aggregate totals
			BytesSent: atomic.LoadUint64(&d.HTTPBytesSent) + atomic.LoadUint64(&d.RawTCPBytesSent),
			BytesRecv: atomic.LoadUint64(&d.HTTPBytesRecv) + atomic.LoadUint64(&d.RawTCPBytesRecv),
		}
	}
	return result
}

// IPRequestStats represents statistics for a single IP address.
type IPRequestStats struct {
	IP              string    `json:"ip"`
	Requests        int       `json:"requests"`
	HTTPBytesSent   uint64    `json:"httpBytesSent"`
	HTTPBytesRecv   uint64    `json:"httpBytesRecv"`
	RawTCPBytesSent uint64    `json:"rawTcpBytesSent"`
	RawTCPBytesRecv uint64    `json:"rawTcpBytesRecv"`
	RawUDPBytesSent uint64    `json:"rawUdpBytesSent"`
	RawUDPBytesRecv uint64    `json:"rawUdpBytesRecv"`
	FirstSeen       time.Time `json:"firstSeen"`
	LastSeen        time.Time `json:"lastSeen"`
}

// GetIPStats returns IP request statistics for the past 24 hours, sorted by request count (descending).
func (sc *StatsCollector) GetIPStats() []IPRequestStats {
	cutoffBucket := time.Now().Add(-24*time.Hour).Unix() / 60
	stats := make([]IPRequestStats, 0)

	sc.IPStats.Range(func(key, value interface{}) bool {
		ip := key.(string)
		ipData := value.(*IPStatsData)

		ipData.mutex.Lock()
		var recentReqs int
		for bucket, count := range ipData.RequestCounts {
			if bucket >= cutoffBucket {
				recentReqs += int(count)
			}
		}
		firstSeen := ipData.FirstSeen
		lastSeen := ipData.LastSeen
		ipData.mutex.Unlock()

		// Only include IPs with requests in the past 24 hours
		if recentReqs > 0 {
			stats = append(stats, IPRequestStats{
				IP:              ip,
				Requests:        recentReqs,
				HTTPBytesSent:   atomic.LoadUint64(&ipData.HTTPBytesSent),
				HTTPBytesRecv:   atomic.LoadUint64(&ipData.HTTPBytesRecv),
				RawTCPBytesSent: atomic.LoadUint64(&ipData.RawTCPBytesSent),
				RawTCPBytesRecv: atomic.LoadUint64(&ipData.RawTCPBytesRecv),
				RawUDPBytesSent: atomic.LoadUint64(&ipData.RawUDPBytesSent),
				RawUDPBytesRecv: atomic.LoadUint64(&ipData.RawUDPBytesRecv),
				FirstSeen:       firstSeen,
				LastSeen:        lastSeen,
			})
		}

		return true
	})

	// Sort by request count (descending)
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Requests > stats[j].Requests
	})

	return stats
}

// updateMetricsForDim updates the metrics for a specific dimension (rule, user, etc.).
func (sc *StatsCollector) updateMetricsForDim(m *sync.Map, key string, data RecordData) {
	if key == "" {
		return
	}
	metrics := sc.getMetrics(m, key)
	if metrics == nil {
		return
	}

	atomic.AddUint64(&metrics.RequestCount, 1)
	if data.IsError {
		atomic.AddUint64(&metrics.Errors, 1)
	}
	if data.Intercepted {
		atomic.AddUint64(&metrics.Intercepted, 1)
	}

	// Protocol-specific counting and traffic tracking
	if data.Protocol == "http" {
		atomic.AddUint64(&metrics.HTTPRequests, 1)
		atomic.AddUint64(&metrics.HTTPBytesSent, data.BytesSent)
		atomic.AddUint64(&metrics.HTTPBytesRecv, data.BytesRecv)

		// Status code classification
		if data.StatusCode >= 100 && data.StatusCode < 400 {
			atomic.AddUint64(&metrics.HTTPSuccess, 1)
		} else if data.StatusCode >= 400 && data.StatusCode < 600 {
			atomic.AddUint64(&metrics.HTTPFailure, 1)
		}
	} else if data.Protocol == "rawtcp" {
		atomic.AddUint64(&metrics.RawTCPRequests, 1)
		atomic.AddUint64(&metrics.RawTCPBytesSent, data.BytesSent)
		atomic.AddUint64(&metrics.RawTCPBytesRecv, data.BytesRecv)
	}

	// Use mutex for min/max updates and time tracking
	metrics.mutex.Lock()
	defer metrics.mutex.Unlock()

	// Bytes Sent
	atomic.AddUint64(&metrics.BytesSent.Total, data.BytesSent)
	// 修复：第一次记录时正确初始化min/max值
	if metrics.BytesSent.Min == ^uint64(0) {
		metrics.BytesSent.Min = data.BytesSent
		metrics.BytesSent.Max = data.BytesSent
	} else {
		if data.BytesSent < metrics.BytesSent.Min {
			metrics.BytesSent.Min = data.BytesSent
		}
		if data.BytesSent > metrics.BytesSent.Max {
			metrics.BytesSent.Max = data.BytesSent
		}
	}

	// Bytes Recv
	atomic.AddUint64(&metrics.BytesRecv.Total, data.BytesRecv)
	// 修复：第一次记录时正确初始化min/max值
	if metrics.BytesRecv.Min == ^uint64(0) {
		metrics.BytesRecv.Min = data.BytesRecv
		metrics.BytesRecv.Max = data.BytesRecv
	} else {
		if data.BytesRecv < metrics.BytesRecv.Min {
			metrics.BytesRecv.Min = data.BytesRecv
		}
		if data.BytesRecv > metrics.BytesRecv.Max {
			metrics.BytesRecv.Max = data.BytesRecv
		}
	}

	// Response Time
	responseTimeNs := data.ResponseTime.Nanoseconds()
	atomic.AddInt64(&metrics.ResponseTime.Total, responseTimeNs)
	if metrics.ResponseTime.Min == -1 || responseTimeNs < metrics.ResponseTime.Min {
		metrics.ResponseTime.Min = responseTimeNs
	}
	if responseTimeNs > metrics.ResponseTime.Max {
		metrics.ResponseTime.Max = responseTimeNs
	}

	// QPS timing and statistics
	now := time.Now()
	if metrics.firstRequestTime.IsZero() {
		metrics.firstRequestTime = now
	}
	metrics.lastRequestTime = now

	// 获取当前请求计数
	currentRequestCount := atomic.LoadUint64(&metrics.RequestCount)

	// 计算当前QPS值
	var currentQPS float64
	if !metrics.firstRequestTime.IsZero() && !metrics.lastRequestTime.IsZero() {
		duration := metrics.lastRequestTime.Sub(metrics.firstRequestTime).Seconds()
		if duration > 1 {
			currentQPS = float64(currentRequestCount) / duration
		} else {
			currentQPS = float64(currentRequestCount)
		}
	}

	// 更新QPS统计信息
	metrics.QPS.Total = currentQPS
	if metrics.QPS.Min == -1 {
		// 第一次初始化，所有值都设为当前QPS
		metrics.QPS.Min = currentQPS
		metrics.QPS.Max = currentQPS
		metrics.QPS.Avg = currentQPS
	} else {
		// 更新min/max值
		if currentQPS < metrics.QPS.Min {
			metrics.QPS.Min = currentQPS
		}
		if currentQPS > metrics.QPS.Max {
			metrics.QPS.Max = currentQPS
		}
		// 计算QPS平均值（基于总请求数和时间窗口）
		if currentRequestCount > 0 {
			metrics.QPS.Avg = currentQPS // 在当前时间窗口内，avg就是当前QPS值
		}
	}
}

// Public facing structs for JSON marshaling
type PublicNumericMetric struct {
	Total uint64  `json:"total"`
	Avg   float64 `json:"avg"`
	Min   uint64  `json:"min"`
	Max   uint64  `json:"max"`
}

type PublicTimeMetric struct {
	TotalMs float64 `json:"totalMs"`
	AvgMs   float64 `json:"avgMs"`
	MinMs   int64   `json:"minMs"`
	MaxMs   int64   `json:"maxMs"`
}

type PublicQPSMetric struct {
	Avg float64 `json:"avg"`
	Min float64 `json:"min"`
	Max float64 `json:"max"`
}

type PublicMetrics struct {
	RequestCount uint64 `json:"requestCount"`
	Errors       uint64 `json:"errors"`
	Intercepted  uint64 `json:"intercepted"`

	// Protocol-specific counters
	HTTPRequests   uint64 `json:"httpRequests"`
	HTTPSuccess    uint64 `json:"httpSuccess"`
	HTTPFailure    uint64 `json:"httpFailure"`
	RawTCPRequests uint64 `json:"rawTcpRequests"`

	// Total traffic (backward compatibility)
	BytesSent PublicNumericMetric `json:"bytesSent"`
	BytesRecv PublicNumericMetric `json:"bytesRecv"`

	// Protocol-separated traffic
	HTTPBytesSent   uint64 `json:"httpBytesSent"`
	HTTPBytesRecv   uint64 `json:"httpBytesRecv"`
	RawTCPBytesSent uint64 `json:"rawTcpBytesSent"`
	RawTCPBytesRecv uint64 `json:"rawTcpBytesRecv"`
	RawUDPBytesSent uint64 `json:"rawUdpBytesSent"`
	RawUDPBytesRecv uint64 `json:"rawUdpBytesRecv"`

	ResponseTime PublicTimeMetric `json:"responseTime"`
	QPS          PublicQPSMetric  `json:"qps"`
}

type PublicStats struct {
	TotalRequests     uint64                    `json:"totalRequests"`
	ActiveConnections int64                     `json:"activeConnections"`
	TotalBytesSent    uint64                    `json:"totalBytesSent"`
	TotalBytesRecv    uint64                    `json:"totalBytesRecv"`
	Uptime            string                    `json:"uptime"`
	Rules             map[string]*PublicMetrics `json:"rules"`
	Users             map[string]*PublicMetrics `json:"users"`
	Servers           map[string]*PublicMetrics `json:"servers"`
	Tunnels           map[string]*PublicMetrics `json:"tunnels"`
	Proxies           map[string]*PublicMetrics `json:"proxies"`
}

// ServeHTTP provides an HTTP endpoint to expose stats as JSON.
func (sc *StatsCollector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 未通过认证则进行键名脱敏（支持会话 Cookie 与 Bearer token）
	if !isAdminRequest(r, sc.Config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	stats := PublicStats{
		TotalRequests:     atomic.LoadUint64(&sc.TotalRequests),
		ActiveConnections: atomic.LoadInt64(&sc.ActiveConnections),
		TotalBytesSent:    atomic.LoadUint64(&sc.TotalBytesSent),
		TotalBytesRecv:    atomic.LoadUint64(&sc.TotalBytesRecv),
		Uptime:            time.Since(sc.StartTime).String(),
		Rules:             sc.buildPublicMetricsMap(&sc.RuleStats),
		Users:             sc.buildPublicMetricsMap(&sc.UserStats),
		Servers:           sc.buildPublicMetricsMap(&sc.ServerStats),
		Tunnels:           sc.buildPublicMetricsMap(&sc.TunnelStats),
		Proxies:           sc.buildPublicMetricsMap(&sc.ProxyStats),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// GetMetricsForKey retrieves and converts metrics for a specific key from a sync.Map to PublicMetrics.
func (sc *StatsCollector) GetMetricsForKey(m *sync.Map, key string) *PublicMetrics {
	value, ok := m.Load(key)
	if !ok {
		return nil
	}

	metrics := value.(*Metrics)
	metrics.mutex.Lock()
	defer metrics.mutex.Unlock()

	requestCount := atomic.LoadUint64(&metrics.RequestCount)
	totalBytesSent := atomic.LoadUint64(&metrics.BytesSent.Total)
	totalBytesRecv := atomic.LoadUint64(&metrics.BytesRecv.Total)
	totalResponseTime := atomic.LoadInt64(&metrics.ResponseTime.Total)

	var avgBytesSent, avgBytesRecv float64
	var avgResponseTimeMs float64
	if requestCount > 0 {
		avgBytesSent = float64(totalBytesSent) / float64(requestCount)
		avgBytesRecv = float64(totalBytesRecv) / float64(requestCount)
		avgResponseTimeMs = float64(totalResponseTime) / float64(requestCount) / 1e6
	}

	// 构建QPS统计信息
	var qpsMetric PublicQPSMetric
	if !metrics.firstRequestTime.IsZero() && !metrics.lastRequestTime.IsZero() {
		duration := metrics.lastRequestTime.Sub(metrics.firstRequestTime).Seconds()
		var currentQPS float64
		if duration > 1 {
			currentQPS = float64(requestCount) / duration
		} else {
			currentQPS = float64(requestCount)
		}

		qpsMetric = PublicQPSMetric{
			Avg: metrics.QPS.Avg,
			Min: metrics.QPS.Min,
			Max: metrics.QPS.Max,
		}

		if metrics.QPS.Min == -1 {
			qpsMetric.Min = currentQPS
			qpsMetric.Avg = currentQPS
			qpsMetric.Max = currentQPS
		}
	} else {
		qpsMetric = PublicQPSMetric{
			Avg: 0,
			Min: 0,
			Max: 0,
		}
	}

	minBytesSent := metrics.BytesSent.Min
	if minBytesSent == ^uint64(0) {
		minBytesSent = 0
	}
	minBytesRecv := metrics.BytesRecv.Min
	if minBytesRecv == ^uint64(0) {
		minBytesRecv = 0
	}
	minResponseTimeMs := metrics.ResponseTime.Min
	if minResponseTimeMs == -1 {
		minResponseTimeMs = 0
	} else {
		minResponseTimeMs /= 1e6
	}

	return &PublicMetrics{
		RequestCount: requestCount,
		Errors:       atomic.LoadUint64(&metrics.Errors),
		Intercepted:  atomic.LoadUint64(&metrics.Intercepted),

		// Protocol-specific counters
		HTTPRequests:   atomic.LoadUint64(&metrics.HTTPRequests),
		HTTPSuccess:    atomic.LoadUint64(&metrics.HTTPSuccess),
		HTTPFailure:    atomic.LoadUint64(&metrics.HTTPFailure),
		RawTCPRequests: atomic.LoadUint64(&metrics.RawTCPRequests),

		QPS: qpsMetric,
		BytesSent: PublicNumericMetric{
			Total: totalBytesSent,
			Avg:   avgBytesSent,
			Min:   minBytesSent,
			Max:   metrics.BytesSent.Max,
		},
		BytesRecv: PublicNumericMetric{
			Total: totalBytesRecv,
			Avg:   avgBytesRecv,
			Min:   minBytesRecv,
			Max:   metrics.BytesRecv.Max,
		},

		// Protocol-separated traffic
		HTTPBytesSent:   atomic.LoadUint64(&metrics.HTTPBytesSent),
		HTTPBytesRecv:   atomic.LoadUint64(&metrics.HTTPBytesRecv),
		RawTCPBytesSent: atomic.LoadUint64(&metrics.RawTCPBytesSent),
		RawTCPBytesRecv: atomic.LoadUint64(&metrics.RawTCPBytesRecv),

		ResponseTime: PublicTimeMetric{
			TotalMs: float64(totalResponseTime) / 1e6,
			AvgMs:   avgResponseTimeMs,
			MinMs:   minResponseTimeMs,
			MaxMs:   metrics.ResponseTime.Max / 1e6,
		},
	}
}

// buildPublicMetricsMap converts a sync.Map of internal Metrics to a map of PublicMetrics.
func (sc *StatsCollector) buildPublicMetricsMap(m *sync.Map) map[string]*PublicMetrics {
	publicMap := make(map[string]*PublicMetrics)
	m.Range(func(key, value interface{}) bool {
		k := key.(string)

		metrics := value.(*Metrics)
		metrics.mutex.Lock()
		defer metrics.mutex.Unlock()

		requestCount := atomic.LoadUint64(&metrics.RequestCount)
		totalBytesSent := atomic.LoadUint64(&metrics.BytesSent.Total)
		totalBytesRecv := atomic.LoadUint64(&metrics.BytesRecv.Total)
		totalResponseTime := atomic.LoadInt64(&metrics.ResponseTime.Total)

		var avgBytesSent, avgBytesRecv float64
		var avgResponseTimeMs float64
		if requestCount > 0 {
			avgBytesSent = float64(totalBytesSent) / float64(requestCount)
			avgBytesRecv = float64(totalBytesRecv) / float64(requestCount)
			avgResponseTimeMs = float64(totalResponseTime) / float64(requestCount) / 1e6
		}

		// 构建QPS统计信息（只保留avg、min、max）
		var qpsMetric PublicQPSMetric
		if !metrics.firstRequestTime.IsZero() && !metrics.lastRequestTime.IsZero() {
			duration := metrics.lastRequestTime.Sub(metrics.firstRequestTime).Seconds()
			var currentQPS float64
			if duration > 1 {
				currentQPS = float64(requestCount) / duration
			} else {
				currentQPS = float64(requestCount)
			}

			qpsMetric = PublicQPSMetric{
				Avg: metrics.QPS.Avg, // 使用内部记录的平均值
				Min: metrics.QPS.Min, // 使用内部记录的最小值
				Max: metrics.QPS.Max, // 使用内部记录的最大值
			}

			// 如果内部min值还是-1（未初始化），则设置为当前值
			if metrics.QPS.Min == -1 {
				qpsMetric.Min = currentQPS
				qpsMetric.Avg = currentQPS
				qpsMetric.Max = currentQPS
			}
		} else {
			qpsMetric = PublicQPSMetric{
				Avg: 0,
				Min: 0,
				Max: 0,
			}
		}

		minBytesSent := metrics.BytesSent.Min
		if minBytesSent == ^uint64(0) {
			minBytesSent = 0
		}
		minBytesRecv := metrics.BytesRecv.Min
		if minBytesRecv == ^uint64(0) {
			minBytesRecv = 0
		}
		minResponseTimeMs := metrics.ResponseTime.Min
		if minResponseTimeMs == -1 {
			minResponseTimeMs = 0
		} else {
			minResponseTimeMs /= 1e6
		}

		publicMap[k] = &PublicMetrics{
			RequestCount: requestCount,
			Errors:       atomic.LoadUint64(&metrics.Errors),
			Intercepted:  atomic.LoadUint64(&metrics.Intercepted),

			// Protocol-specific counters
			HTTPRequests:   atomic.LoadUint64(&metrics.HTTPRequests),
			HTTPSuccess:    atomic.LoadUint64(&metrics.HTTPSuccess),
			HTTPFailure:    atomic.LoadUint64(&metrics.HTTPFailure),
			RawTCPRequests: atomic.LoadUint64(&metrics.RawTCPRequests),

			QPS: qpsMetric,
			BytesSent: PublicNumericMetric{
				Total: totalBytesSent,
				Avg:   avgBytesSent,
				Min:   minBytesSent,
				Max:   metrics.BytesSent.Max,
			},
			BytesRecv: PublicNumericMetric{
				Total: totalBytesRecv,
				Avg:   avgBytesRecv,
				Min:   minBytesRecv,
				Max:   metrics.BytesRecv.Max,
			},

			// Protocol-separated traffic
			HTTPBytesSent:   atomic.LoadUint64(&metrics.HTTPBytesSent),
			HTTPBytesRecv:   atomic.LoadUint64(&metrics.HTTPBytesRecv),
			RawTCPBytesSent: atomic.LoadUint64(&metrics.RawTCPBytesSent),
			RawTCPBytesRecv: atomic.LoadUint64(&metrics.RawTCPBytesRecv),

			ResponseTime: PublicTimeMetric{
				TotalMs: float64(totalResponseTime) / 1e6,
				AvgMs:   avgResponseTimeMs,
				MinMs:   minResponseTimeMs,
				MaxMs:   metrics.ResponseTime.Max / 1e6,
			},
		}
		return true
	})
	return publicMap
}
