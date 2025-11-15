package main

import (
	"encoding/json"
	"net/http"
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

// Metrics holds all metrics for a specific entity (like a rule, user, etc.).
type Metrics struct {
	RequestCount uint64
	Errors       uint64
	BytesSent    NumericMetric
	BytesRecv    NumericMetric
	ResponseTime TimeMetric

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

	RuleStats   sync.Map // map[string]*Metrics
	UserStats   sync.Map // map[string]*Metrics
	ServerStats sync.Map // map[string]*Metrics
	TunnelStats sync.Map // map[string]*Metrics
	ProxyStats  sync.Map // map[string]*Metrics
}

// NewStatsCollector creates and initializes a new StatsCollector.
func NewStatsCollector() *StatsCollector {
	return &StatsCollector{
		StartTime: time.Now(),
	}
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
	ProxyKey     string
	BytesSent    uint64
	BytesRecv    uint64
	ResponseTime time.Duration
	IsError      bool
}

// Record processes a RecordData event and updates all relevant metrics.
func (sc *StatsCollector) Record(data RecordData) {
	sc.updateMetricsForDim(&sc.RuleStats, data.RuleKey, data)
	sc.updateMetricsForDim(&sc.UserStats, data.UserKey, data)
	sc.updateMetricsForDim(&sc.ServerStats, data.ServerKey, data)
	sc.updateMetricsForDim(&sc.TunnelStats, data.TunnelKey, data)
	sc.updateMetricsForDim(&sc.ProxyStats, data.ProxyKey, data)
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

	// Use mutex for min/max updates and time tracking
	metrics.mutex.Lock()
	defer metrics.mutex.Unlock()

	// Bytes Sent
	atomic.AddUint64(&metrics.BytesSent.Total, data.BytesSent)
	if data.BytesSent < metrics.BytesSent.Min {
		metrics.BytesSent.Min = data.BytesSent
	}
	if data.BytesSent > metrics.BytesSent.Max {
		metrics.BytesSent.Max = data.BytesSent
	}

	// Bytes Recv
	atomic.AddUint64(&metrics.BytesRecv.Total, data.BytesRecv)
	if data.BytesRecv < metrics.BytesRecv.Min {
		metrics.BytesRecv.Min = data.BytesRecv
	}
	if data.BytesRecv > metrics.BytesRecv.Max {
		metrics.BytesRecv.Max = data.BytesRecv
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

	// QPS timing
	now := time.Now()
	if metrics.firstRequestTime.IsZero() {
		metrics.firstRequestTime = now
	}
	metrics.lastRequestTime = now
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

type PublicMetrics struct {
	RequestCount uint64              `json:"requestCount"`
	Errors       uint64              `json:"errors"`
	BytesSent    PublicNumericMetric `json:"bytesSent"`
	BytesRecv    PublicNumericMetric `json:"bytesRecv"`
	ResponseTime PublicTimeMetric    `json:"responseTime"`
	QPS          float64             `json:"qps"`
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

		var avgBytesSent, avgBytesRecv, qps float64
		var avgResponseTimeMs float64
		if requestCount > 0 {
			avgBytesSent = float64(totalBytesSent) / float64(requestCount)
			avgBytesRecv = float64(totalBytesRecv) / float64(requestCount)
			avgResponseTimeMs = float64(totalResponseTime) / float64(requestCount) / 1e6
		}

		if !metrics.firstRequestTime.IsZero() && !metrics.lastRequestTime.IsZero() {
			duration := metrics.lastRequestTime.Sub(metrics.firstRequestTime).Seconds()
			if duration > 1 {
				qps = float64(requestCount) / duration
			} else {
				qps = float64(requestCount)
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
			QPS:          qps,
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