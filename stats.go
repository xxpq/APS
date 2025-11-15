package main

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// StatsCollector collects and exposes metrics about the proxy's activity.
type StatsCollector struct {
	TotalRequests     uint64
	ActiveConnections int64
	TotalBytesSent    uint64
	TotalBytesRecv    uint64
	StartTime         time.Time
	RuleStats         sync.Map // map[string]*RuleStats
}

// RuleStats holds metrics for a specific mapping rule.
type RuleStats struct {
	MatchCount        uint64
	BytesSent         uint64
	BytesRecv         uint64
	Errors            uint64
	TotalResponseTime int64 // in nanoseconds
	MinResponseTime   int64 // in nanoseconds
	MaxResponseTime   int64 // in nanoseconds
	TotalRequestSize  uint64
	MinRequestSize    uint64
	MaxRequestSize    uint64
	firstRequestTime  time.Time
	lastRequestTime   time.Time
	mutex             sync.Mutex
}

func NewStatsCollector() *StatsCollector {
	return &StatsCollector{
		StartTime: time.Now(),
	}
}

func (sc *StatsCollector) IncTotalRequests() {
	atomic.AddUint64(&sc.TotalRequests, 1)
}

func (sc *StatsCollector) IncActiveConnections() {
	atomic.AddInt64(&sc.ActiveConnections, 1)
}

func (sc *StatsCollector) DecActiveConnections() {
	atomic.AddInt64(&sc.ActiveConnections, -1)
}

func (sc *StatsCollector) AddBytesSent(n uint64) {
	atomic.AddUint64(&sc.TotalBytesSent, n)
}

func (sc *StatsCollector) AddBytesRecv(n uint64) {
	atomic.AddUint64(&sc.TotalBytesRecv, n)
}

func (sc *StatsCollector) getRuleStats(ruleKey string) *RuleStats {
	stats, _ := sc.RuleStats.LoadOrStore(ruleKey, &RuleStats{
		MinResponseTime: -1,
		MinRequestSize:  ^uint64(0),
	})
	return stats.(*RuleStats)
}

func (sc *StatsCollector) IncRuleMatchCount(ruleKey string) {
	stats := sc.getRuleStats(ruleKey)
	atomic.AddUint64(&stats.MatchCount, 1)
}

func (sc *StatsCollector) AddRuleBytesSent(ruleKey string, n uint64) {
	stats := sc.getRuleStats(ruleKey)
	atomic.AddUint64(&stats.BytesSent, n)
}

func (sc *StatsCollector) AddRuleBytesRecv(ruleKey string, n uint64) {
	stats := sc.getRuleStats(ruleKey)
	atomic.AddUint64(&stats.BytesRecv, n)
}

func (sc *StatsCollector) IncRuleErrors(ruleKey string) {
	stats := sc.getRuleStats(ruleKey)
	atomic.AddUint64(&stats.Errors, 1)
}

func (sc *StatsCollector) AddRuleResponseTime(ruleKey string, d time.Duration) {
	stats := sc.getRuleStats(ruleKey)
	ns := d.Nanoseconds()
	atomic.AddInt64(&stats.TotalResponseTime, ns)

	stats.mutex.Lock()
	defer stats.mutex.Unlock()

	if stats.MinResponseTime == -1 || ns < stats.MinResponseTime {
		stats.MinResponseTime = ns
	}
	if ns > stats.MaxResponseTime {
		stats.MaxResponseTime = ns
	}
}

func (sc *StatsCollector) AddRuleRequestSize(ruleKey string, size uint64) {
	stats := sc.getRuleStats(ruleKey)
	atomic.AddUint64(&stats.TotalRequestSize, size)

	stats.mutex.Lock()
	defer stats.mutex.Unlock()

	if size < stats.MinRequestSize {
		stats.MinRequestSize = size
	}
	if size > stats.MaxRequestSize {
		stats.MaxRequestSize = size
	}
	now := time.Now()
	if stats.firstRequestTime.IsZero() {
		stats.firstRequestTime = now
	}
	stats.lastRequestTime = now
}

// StatsReadWriteCloser is a wrapper around an io.ReadWriteCloser that tracks bytes read and written.
type StatsReadWriteCloser struct {
	conn  io.ReadWriteCloser
	stats *StatsCollector
}

func NewStatsReadWriteCloser(conn io.ReadWriteCloser, stats *StatsCollector) *StatsReadWriteCloser {
	return &StatsReadWriteCloser{conn: conn, stats: stats}
}

func (s *StatsReadWriteCloser) Read(p []byte) (n int, err error) {
	n, err = s.conn.Read(p)
	// Bytes read from a connection are considered "sent" from the proxy's perspective (e.g. sent to client)
	s.stats.AddBytesSent(uint64(n))
	return
}

func (s *StatsReadWriteCloser) Write(p []byte) (n int, err error) {
	n, err = s.conn.Write(p)
	// Bytes written to a connection are considered "received" by the proxy (e.g. received from client)
	s.stats.AddBytesRecv(uint64(n))
	return
}

func (s *StatsReadWriteCloser) Close() error {
	return s.conn.Close()
}

// ServeHTTP provides an HTTP endpoint to expose stats as JSON.
func (sc *StatsCollector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	type PublicRuleStats struct {
		MatchCount        uint64  `json:"matchCount"`
		BytesSent         uint64  `json:"bytesSent"`
		BytesRecv         uint64  `json:"bytesRecv"`
		Errors            uint64  `json:"errors"`
		AvgResponseTimeMs float64 `json:"avgResponseTimeMs"`
		MinResponseTimeMs int64   `json:"minResponseTimeMs"`
		MaxResponseTimeMs int64   `json:"maxResponseTimeMs"`
		AvgRequestSize    float64 `json:"avgRequestSize"`
		MinRequestSize    uint64  `json:"minRequestSize"`
		MaxRequestSize    uint64  `json:"maxRequestSize"`
		QPS               float64 `json:"qps"`
	}

	type PublicStats struct {
		TotalRequests     uint64                      `json:"totalRequests"`
		ActiveConnections int64                       `json:"activeConnections"`
		TotalBytesSent    uint64                      `json:"totalBytesSent"`
		TotalBytesRecv    uint64                      `json:"totalBytesRecv"`
		Uptime            string                      `json:"uptime"`
		RuleStats         map[string]*PublicRuleStats `json:"ruleStats"`
	}

	ruleStatsMap := make(map[string]*PublicRuleStats)
	sc.RuleStats.Range(func(key, value interface{}) bool {
		ruleKey := key.(string)
		stats := value.(*RuleStats)
		stats.mutex.Lock()
		defer stats.mutex.Unlock()

		matchCount := atomic.LoadUint64(&stats.MatchCount)
		totalResponseTime := atomic.LoadInt64(&stats.TotalResponseTime)
		totalRequestSize := atomic.LoadUint64(&stats.TotalRequestSize)

		var avgResponseTimeMs float64
		if matchCount > 0 {
			avgResponseTimeMs = float64(totalResponseTime) / float64(matchCount) / 1e6
		}

		var avgRequestSize float64
		if matchCount > 0 {
			avgRequestSize = float64(totalRequestSize) / float64(matchCount)
		}

		minResponseTimeMs := stats.MinResponseTime / 1e6
		if stats.MinResponseTime == -1 {
			minResponseTimeMs = 0
		}

		minRequestSize := stats.MinRequestSize
		if minRequestSize == ^uint64(0) {
			minRequestSize = 0
		}

		var qps float64
		if !stats.firstRequestTime.IsZero() && !stats.lastRequestTime.IsZero() {
			duration := stats.lastRequestTime.Sub(stats.firstRequestTime).Seconds()
			if duration > 1 {
				qps = float64(matchCount) / duration
			} else {
				qps = float64(matchCount)
			}
		}

		ruleStatsMap[ruleKey] = &PublicRuleStats{
			MatchCount:        matchCount,
			BytesSent:         atomic.LoadUint64(&stats.BytesSent),
			BytesRecv:         atomic.LoadUint64(&stats.BytesRecv),
			Errors:            atomic.LoadUint64(&stats.Errors),
			AvgResponseTimeMs: avgResponseTimeMs,
			MinResponseTimeMs: minResponseTimeMs,
			MaxResponseTimeMs: stats.MaxResponseTime / 1e6,
			AvgRequestSize:    avgRequestSize,
			MinRequestSize:    minRequestSize,
			MaxRequestSize:    stats.MaxRequestSize,
			QPS:               qps,
		}
		return true
	})

	stats := PublicStats{
		TotalRequests:     atomic.LoadUint64(&sc.TotalRequests),
		ActiveConnections: atomic.LoadInt64(&sc.ActiveConnections),
		TotalBytesSent:    atomic.LoadUint64(&sc.TotalBytesSent),
		TotalBytesRecv:    atomic.LoadUint64(&sc.TotalBytesRecv),
		Uptime:            time.Since(sc.StartTime).String(),
		RuleStats:         ruleStatsMap,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}