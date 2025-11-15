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
	MatchCount uint64
	BytesSent  uint64
	BytesRecv  uint64
	Errors     uint64
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
	stats, _ := sc.RuleStats.LoadOrStore(ruleKey, &RuleStats{})
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
		MatchCount uint64 `json:"matchCount"`
		BytesSent  uint64 `json:"bytesSent"`
		BytesRecv  uint64 `json:"bytesRecv"`
		Errors     uint64 `json:"errors"`
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
		ruleStatsMap[ruleKey] = &PublicRuleStats{
			MatchCount: atomic.LoadUint64(&stats.MatchCount),
			BytesSent:  atomic.LoadUint64(&stats.BytesSent),
			BytesRecv:  atomic.LoadUint64(&stats.BytesRecv),
			Errors:     atomic.LoadUint64(&stats.Errors),
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