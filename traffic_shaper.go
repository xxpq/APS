package main

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/time/rate"
)

// TrafficShaper manages rate limiters and traffic quotas for different entities.
type TrafficShaper struct {
	limiters sync.Map // map[string]*rate.Limiter
	quotas   sync.Map // map[string]interface{} // Can store *TrafficQuota or *RequestQuota
	mu       sync.Mutex
}

// TrafficQuota tracks traffic usage against a defined limit.
type TrafficQuota struct {
	Limit    int64
	Used     int64
	mu       sync.RWMutex
	Exceeded bool
}

// RequestQuota tracks request count against a defined limit.
type RequestQuota struct {
	Limit    int64
	Used     int64
	mu       sync.RWMutex
	Exceeded bool
}

func NewTrafficShaper(initialUsage map[string]*QuotaUsageData) *TrafficShaper {
	ts := &TrafficShaper{}
	for key, data := range initialUsage {
		if data.TrafficUsed > 0 {
			// This will be fully populated when GetTrafficQuota is called with the limit
			ts.quotas.Store(key, &TrafficQuota{Used: data.TrafficUsed})
		}
		if data.RequestsUsed > 0 {
			// This will be fully populated when GetRequestQuota is called with the limit
			ts.quotas.Store(key, &RequestQuota{Used: data.RequestsUsed})
		}
	}
	return ts
}

// GetLimiter returns a rate limiter for a given key and rate limit string (e.g., "1mbps").
// If the limiter doesn't exist, it's created.
func (ts *TrafficShaper) GetLimiter(key, rateLimitStr string) (*rate.Limiter, error) {
	if rateLimitStr == "" {
		return nil, nil
	}

	if limiter, ok := ts.limiters.Load(key); ok {
		return limiter.(*rate.Limiter), nil
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Double check after lock
	if limiter, ok := ts.limiters.Load(key); ok {
		return limiter.(*rate.Limiter), nil
	}

	limit, err := parseRate(rateLimitStr)
	if err != nil {
		return nil, fmt.Errorf("invalid rate limit format for key '%s': %w", key, err)
	}

	limiter := rate.NewLimiter(limit, int(limit)) // Burst size equal to the rate limit
	ts.limiters.Store(key, limiter)
	return limiter, nil
}

// GetTrafficQuota returns a traffic quota tracker for a given key and quota string (e.g., "10gb").
// If the tracker doesn't exist, it's created.
func (ts *TrafficShaper) GetTrafficQuota(key, quotaStr string) (*TrafficQuota, error) {
	if quotaStr == "" {
		return nil, nil
	}

	// Try to load existing quota
	val, loaded := ts.quotas.Load(key)
	if loaded {
		if quota, ok := val.(*TrafficQuota); ok {
			// Update limit if it has changed
			limit, err := parseSize(quotaStr)
			if err != nil {
				return nil, fmt.Errorf("invalid traffic quota format for key '%s': %w", key, err)
			}
			quota.mu.Lock()
			quota.Limit = limit
			quota.mu.Unlock()
			return quota, nil
		}
	}

	// Lock and double-check
	ts.mu.Lock()
	defer ts.mu.Unlock()

	val, loaded = ts.quotas.Load(key)
	if loaded { // Another goroutine might have created it
		if quota, ok := val.(*TrafficQuota); ok {
			limit, err := parseSize(quotaStr)
			if err != nil {
				return nil, fmt.Errorf("invalid traffic quota format for key '%s': %w", key, err)
			}
			quota.mu.Lock()
			quota.Limit = limit
			quota.mu.Unlock()
			return quota, nil
		}
	}

	// Create new quota
	limit, err := parseSize(quotaStr)
	if err != nil {
		return nil, fmt.Errorf("invalid traffic quota format for key '%s': %w", key, err)
	}
	
	// Check if initialUsage was already loaded in NewTrafficShaper for this key
	var initialUsed int64
	if val, ok := ts.quotas.Load(key); ok {
		// Existing entry might be a RequestQuota, handle this
		if existingTQ, ok := val.(*TrafficQuota); ok {
			initialUsed = existingTQ.Used
		}
	}

	quota := &TrafficQuota{
		Limit: limit,
		Used:  initialUsed, // Use loaded initial usage if available
	}
	ts.quotas.Store(key, quota)
	return quota, nil
}

// GetRequestQuota returns a request quota tracker for a given key and quota limit.
// If the tracker doesn't exist, it's created.
func (ts *TrafficShaper) GetRequestQuota(key string, quotaLimit int64) (*RequestQuota, error) {
	if quotaLimit <= 0 {
		return nil, nil
	}

	// Try to load existing quota
	val, loaded := ts.quotas.Load(key)
	if loaded {
		if quota, ok := val.(*RequestQuota); ok {
			// Update limit if it has changed
			quota.mu.Lock()
			quota.Limit = quotaLimit
			quota.mu.Unlock()
			return quota, nil
		}
	}

	// Lock and double-check
	ts.mu.Lock()
	defer ts.mu.Unlock()

	val, loaded = ts.quotas.Load(key)
	if loaded { // Another goroutine might have created it
		if quota, ok := val.(*RequestQuota); ok {
			quota.mu.Lock()
			quota.Limit = quotaLimit
			quota.mu.Unlock()
			return quota, nil
		}
	}

	// Create new quota
	// Check if initialUsage was already loaded in NewTrafficShaper for this key
	var initialUsed int64
	if val, ok := ts.quotas.Load(key); ok {
		if existingRQ, ok := val.(*RequestQuota); ok {
			initialUsed = existingRQ.Used
		}
	}

	quota := &RequestQuota{
		Limit: quotaLimit,
		Used:  initialUsed, // Use loaded initial usage if available
	}
	ts.quotas.Store(key, quota)
	return quota, nil
}

// AddTraffic records traffic usage for a given quota key.
func (tq *TrafficQuota) AddTraffic(amount int64) bool {
	if tq == nil {
		return true // No quota, allow traffic
	}

	tq.mu.Lock()
	defer tq.mu.Unlock()

	if tq.Exceeded || (tq.Used+amount > tq.Limit) {
		tq.Exceeded = true
		return false // Quota exceeded
	}

	tq.Used += amount
	return true
}

// AddRequest records a single request against a quota.
// Returns true if the request is allowed, false if the quota is exceeded.
func (rq *RequestQuota) AddRequest() bool {
	if rq == nil {
		return true // No quota, allow request
	}

	rq.mu.Lock()
	defer rq.mu.Unlock()

	if rq.Exceeded || (rq.Used+1 > rq.Limit) {
		rq.Exceeded = true
		return false // Quota exceeded
	}

	rq.Used++
	return true
}

// parseRate converts a string like "100kbps" or "1mbps" to a rate.Limit (float64 bytes/sec).
func parseRate(s string) (rate.Limit, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	var multiplier float64

	if strings.HasSuffix(s, "kbps") {
		multiplier = 1024
		s = strings.TrimSuffix(s, "kbps")
	} else if strings.HasSuffix(s, "mbps") {
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "mbps")
	} else if strings.HasSuffix(s, "gbps") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "gbps")
	} else if strings.HasSuffix(s, "bps") {
		multiplier = 1
		s = strings.TrimSuffix(s, "bps")
	} else {
		return 0, fmt.Errorf("invalid rate unit, must be bps, kbps, mbps, or gbps")
	}

	val, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, err
	}

	return rate.Limit(val * multiplier / 8), nil // Convert bits per second to bytes per second
}

// parseSize converts a string like "100mb" or "10gb" to bytes.
func parseSize(s string) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	var multiplier int64

	if strings.HasSuffix(s, "kb") {
		multiplier = 1024
		s = strings.TrimSuffix(s, "kb")
	} else if strings.HasSuffix(s, "mb") {
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "mb")
	} else if strings.HasSuffix(s, "gb") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "gb")
	} else if strings.HasSuffix(s, "b") {
		multiplier = 1
		s = strings.TrimSuffix(s, "b")
	} else {
		// Assume bytes if no unit
		multiplier = 1
	}

	val, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}

	return val * multiplier, nil
}

// limitedReadWriteCloser wraps an io.ReadWriteCloser to enforce rate limiting and track traffic quota.
type limitedReadWriteCloser struct {
	rwc    io.ReadWriteCloser
	reader io.Reader
	writer io.Writer
}

func newLimitedReadWriteCloser(rwc io.ReadWriteCloser, limiter *rate.Limiter, quota *TrafficQuota) io.ReadWriteCloser {
	reader := io.Reader(rwc)
	writer := io.Writer(rwc)

	if limiter != nil {
		reader = &limitedReader{r: reader, l: limiter}
		writer = &limitedWriter{w: writer, l: limiter}
	}

	if quota != nil {
		reader = &quotaReader{r: reader, tq: quota}
		writer = &quotaWriter{w: writer, tq: quota}
	}

	return &limitedReadWriteCloser{
		rwc:    rwc,
		reader: reader,
		writer: writer,
	}
}

func (l *limitedReadWriteCloser) Read(p []byte) (n int, err error) {
	return l.reader.Read(p)
}

func (l *limitedReadWriteCloser) Write(p []byte) (n int, err error) {
	return l.writer.Write(p)
}

func (l *limitedReadWriteCloser) Close() error {
	return l.rwc.Close()
}

// quotaReader wraps an io.Reader to track read bytes for a traffic quota.
type quotaReader struct {
	r  io.Reader
	tq *TrafficQuota
}

func (qr *quotaReader) Read(p []byte) (n int, err error) {
	n, err = qr.r.Read(p)
	if n > 0 {
		if !qr.tq.AddTraffic(int64(n)) {
			return n, io.ErrShortWrite // A bit of a hack, but signals quota exceeded
		}
	}
	return
}

// quotaWriter wraps an io.Writer to track written bytes for a traffic quota.
type quotaWriter struct {
	w  io.Writer
	tq *TrafficQuota
}

func (qw *quotaWriter) Write(p []byte) (n int, err error) {
	n, err = qw.w.Write(p)
	if n > 0 {
		if !qw.tq.AddTraffic(int64(n)) {
			return n, io.ErrShortWrite
		}
	}
	return
}

// limitedReader wraps an io.Reader to enforce a rate limit.
type limitedReader struct {
	r io.Reader
	l *rate.Limiter
}

func (lr *limitedReader) Read(p []byte) (n int, err error) {
	n, err = lr.r.Read(p)
	if n > 0 {
		if err := lr.l.WaitN(context.Background(), n); err != nil {
			return n, err
		}
	}
	return
}

// limitedWriter wraps an io.Writer to enforce a rate limit.
type limitedWriter struct {
	w io.Writer
	l *rate.Limiter
}

func (lw *limitedWriter) Write(p []byte) (n int, err error) {
	n, err = lw.w.Write(p)
	if n > 0 {
		if err := lw.l.WaitN(context.Background(), n); err != nil {
			return n, err
		}
	}
	return
}