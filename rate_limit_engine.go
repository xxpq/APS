package main

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Metric Types
const (
	MetricTransferRate       = "transfer_rate"       // Bytes per second (calculated over window)
	MetricTrafficVolume      = "traffic_volume"      // Total bytes in window
	MetricConcurrentRequests = "concurrent_requests" // Active requests
	MetricRequestCount       = "request_count"       // Total requests in window
)

// Action Types
const (
	ActionBan      = "ban"
	ActionQueue    = "queue"
	ActionRedirect = "redirect"
)

// Target Types
const (
	TargetIP    = "ip"
	TargetToken = "token"
)

// MetricConfig defines a metric to track
type MetricConfig struct {
	Type      string  `json:"type"`      // Metric type
	Window    int     `json:"window"`    // Window size in seconds
	Threshold float64 `json:"threshold"` // Threshold value
}

// ActionConfig defines an action to take when threshold is exceeded
type ActionConfig struct {
	Type     string `json:"type"`     // Action type
	Duration int    `json:"duration"` // For ban (seconds)
	MaxWait  int    `json:"maxWait"`  // For queue (seconds)
	Location string `json:"location"` // For redirect (URL)
}

// RateLimitRule defines a rate limiting rule
type RateLimitRule struct {
	Name       string         `json:"name"`
	TargetType string         `json:"targetType"` // "ip" or "token"
	Metrics    []MetricConfig `json:"metrics"`
	Actions    []ActionConfig `json:"actions"`
}

// Tracker interface for different metric types
type Tracker interface {
	Increment(amount float64)
	Decrement(amount float64)
	Value() float64
	ResetIfNeeded(window int)
}

// WindowTracker tracks counts/sums over a time window
type WindowTracker struct {
	count       float64
	windowStart time.Time
	mu          sync.Mutex
}

func (t *WindowTracker) Increment(amount float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.count += amount
}

func (t *WindowTracker) Decrement(amount float64) {
	// Not used for window tracker usually
}

func (t *WindowTracker) Value() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.count
}

func (t *WindowTracker) ResetIfNeeded(window int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if time.Since(t.windowStart) > time.Duration(window)*time.Second {
		t.count = 0
		t.windowStart = time.Now()
	}
}

// GaugeTracker tracks current value (e.g. concurrency)
type GaugeTracker struct {
	value float64
	mu    sync.Mutex
}

func (t *GaugeTracker) Increment(amount float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.value += amount
}

func (t *GaugeTracker) Decrement(amount float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.value -= amount
}

func (t *GaugeTracker) Value() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.value
}

func (t *GaugeTracker) ResetIfNeeded(window int) {
	// No-op for gauge
}

// RateLimitEngine manages rate limiting
type RateLimitEngine struct {
	mu    sync.RWMutex
	rules map[string]*RateLimitRule

	// Key: dimension_target_rule_metricIndex
	trackers sync.Map

	// Key: dimension_target_rule
	banned sync.Map // map[string]time.Time
}

func NewRateLimitEngine(rules map[string]*RateLimitRule) *RateLimitEngine {
	if rules == nil {
		rules = make(map[string]*RateLimitRule)
	}
	return &RateLimitEngine{
		rules: rules,
	}
}

// UpdateRule updates or adds a rule
func (e *RateLimitEngine) UpdateRule(rule *RateLimitRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules[rule.Name] = rule
}

// DeleteRule deletes a rule
func (e *RateLimitEngine) DeleteRule(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.rules, name)
}

// RequestContext holds info for rate limiting check
type RequestContext struct {
	IP        string
	Token     string
	Server    string
	Mapping   string
	User      string
	RuleNames []string // Rules to apply
}

// ActionResult result of rate limit check
type ActionResult struct {
	Allowed      bool
	Action       string // "ban", "queue", "redirect"
	RedirectURL  string
	WaitDuration time.Duration
	Message      string
}

// CheckRules checks if request is allowed based on rules
func (e *RateLimitEngine) CheckRules(ctx *RequestContext) (*ActionResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, ruleName := range ctx.RuleNames {
		rule, exists := e.rules[ruleName]
		if !exists {
			continue
		}

		target := ctx.IP
		if rule.TargetType == TargetToken {
			target = ctx.Token
			if target == "" {
				continue // Skip if token required but not present
			}
		}
	}
	return &ActionResult{Allowed: true}, nil
}

// CheckRequest checks all applicable rules for the request
func (e *RateLimitEngine) CheckRequest(ip, token string, bindings map[string][]string) *ActionResult {
	// bindings: map[dimension_key][]rule_names
	// dimension_key example: "server:srv1", "mapping:map1", "user:usr1"

	for dimKey, ruleNames := range bindings {
		e.mu.RLock()
		for _, ruleName := range ruleNames {
			rule, exists := e.rules[ruleName]
			if !exists {
				continue
			}

			// Determine target value
			targetVal := ip
			if rule.TargetType == TargetToken {
				targetVal = token
			}
			if targetVal == "" {
				continue
			}

			// Check if banned
			banKey := fmt.Sprintf("ban:%s:%s:%s", dimKey, ruleName, targetVal)
			if expiry, ok := e.banned.Load(banKey); ok {
				if time.Now().Before(expiry.(time.Time)) {
					e.mu.RUnlock()
					return &ActionResult{
						Allowed: false,
						Action:  ActionBan,
						Message: "Rate limit exceeded (Banned)",
					}
				} else {
					e.banned.Delete(banKey)
				}
			}

			// Check metrics
			triggered := false
			for i, metric := range rule.Metrics {
				trackerKey := fmt.Sprintf("track:%s:%s:%s:%d", dimKey, ruleName, targetVal, i)

				var currentVal float64

				// Get or create tracker
				t, _ := e.trackers.LoadOrStore(trackerKey, e.createTracker(metric.Type))
				tracker := t.(Tracker)

				// For window-based metrics, check reset
				tracker.ResetIfNeeded(metric.Window)

				// For concurrency, we don't increment here, we just check.
				// Increment happens in OnRequestStart/OnRequestEnd.
				// For others (count, volume), we increment tentatively?
				// Usually rate limiting checks BEFORE incrementing for strict limits.
				// But for sliding window, we usually count the current request.
				// Let's check current value + projected increment.

				currentVal = tracker.Value()

				increment := 0.0
				if metric.Type == MetricRequestCount {
					increment = 1
				} else if metric.Type == MetricConcurrentRequests {
					increment = 1
				}
				// Traffic volume/rate is harder to predict before request.
				// We might only check existing volume.

				// Check threshold
				checkVal := currentVal
				if metric.Type == MetricRequestCount || metric.Type == MetricConcurrentRequests {
					checkVal += increment
				}

				if checkVal > metric.Threshold {
					triggered = true
					break
				}
			}

			if triggered {
				// Execute actions
				// We take the first action for now, or highest priority?
				// User said "can execute ban, queue, redirect".
				// Let's pick the most severe? Ban > Queue > Redirect.

				for _, action := range rule.Actions {
					if action.Type == ActionBan {
						e.banned.Store(banKey, time.Now().Add(time.Duration(action.Duration)*time.Second))
						e.mu.RUnlock()
						return &ActionResult{
							Allowed: false,
							Action:  ActionBan,
							Message: fmt.Sprintf("Rate limit exceeded. Banned for %ds", action.Duration),
						}
					}
					if action.Type == ActionRedirect {
						e.mu.RUnlock()
						return &ActionResult{
							Allowed:     false,
							Action:      ActionRedirect,
							RedirectURL: action.Location,
						}
					}
					if action.Type == ActionQueue {
						// Queue logic is complex to implement in this synchronous check.
						// We'll return a Queue action and let the handler handle the wait.
						e.mu.RUnlock()
						return &ActionResult{
							Allowed:      true, // Allowed but needs wait
							Action:       ActionQueue,
							WaitDuration: time.Duration(action.MaxWait) * time.Second, // This is max wait, actual wait depends on queue depth?
							// For simple implementation, we might just return "Queue" and let handler sleep?
							// But without a real queue, sleeping just holds the connection.
							// If we want a real queue, we need a channel per key.
						}
					}
				}
				// If no action defined but triggered? Block?
				e.mu.RUnlock()
				return &ActionResult{Allowed: false, Message: "Rate limit exceeded"}
			}
		}
		e.mu.RUnlock()
	}

	return &ActionResult{Allowed: true}
}

func (e *RateLimitEngine) createTracker(metricType string) Tracker {
	if metricType == MetricConcurrentRequests {
		return &GaugeTracker{}
	}
	return &WindowTracker{windowStart: time.Now()}
}

// OnRequestStart increments counters
func (e *RateLimitEngine) OnRequestStart(ip, token string, bindings map[string][]string) {
	e.updateTrackers(ip, token, bindings, 1, 0, true)
}

// OnRequestEnd decrements concurrency, adds traffic
func (e *RateLimitEngine) OnRequestEnd(ip, token string, bindings map[string][]string, bytes int64) {
	e.updateTrackers(ip, token, bindings, -1, float64(bytes), false)
}

func (e *RateLimitEngine) updateTrackers(ip, token string, bindings map[string][]string, concurrencyDelta float64, trafficDelta float64, isStart bool) {
	for dimKey, ruleNames := range bindings {
		e.mu.RLock()
		for _, ruleName := range ruleNames {
			rule, exists := e.rules[ruleName]
			if !exists {
				continue
			}

			targetVal := ip
			if rule.TargetType == TargetToken {
				targetVal = token
			}
			if targetVal == "" {
				continue
			}

			for i, metric := range rule.Metrics {
				trackerKey := fmt.Sprintf("track:%s:%s:%s:%d", dimKey, ruleName, targetVal, i)
				t, ok := e.trackers.Load(trackerKey)
				if !ok {
					// Should exist if CheckRequest was called, but if not, create
					t, _ = e.trackers.LoadOrStore(trackerKey, e.createTracker(metric.Type))
				}
				tracker := t.(Tracker)

				if metric.Type == MetricConcurrentRequests {
					if concurrencyDelta > 0 {
						tracker.Increment(concurrencyDelta)
					} else {
						tracker.Decrement(-concurrencyDelta)
					}
				} else if metric.Type == MetricRequestCount {
					if isStart {
						tracker.Increment(1)
					}
				} else if metric.Type == MetricTrafficVolume || metric.Type == MetricTransferRate {
					if !isStart && trafficDelta > 0 {
						tracker.Increment(trafficDelta)
					}
				}
			}
		}
		e.mu.RUnlock()
	}
}

// IsBanned checks if the target is currently banned by any rule
func (e *RateLimitEngine) IsBanned(target string) bool {
	banned := false
	e.banned.Range(func(key, value interface{}) bool {
		// key is string "ban:dim:rule:target"
		k := key.(string)
		if strings.HasSuffix(k, ":"+target) {
			if time.Now().Before(value.(time.Time)) {
				banned = true
				return false // stop iteration
			}
		}
		return true
	})
	return banned
}
