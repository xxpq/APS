package main

import (
	"testing"
	"time"
)

func TestStatsCollector_Intercepted(t *testing.T) {
	sc := NewStatsCollector(&Config{})
	defer sc.Close()

	// Simulate intercepted request
	sc.Record(RecordData{
		RuleKey:     "rule1",
		Intercepted: true,
		IsError:     false,
		Protocol:    "http",
	})

	// Simulate normal request
	sc.Record(RecordData{
		RuleKey:     "rule1",
		Intercepted: false,
		IsError:     false,
		Protocol:    "http",
	})

	// Simulate error request
	sc.Record(RecordData{
		RuleKey:     "rule1",
		Intercepted: false,
		IsError:     true,
		Protocol:    "http",
	})

	// Wait for async processing
	time.Sleep(100 * time.Millisecond)

	// Verify metrics
	metrics := sc.getMetrics(&sc.RuleStats, "rule1")
	if metrics == nil {
		t.Fatal("metrics not found")
	}

	metrics.mutex.Lock()
	defer metrics.mutex.Unlock()

	if metrics.RequestCount != 3 {
		t.Errorf("expected RequestCount 3, got %d", metrics.RequestCount)
	}

	if metrics.Intercepted != 1 {
		t.Errorf("expected Intercepted 1, got %d", metrics.Intercepted)
	}

	if metrics.Errors != 1 {
		t.Errorf("expected Errors 1, got %d", metrics.Errors)
	}
}
