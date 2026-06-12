package util

import (
	"log"
	"sync"
	"time"
)

type debugLogThrottle struct {
	mu   sync.Mutex
	last map[string]time.Time
}

var globalDebugLogThrottle = &debugLogThrottle{
	last: make(map[string]time.Time),
}

func (t *debugLogThrottle) allow(key string, window time.Duration, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if lastTime, ok := t.last[key]; ok && now.Sub(lastTime) < window {
		return false
	}
	t.last[key] = now
	return true
}

func DebugLogThrottled(key string, window time.Duration, format string, args ...interface{}) {
	if !IsDebugMode {
		return
	}
	if !globalDebugLogThrottle.allow(key, window, time.Now()) {
		return
	}
	log.Printf(format, args...)
}
