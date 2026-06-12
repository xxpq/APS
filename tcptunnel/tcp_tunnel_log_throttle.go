package tcptunnel

import (
	"fmt"
	"log"
	"sync"
	"time"

	"aps/util"
)

const tcpTunnelLogThrottleWindow = 30 * time.Second
const tcpTunnelLogThrottleMaxKeys = 8192

type tcpTunnelLogThrottle struct {
	mu   sync.Mutex
	last map[string]time.Time
}

var globalTCPTunnelLogThrottle = &tcpTunnelLogThrottle{
	last: make(map[string]time.Time),
}

func (t *tcpTunnelLogThrottle) allow(key string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if lastTime, ok := t.last[key]; ok && now.Sub(lastTime) < tcpTunnelLogThrottleWindow {
		return false
	}
	t.last[key] = now

	if len(t.last) > tcpTunnelLogThrottleMaxKeys {
		cutoff := now.Add(-tcpTunnelLogThrottleWindow * 2)
		for k, ts := range t.last {
			if ts.Before(cutoff) {
				delete(t.last, k)
			}
		}
	}

	return true
}

func debugLogTCPTunnelThrottled(sourceIP, endpointName, endpointID, targetAddr, eventKey, format string, args ...interface{}) {
	if !util.IsDebugMode {
		return
	}

	scopeKey := buildTCPTunnelLogScopeKey(sourceIP, endpointName, endpointID, targetAddr)
	throttleKey := fmt.Sprintf("%s|%s", scopeKey, eventKey)
	if !globalTCPTunnelLogThrottle.allow(throttleKey, time.Now()) {
		return
	}

	log.Printf(format, args...)
}

func tcpTunnelEventKey(prefix string, msgType uint8) string {
	return fmt.Sprintf("%s_%d", prefix, msgType)
}
