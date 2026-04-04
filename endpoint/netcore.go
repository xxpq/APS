package main

import (
	"sort"
	"strings"
	"sync"
	"time"
)

type NetPath struct {
	RouteID      string
	RouteEpoch   int64
	NextHop      string
	Transport    string // quic|tcp|relay
	Reliability  float64
	LatencyMs    int64
	HopCount     int
	LastSelected time.Time
}

type NetCore struct {
	mu        sync.RWMutex
	paths     map[string][]NetPath // destination -> candidates
	useQUIC   bool
	useTCP    bool
	parallel  bool
	iceEnable bool
}

var endpointNetCoreRegistry = struct {
	mu   sync.RWMutex
	core *NetCore
}{}

func NewNetCore(useQUIC, useTCP, parallel, iceEnable bool) *NetCore {
	return &NetCore{
		paths:     make(map[string][]NetPath),
		useQUIC:   useQUIC,
		useTCP:    useTCP,
		parallel:  parallel,
		iceEnable: iceEnable,
	}
}

func EnsureNetCore() *NetCore {
	endpointNetCoreRegistry.mu.Lock()
	defer endpointNetCoreRegistry.mu.Unlock()
	if endpointNetCoreRegistry.core == nil {
		endpointNetCoreRegistry.core = NewNetCore(true, true, true, true)
	}
	return endpointNetCoreRegistry.core
}

func RecordRelayPath(destination, routeID string, routeEpoch int64, hopCount int) {
	destination = strings.TrimSpace(destination)
	if destination == "" {
		return
	}
	core := EnsureNetCore()
	if routeID == "" {
		routeID = "relay-fallback"
	}
	if routeEpoch == 0 {
		routeEpoch = time.Now().UTC().UnixNano()
	}
	if hopCount < 0 {
		hopCount = 0
	}
	path := NetPath{
		RouteID:     routeID,
		RouteEpoch:  routeEpoch,
		NextHop:     "aps-relay",
		Transport:   "relay",
		Reliability: 0.95,
		LatencyMs:   int64((hopCount + 1) * 15),
		HopCount:    hopCount,
	}
	core.UpdatePaths(destination, []NetPath{path})
}

func (n *NetCore) UpdatePaths(destination string, candidates []NetPath) {
	n.mu.Lock()
	defer n.mu.Unlock()
	dedup := make(map[string]NetPath)
	for _, candidate := range candidates {
		key := candidate.RouteID + "|" + candidate.NextHop + "|" + candidate.Transport
		dedup[key] = candidate
	}
	normalized := make([]NetPath, 0, len(dedup))
	for _, candidate := range dedup {
		if candidate.Reliability <= 0 {
			candidate.Reliability = 0.01
		}
		if candidate.LatencyMs <= 0 {
			candidate.LatencyMs = 1
		}
		normalized = append(normalized, candidate)
	}
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].Reliability == normalized[j].Reliability {
			if normalized[i].LatencyMs == normalized[j].LatencyMs {
				return normalized[i].HopCount < normalized[j].HopCount
			}
			return normalized[i].LatencyMs < normalized[j].LatencyMs
		}
		return normalized[i].Reliability > normalized[j].Reliability
	})
	n.paths[destination] = normalized
}

func (n *NetCore) SelectPath(destination string) (NetPath, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	candidates := n.paths[destination]
	if len(candidates) == 0 {
		return NetPath{}, false
	}
	selected := candidates[0]
	selected.LastSelected = time.Now().UTC()
	candidates[0] = selected
	n.paths[destination] = candidates
	return selected, true
}

func (n *NetCore) SupportsQUIC() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.useQUIC
}

func (n *NetCore) SupportsTCP() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.useTCP
}

func (n *NetCore) IsParallelEnabled() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.parallel
}

func (n *NetCore) IsICEEnabled() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.iceEnable
}
