package main

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	upnp "github.com/NebulousLabs/go-upnp"
)

var gridUPnPState = struct {
	mu           sync.Mutex
	igd          *upnp.IGD
	externalIP   string
	discoveredAt time.Time
	forwarded    map[uint16]struct{}
}{}

func isGridUPnPEnabled() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("APS_GRID_UPNP_ENABLE")))
	if raw == "" {
		return true
	}
	switch raw {
	case "0", "false", "no", "off", "disable", "disabled":
		return false
	default:
		return true
	}
}

func gridUPnPCandidatesForPorts(ports []int) []string {
	if !isGridUPnPEnabled() {
		return nil
	}
	ports = normalizeGridCandidatePorts(ports)
	if len(ports) == 0 {
		return nil
	}

	igd, externalIP := ensureGridUPnPDiscovery()
	if igd == nil || externalIP == "" {
		return nil
	}

	now := time.Now()
	gridUPnPState.mu.Lock()
	if gridUPnPState.forwarded == nil {
		gridUPnPState.forwarded = make(map[uint16]struct{})
	}
	gridUPnPState.discoveredAt = now
	gridUPnPState.mu.Unlock()

	candidates := make([]string, 0, len(ports))
	for _, port := range ports {
		if port <= 0 || port > 65535 {
			continue
		}
		p := uint16(port)
		needsForward := false

		gridUPnPState.mu.Lock()
		_, alreadyForwarded := gridUPnPState.forwarded[p]
		if !alreadyForwarded {
			needsForward = true
		}
		gridUPnPState.mu.Unlock()

		if needsForward {
			if err := igd.Forward(p, "aps-grid"); err == nil {
				gridUPnPState.mu.Lock()
				gridUPnPState.forwarded[p] = struct{}{}
				gridUPnPState.mu.Unlock()
			}
		}

		candidates = append(candidates, net.JoinHostPort(externalIP, strconv.Itoa(port)))
	}
	return candidates
}

func ensureGridUPnPDiscovery() (*upnp.IGD, string) {
	gridUPnPState.mu.Lock()
	if gridUPnPState.igd != nil && gridUPnPState.externalIP != "" && time.Since(gridUPnPState.discoveredAt) < 10*time.Minute {
		igd := gridUPnPState.igd
		externalIP := gridUPnPState.externalIP
		gridUPnPState.mu.Unlock()
		return igd, externalIP
	}
	gridUPnPState.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	igd, err := upnp.DiscoverCtx(ctx)
	if err != nil || igd == nil {
		return nil, ""
	}
	externalIP, err := igd.ExternalIP()
	if err != nil {
		return nil, ""
	}
	externalIP = strings.TrimSpace(externalIP)
	if externalIP == "" {
		return nil, ""
	}

	gridUPnPState.mu.Lock()
	gridUPnPState.igd = igd
	gridUPnPState.externalIP = externalIP
	gridUPnPState.discoveredAt = time.Now()
	if gridUPnPState.forwarded == nil {
		gridUPnPState.forwarded = make(map[uint16]struct{})
	}
	gridUPnPState.mu.Unlock()
	return igd, externalIP
}
