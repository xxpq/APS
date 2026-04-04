package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type GridExecutionEngine struct {
	control      *GridControlPlane
	tunnelManger TunnelManagerInterface
	sourceNode   string
}

type resolvedGridPath struct {
	TunnelName   string
	EndpointName string
	Frame        *ForwardFrame
	Priority     int
	Score        float64
}

func NewGridExecutionEngine(control *GridControlPlane, tunnelManager TunnelManagerInterface, sourceNode string) *GridExecutionEngine {
	if tunnelManager == nil {
		return nil
	}
	return &GridExecutionEngine{
		control:      control,
		tunnelManger: tunnelManager,
		sourceNode:   strings.TrimSpace(sourceNode),
	}
}

func (g *GridExecutionEngine) SendRequestStream(ctx context.Context, tunnelName, endpointName string, reqPayload *RequestPayload) (io.ReadCloser, []byte, error) {
	if g == nil || g.tunnelManger == nil {
		return nil, nil, errors.New("grid execution engine is not initialized")
	}

	paths := g.resolvePathCandidates(ctx, tunnelName, endpointName, 3)
	if len(paths) == 0 {
		return nil, nil, fmt.Errorf("grid route resolution failed: tunnel='%s' endpoint='%s'", strings.TrimSpace(tunnelName), strings.TrimSpace(endpointName))
	}

	allowRetry := reqPayload == nil || reqPayload.Body == nil
	var lastErr error
	for i, path := range paths {
		if reqPayload != nil {
			reqPayload.GridFrame = cloneForwardFrame(path.Frame)
		}
		rc, header, err := g.tunnelManger.SendRequestStream(ctx, path.TunnelName, path.EndpointName, reqPayload)
		if err == nil {
			return rc, header, nil
		}
		lastErr = err
		DebugLog("[GRID] request route attempt failed idx=%d priority=%d tunnel=%s endpoint=%s err=%v", i+1, path.Priority, path.TunnelName, path.EndpointName, err)
		if !allowRetry {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no available route path")
	}
	return nil, nil, lastErr
}

func (g *GridExecutionEngine) SendProxyConnect(ctx context.Context, tunnelName, endpointName string, host string, port int, useTLS bool, clientConn net.Conn, clientIP string) (<-chan struct{}, error) {
	if g == nil || g.tunnelManger == nil {
		return nil, errors.New("grid execution engine is not initialized")
	}
	resolvedTunnel, resolvedEndpoint, frame := g.resolvePath(ctx, tunnelName, endpointName)
	if strings.TrimSpace(resolvedTunnel) == "" || strings.TrimSpace(resolvedEndpoint) == "" {
		return nil, fmt.Errorf("grid route resolution failed: tunnel='%s' endpoint='%s'", resolvedTunnel, resolvedEndpoint)
	}
	return g.tunnelManger.SendProxyConnect(ctx, resolvedTunnel, resolvedEndpoint, host, port, useTLS, clientConn, clientIP, frame)
}

func cloneForwardFrame(frame *ForwardFrame) *ForwardFrame {
	if frame == nil {
		return nil
	}
	cloned := *frame
	if len(frame.Payload) > 0 {
		cloned.Payload = append([]byte(nil), frame.Payload...)
	}
	return &cloned
}

func (g *GridExecutionEngine) resolvePath(ctx context.Context, tunnelName, endpointName string) (string, string, *ForwardFrame) {
	paths := g.resolvePathCandidates(ctx, tunnelName, endpointName, 1)
	if len(paths) == 0 {
		return "", "", nil
	}
	return paths[0].TunnelName, paths[0].EndpointName, paths[0].Frame
}

func (g *GridExecutionEngine) resolvePathCandidates(ctx context.Context, tunnelName, endpointName string, maxCandidates int) []resolvedGridPath {
	resolvedTunnel := strings.TrimSpace(tunnelName)
	resolvedEndpoint := strings.TrimSpace(endpointName)
	if maxCandidates <= 0 {
		maxCandidates = 1
	}

	routeID := "relay-fallback"
	routeEpoch := time.Now().UTC().UnixNano()
	traceID := "trace-fallback"
	if id, err := randomGridTraceID(); err == nil {
		traceID = id
	}

	if g.control == nil || resolvedEndpoint == "" {
		t, e, f := g.resolveWithFallback(resolvedTunnel, resolvedEndpoint, routeID, routeEpoch, traceID)
		if strings.TrimSpace(t) == "" || strings.TrimSpace(e) == "" || f == nil {
			return nil
		}
		return []resolvedGridPath{{TunnelName: t, EndpointName: e, Frame: f, Priority: 1, Score: 0}}
	}

	source := g.sourceNode
	if source == "" {
		source = "aps"
	}
	if !strings.HasPrefix(source, "aps:") {
		source = "aps:" + source
	}

	queryResp, err := g.control.QueryRoutes(ctx, &GridQueryRouteRequest{
		SourceNode:      source,
		DestinationNode: resolvedEndpoint,
		Limit:           8,
	})
	if err != nil || queryResp == nil {
		t, e, f := g.resolveWithFallback(resolvedTunnel, resolvedEndpoint, routeID, routeEpoch, traceID)
		if strings.TrimSpace(t) == "" || strings.TrimSpace(e) == "" || f == nil {
			return nil
		}
		return []resolvedGridPath{{TunnelName: t, EndpointName: e, Frame: f, Priority: 1, Score: 0}}
	}
	if !queryResp.Success {
		if queryResp.Unreachable || strings.EqualFold(strings.TrimSpace(queryResp.ErrorCode), GridRouteErrorNotFound) {
			DebugLog("[GRID] route query unreachable source=%s dst=%s code=%s err=%s", source, resolvedEndpoint, queryResp.ErrorCode, queryResp.Error)
			return nil
		}
		t, e, f := g.resolveWithFallback(resolvedTunnel, resolvedEndpoint, routeID, routeEpoch, traceID)
		if strings.TrimSpace(t) == "" || strings.TrimSpace(e) == "" || f == nil {
			return nil
		}
		return []resolvedGridPath{{TunnelName: t, EndpointName: e, Frame: f, Priority: 1, Score: 0}}
	}

	destinationICE := g.queryDestinationICECandidates(ctx, resolvedEndpoint)
	resolved := make([]resolvedGridPath, 0, maxCandidates)
	seen := make(map[string]struct{}, maxCandidates*2)
	for _, candidate := range queryResp.Candidates {
		if candidate.IsRelay {
			continue
		}
		nextHop := strings.TrimSpace(candidate.NextHop)
		if nextHop == "" {
			nextHop = resolvedEndpoint
		}
		tunnelForHop := resolvedTunnel
		if tunnelForHop == "" {
			if foundTunnel, ok := g.tunnelManger.FindTunnelForEndpoint(nextHop); ok {
				tunnelForHop = foundTunnel
			}
		}
		if tunnelForHop == "" {
			continue
		}

		frame := &ForwardFrame{
			RouteID:    nonEmpty(candidate.RouteID, routeID),
			RouteEpoch: nonZeroInt64(candidate.RouteEpoch, routeEpoch),
			HopCount:   0,
			TraceID:    traceID,
		}
		planICE := candidate.ICECandidates
		if len(planICE) == 0 {
			planICE = destinationICE
		}
		if remainingHops := extractRemainingHops(candidate.Hops, nextHop); len(remainingHops) > 0 {
			frame.Payload = buildGridHopPlanPayloadWithICE(remainingHops, planICE)
		} else if len(planICE) > 0 {
			frame.Payload = buildGridHopPlanPayloadWithICE(nil, planICE)
		}
		key := tunnelForHop + "|" + nextHop + "|" + frame.RouteID + "|" + fmt.Sprintf("%d", frame.RouteEpoch)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		resolved = append(resolved, resolvedGridPath{
			TunnelName:   tunnelForHop,
			EndpointName: nextHop,
			Frame:        frame,
			Priority:     candidate.Priority,
			Score:        candidate.Score,
		})
		if len(resolved) >= maxCandidates {
			break
		}
	}
	if len(resolved) > 0 {
		DebugLog("[GRID] route selected source=%s dst=%s candidates=%d", source, resolvedEndpoint, len(resolved))
		return resolved
	}

	if len(queryResp.Routes) > 0 {
		routeID = nonEmpty(queryResp.Routes[0].RouteID, routeID)
		routeEpoch = nonZeroInt64(queryResp.Routes[0].Epoch, routeEpoch)
	}
	t, e, f := g.resolveWithFallback(resolvedTunnel, resolvedEndpoint, routeID, routeEpoch, traceID)
	if strings.TrimSpace(t) == "" || strings.TrimSpace(e) == "" || f == nil {
		return nil
	}
	DebugLog("[GRID] fallback route: dst=%s tunnel=%s endpoint=%s route=%s epoch=%d trace=%s", reqSafeEndpoint(e), t, e, f.RouteID, f.RouteEpoch, f.TraceID)
	return []resolvedGridPath{{TunnelName: t, EndpointName: e, Frame: f, Priority: 1, Score: 0}}
}

func (g *GridExecutionEngine) resolveWithFallback(tunnelName, endpointName, routeID string, routeEpoch int64, traceID string) (string, string, *ForwardFrame) {
	resolvedTunnel := strings.TrimSpace(tunnelName)
	resolvedEndpoint := strings.TrimSpace(endpointName)

	if resolvedTunnel == "" && resolvedEndpoint != "" {
		if t, ok := g.tunnelManger.FindTunnelForEndpoint(resolvedEndpoint); ok {
			resolvedTunnel = t
		}
	}

	if resolvedEndpoint == "" && resolvedTunnel != "" {
		if _, ep, err := g.tunnelManger.GetRandomEndpointFromTunnels([]string{resolvedTunnel}); err == nil {
			resolvedEndpoint = ep
		}
	}

	frame := &ForwardFrame{
		RouteID:    nonEmpty(routeID, "relay-fallback"),
		RouteEpoch: nonZeroInt64(routeEpoch, time.Now().UTC().UnixNano()),
		HopCount:   0,
		TraceID:    nonEmpty(traceID, "trace-fallback"),
	}
	return resolvedTunnel, resolvedEndpoint, frame
}

func randomGridTraceID() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func nonEmpty(v string, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	return v
}

func nonZeroInt64(v int64, fallback int64) int64 {
	if v == 0 {
		return fallback
	}
	return v
}

func reqSafeEndpoint(v string) string {
	if strings.TrimSpace(v) == "" {
		return "<empty>"
	}
	return v
}

func (g *GridExecutionEngine) queryDestinationICECandidates(ctx context.Context, nodeID string) []string {
	if g == nil || g.control == nil {
		return nil
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return nil
	}
	resp, err := g.control.QueryICECandidates(ctx, &GridICEQueryRequest{NodeID: nodeID})
	if err != nil || resp == nil || !resp.Success {
		return nil
	}
	return append([]string(nil), resp.Candidates...)
}

func extractRemainingHops(hops []string, nextHop string) []string {
	if len(hops) == 0 {
		return nil
	}
	nextHop = strings.TrimSpace(nextHop)
	if nextHop == "" {
		return nil
	}
	idx := -1
	for i, hop := range hops {
		if strings.TrimSpace(hop) == nextHop {
			idx = i
			break
		}
	}
	if idx < 0 || idx+1 >= len(hops) {
		return nil
	}
	remaining := make([]string, 0, len(hops)-idx-1)
	for _, hop := range hops[idx+1:] {
		h := strings.TrimSpace(hop)
		if h == "" {
			continue
		}
		remaining = append(remaining, h)
	}
	return remaining
}
