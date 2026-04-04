package main

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type fakeTunnelManager struct {
	lastSendTunnel      string
	lastSendEndpoint    string
	lastSendFrame       *ForwardFrame
	sendFailures        map[string]error
	sendCallByEndpoint  map[string]int
	lastConnectTunnel   string
	lastConnectEndpoint string
	lastConnectFrame    *ForwardFrame
}

func (f *fakeTunnelManager) StartTCPServer(addr string) error     { return nil }
func (f *fakeTunnelManager) HandleTunnelConnection(conn net.Conn) {}
func (f *fakeTunnelManager) SendRequestStream(ctx context.Context, tunnelName, endpointName string, reqPayload *RequestPayload) (io.ReadCloser, []byte, error) {
	f.lastSendTunnel = tunnelName
	f.lastSendEndpoint = endpointName
	if reqPayload != nil {
		f.lastSendFrame = reqPayload.GridFrame
	}
	if f.sendCallByEndpoint == nil {
		f.sendCallByEndpoint = make(map[string]int)
	}
	f.sendCallByEndpoint[endpointName]++
	if f.sendFailures != nil {
		if err, exists := f.sendFailures[endpointName]; exists && err != nil {
			return nil, nil, err
		}
	}
	return io.NopCloser(&nopReader{}), []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), nil
}
func (f *fakeTunnelManager) SendProxyConnect(ctx context.Context, tunnelName, endpointName string, host string, port int, useTLS bool, clientConn net.Conn, clientIP string, frame *ForwardFrame) (<-chan struct{}, error) {
	f.lastConnectTunnel = tunnelName
	f.lastConnectEndpoint = endpointName
	f.lastConnectFrame = frame
	ch := make(chan struct{})
	close(ch)
	return ch, nil
}
func (f *fakeTunnelManager) GetRandomEndpointFromTunnels(tunnelNames []string) (string, string, error) {
	if len(tunnelNames) == 0 {
		return "", "", errors.New("no tunnels")
	}
	return tunnelNames[0], "ep-random", nil
}
func (f *fakeTunnelManager) FindTunnelForEndpoint(endpointName string) (string, bool) {
	if endpointName == "ep-next" {
		return "t-next", true
	}
	if endpointName == "ep-primary" {
		return "t-next", true
	}
	if endpointName == "ep-backup" {
		return "t-next", true
	}
	if endpointName == "ep-fallback" {
		return "t-fallback", true
	}
	return "", false
}
func (f *fakeTunnelManager) GetEndpointsInfo(tunnelName string, stats *StatsCollector) map[string]*EndpointInfo {
	return nil
}
func (f *fakeTunnelManager) MeasureEndpointLatency(tunnelName, endpointName string) (time.Duration, error) {
	return 0, nil
}
func (f *fakeTunnelManager) SetStatsCollector(statsCollector *StatsCollector) {}
func (f *fakeTunnelManager) GetPoolStats() map[string]interface{}             { return nil }
func (f *fakeTunnelManager) Cleanup()                                         {}
func (f *fakeTunnelManager) UpdateTunnels(newConfig *Config)                  {}
func (f *fakeTunnelManager) SendConfigUpdate(tunnelName, endpointName string, payload []byte) error {
	return nil
}
func (f *fakeTunnelManager) GetAllOnlineEndpoints() []EndpointInfo { return nil }

type nopReader struct{}

func (r *nopReader) Read(p []byte) (int, error) { return 0, io.EOF }

func TestGridExecutionEngineSendRequestStreamFallback(t *testing.T) {
	tm := &fakeTunnelManager{}
	engine := NewGridExecutionEngine(nil, tm, "server-a")
	if engine == nil {
		t.Fatal("engine should not be nil")
	}
	reqPayload := &RequestPayload{}
	_, _, err := engine.SendRequestStream(context.Background(), "t-fallback", "ep-fallback", reqPayload)
	if err != nil {
		t.Fatalf("SendRequestStream failed: %v", err)
	}
	if tm.lastSendTunnel != "t-fallback" || tm.lastSendEndpoint != "ep-fallback" {
		t.Fatalf("unexpected tunnel routing: %s/%s", tm.lastSendTunnel, tm.lastSendEndpoint)
	}
	if reqPayload.GridFrame == nil {
		t.Fatal("expected grid frame to be attached")
	}
	if reqPayload.GridFrame.RouteID == "" || reqPayload.GridFrame.TraceID == "" || reqPayload.GridFrame.RouteEpoch == 0 {
		t.Fatalf("unexpected frame: %+v", reqPayload.GridFrame)
	}
}

func TestGridExecutionEngineSendProxyConnectFallback(t *testing.T) {
	tm := &fakeTunnelManager{}
	engine := NewGridExecutionEngine(nil, tm, "server-a")
	if engine == nil {
		t.Fatal("engine should not be nil")
	}
	_, err := engine.SendProxyConnect(context.Background(), "t-fallback", "ep-fallback", "example.com", 443, true, nil, "127.0.0.1")
	if err != nil {
		t.Fatalf("SendProxyConnect failed: %v", err)
	}
	if tm.lastConnectTunnel != "t-fallback" || tm.lastConnectEndpoint != "ep-fallback" {
		t.Fatalf("unexpected connect routing: %s/%s", tm.lastConnectTunnel, tm.lastConnectEndpoint)
	}
	if tm.lastConnectFrame == nil {
		t.Fatal("expected proxy connect frame")
	}
	if tm.lastConnectFrame.RouteID == "" || tm.lastConnectFrame.TraceID == "" || tm.lastConnectFrame.RouteEpoch == 0 {
		t.Fatalf("unexpected proxy frame: %+v", tm.lastConnectFrame)
	}
}

func TestGridExecutionEngineSelectsBestRouteCandidate(t *testing.T) {
	tm := &fakeTunnelManager{}
	cp := buildTestGridControlPlane(t, GridDeploymentModeCluster)
	defer cp.Close()

	ctx := context.Background()
	_, err := cp.AnnounceRoute(ctx, &GridAnnounceRouteRequest{
		Route: RouteDescriptor{
			RouteID:          "route-better",
			SourceNode:       "aps:server-a",
			DestinationNode:  "ep-next",
			Hops:             []string{"aps:server-a", "ep-next"},
			ReliabilityScore: 0.98,
			LatencyMs:        20,
			Epoch:            1001,
			ExpiresAt:        time.Now().UTC().Add(2 * time.Minute).Unix(),
		},
	})
	if err != nil {
		t.Fatalf("announce better route failed: %v", err)
	}
	_, err = cp.AnnounceRoute(ctx, &GridAnnounceRouteRequest{
		Route: RouteDescriptor{
			RouteID:          "route-worse",
			SourceNode:       "aps:server-a",
			DestinationNode:  "ep-next",
			Hops:             []string{"aps:server-a", "ep-next"},
			ReliabilityScore: 0.40,
			LatencyMs:        5,
			Epoch:            1000,
			ExpiresAt:        time.Now().UTC().Add(2 * time.Minute).Unix(),
		},
	})
	if err != nil {
		t.Fatalf("announce worse route failed: %v", err)
	}

	engine := NewGridExecutionEngine(cp, tm, "server-a")
	if engine == nil {
		t.Fatal("engine should not be nil")
	}
	reqPayload := &RequestPayload{}
	_, _, err = engine.SendRequestStream(context.Background(), "", "ep-next", reqPayload)
	if err != nil {
		t.Fatalf("SendRequestStream failed: %v", err)
	}
	if tm.lastSendTunnel != "t-next" || tm.lastSendEndpoint != "ep-next" {
		t.Fatalf("unexpected selected route tunnel=%s endpoint=%s", tm.lastSendTunnel, tm.lastSendEndpoint)
	}
	if reqPayload.GridFrame == nil {
		t.Fatal("expected grid frame")
	}
	if reqPayload.GridFrame.RouteID != "route-better" {
		t.Fatalf("expected best route id route-better, got %s", reqPayload.GridFrame.RouteID)
	}
	if reqPayload.GridFrame.RouteEpoch != 1001 {
		t.Fatalf("expected route epoch 1001, got %d", reqPayload.GridFrame.RouteEpoch)
	}
	remaining := parseGridHopPlanPayload(reqPayload.GridFrame.Payload)
	if len(remaining) != 0 {
		t.Fatalf("expected no remaining hops, got %#v", remaining)
	}
}

func TestGridExecutionEngineEncodesRemainingHops(t *testing.T) {
	tm := &fakeTunnelManager{}
	cp := buildTestGridControlPlane(t, GridDeploymentModeCluster)
	defer cp.Close()

	_, err := cp.AnnounceRoute(context.Background(), &GridAnnounceRouteRequest{
		Route: RouteDescriptor{
			RouteID:          "route-chain",
			SourceNode:       "aps:server-a",
			DestinationNode:  "ep-hop-1",
			Hops:             []string{"aps:server-a", "ep-hop-1", "ep-hop-2", "ep-final"},
			ReliabilityScore: 0.95,
			LatencyMs:        50,
			Epoch:            2001,
			ExpiresAt:        time.Now().UTC().Add(2 * time.Minute).Unix(),
		},
	})
	if err != nil {
		t.Fatalf("announce route failed: %v", err)
	}
	engine := NewGridExecutionEngine(cp, tm, "server-a")
	if engine == nil {
		t.Fatal("engine should not be nil")
	}

	reqPayload := &RequestPayload{}
	_, _, err = engine.SendRequestStream(context.Background(), "t-next", "ep-hop-1", reqPayload)
	if err != nil {
		t.Fatalf("SendRequestStream failed: %v", err)
	}
	if reqPayload.GridFrame == nil {
		t.Fatal("expected grid frame")
	}
	remaining := parseGridHopPlanPayload(reqPayload.GridFrame.Payload)
	if len(remaining) != 2 || remaining[0] != "ep-hop-2" || remaining[1] != "ep-final" {
		t.Fatalf("unexpected remaining hops: %#v", remaining)
	}
}

func TestGridExecutionEngineRouteQueryUnreachable(t *testing.T) {
	tm := &fakeTunnelManager{}
	cp := buildTestGridControlPlane(t, GridDeploymentModeCluster)
	defer cp.Close()

	engine := NewGridExecutionEngine(cp, tm, "server-a")
	if engine == nil {
		t.Fatal("engine should not be nil")
	}

	reqPayload := &RequestPayload{}
	_, _, err := engine.SendRequestStream(context.Background(), "", "ep-offline", reqPayload)
	if err == nil {
		t.Fatal("expected route resolution error for unreachable destination")
	}
}

func TestGridExecutionEngineRequestRouteFailoverTop3(t *testing.T) {
	tm := &fakeTunnelManager{
		sendFailures: map[string]error{
			"ep-primary": errors.New("primary unavailable"),
		},
	}
	cp := buildTestGridControlPlane(t, GridDeploymentModeCluster)
	defer cp.Close()

	expire := time.Now().UTC().Add(2 * time.Minute).Unix()
	_, err := cp.AnnounceRoute(context.Background(), &GridAnnounceRouteRequest{
		Route: RouteDescriptor{
			RouteID:          "route-primary",
			SourceNode:       "aps:server-a",
			DestinationNode:  "ep-next",
			Hops:             []string{"aps:server-a", "ep-primary", "ep-next"},
			ReliabilityScore: 0.99,
			LatencyMs:        10,
			Epoch:            3001,
			ExpiresAt:        expire,
		},
	})
	if err != nil {
		t.Fatalf("announce primary failed: %v", err)
	}
	_, err = cp.AnnounceRoute(context.Background(), &GridAnnounceRouteRequest{
		Route: RouteDescriptor{
			RouteID:          "route-backup",
			SourceNode:       "aps:server-a",
			DestinationNode:  "ep-next",
			Hops:             []string{"aps:server-a", "ep-backup", "ep-next"},
			ReliabilityScore: 0.95,
			LatencyMs:        15,
			Epoch:            3002,
			ExpiresAt:        expire,
		},
	})
	if err != nil {
		t.Fatalf("announce backup failed: %v", err)
	}

	engine := NewGridExecutionEngine(cp, tm, "server-a")
	reqPayload := &RequestPayload{}
	_, _, err = engine.SendRequestStream(context.Background(), "", "ep-next", reqPayload)
	if err != nil {
		t.Fatalf("SendRequestStream should succeed via backup path: %v", err)
	}
	if tm.sendCallByEndpoint["ep-primary"] == 0 {
		t.Fatal("expected primary path to be attempted first")
	}
	if tm.sendCallByEndpoint["ep-backup"] == 0 {
		t.Fatal("expected backup path to be attempted after primary failure")
	}
	if tm.lastSendEndpoint != "ep-backup" {
		t.Fatalf("expected final successful endpoint ep-backup, got %s", tm.lastSendEndpoint)
	}
}
