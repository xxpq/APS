package main

import (
	"net"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

func TestHandleInboundRequestStreamRelayBidirectional(t *testing.T) {
	clientA, serverA, closeA := mustNewSMUXPair(t)
	defer closeA()
	clientB, serverB, closeB := mustNewSMUXPair(t)
	defer closeB()

	tm := &TCPTunnelManager{
		tunnels: make(map[string]*tcpTunnel),
		config:  &Config{},
	}
	server := &TCPTunnelServer{}
	server.SetTunnelManager(tm)

	epA := &TCPEndpoint{
		ID:           "ep-a-id",
		TunnelName:   "t1",
		EndpointName: "ep-a",
		session:      serverA,
	}
	epB := &TCPEndpoint{
		ID:           "ep-b-id",
		TunnelName:   "t1",
		EndpointName: "ep-b",
		session:      serverB,
	}
	tm.RegisterEndpoint(epA)
	tm.RegisterEndpoint(epB)

	srcClientStream, err := clientA.OpenStream()
	if err != nil {
		t.Fatalf("open source stream failed: %v", err)
	}
	defer srcClientStream.Close()
	srcClientConn := NewTunnelConn(srcClientStream)

	bootstrap := RequestStartPayloadTCP{
		ID:               "req-grid-relay-1",
		URL:              "http://example.com/path",
		Header:           []byte("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		GridRouteTo:      "ep-b",
		GridPayloadPlain: true,
		HopCount:         1,
	}
	if err := srcClientConn.SendJSON(MsgTypeRequestStart, bootstrap); err != nil {
		t.Fatalf("send bootstrap failed: %v", err)
	}

	apsSrcStream, err := serverA.AcceptStream()
	if err != nil {
		t.Fatalf("accept source stream on aps failed: %v", err)
	}

	relayDone := make(chan struct{})
	go func() {
		epA.handleInboundStream(server, apsSrcStream)
		close(relayDone)
	}()

	dstClientStream, err := clientB.AcceptStream()
	if err != nil {
		t.Fatalf("accept destination stream failed: %v", err)
	}
	defer dstClientStream.Close()
	dstClientConn := NewTunnelConn(dstClientStream)

	msg, err := dstClientConn.ReadMessage()
	if err != nil {
		t.Fatalf("read forwarded bootstrap failed: %v", err)
	}
	if msg.Type != MsgTypeRequestStart {
		t.Fatalf("expected request start type %d, got %d", MsgTypeRequestStart, msg.Type)
	}
	var forwarded RequestStartPayloadTCP
	if err := msg.ParseJSON(&forwarded); err != nil {
		t.Fatalf("parse forwarded bootstrap failed: %v", err)
	}
	if forwarded.GridRouteTo != "" {
		t.Fatalf("expected grid_route_to to be cleared after aps forwarding, got %q", forwarded.GridRouteTo)
	}
	if forwarded.ID != bootstrap.ID {
		t.Fatalf("expected forwarded id %q, got %q", bootstrap.ID, forwarded.ID)
	}

	if err := srcClientConn.SendJSON(MsgTypeRequestEnd, RequestEndPayloadTCP{ID: bootstrap.ID}); err != nil {
		t.Fatalf("send request end failed: %v", err)
	}
	msg, err = dstClientConn.ReadMessage()
	if err != nil {
		t.Fatalf("read forwarded request end failed: %v", err)
	}
	if msg.Type != MsgTypeRequestEnd {
		t.Fatalf("expected request end type %d, got %d", MsgTypeRequestEnd, msg.Type)
	}
	var reqEnd RequestEndPayloadTCP
	if err := msg.ParseJSON(&reqEnd); err != nil {
		t.Fatalf("parse forwarded request end failed: %v", err)
	}
	if reqEnd.ID != bootstrap.ID {
		t.Fatalf("expected forwarded request end id %q, got %q", bootstrap.ID, reqEnd.ID)
	}

	if err := dstClientConn.SendJSON(MsgTypeResponseEnd, ResponseEndPayloadTCP{ID: bootstrap.ID}); err != nil {
		t.Fatalf("send response end failed: %v", err)
	}
	msg, err = srcClientConn.ReadMessage()
	if err != nil {
		t.Fatalf("read relayed response end failed: %v", err)
	}
	if msg.Type != MsgTypeResponseEnd {
		t.Fatalf("expected response end type %d, got %d", MsgTypeResponseEnd, msg.Type)
	}
	var respEnd ResponseEndPayloadTCP
	if err := msg.ParseJSON(&respEnd); err != nil {
		t.Fatalf("parse relayed response end failed: %v", err)
	}
	if respEnd.ID != bootstrap.ID {
		t.Fatalf("expected relayed response end id %q, got %q", bootstrap.ID, respEnd.ID)
	}

	_ = srcClientStream.Close()
	_ = dstClientStream.Close()

	select {
	case <-relayDone:
	case <-time.After(2 * time.Second):
		t.Fatal("relay goroutine did not exit")
	}
}

func mustNewSMUXPair(t *testing.T) (*smux.Session, *smux.Session, func()) {
	t.Helper()
	clientConn, serverConn := net.Pipe()

	serverSession, err := smux.Server(serverConn, nil)
	if err != nil {
		_ = clientConn.Close()
		_ = serverConn.Close()
		t.Fatalf("create smux server failed: %v", err)
	}
	clientSession, err := smux.Client(clientConn, nil)
	if err != nil {
		_ = serverSession.Close()
		_ = clientConn.Close()
		_ = serverConn.Close()
		t.Fatalf("create smux client failed: %v", err)
	}

	closeFn := func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
		_ = clientConn.Close()
		_ = serverConn.Close()
	}
	return clientSession, serverSession, closeFn
}
