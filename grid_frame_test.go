package main

import "testing"

func TestNextForwardFrameFromNil(t *testing.T) {
	frame := nextForwardFrame(nil)
	if frame == nil {
		t.Fatal("expected non-nil frame")
	}
	if frame.RouteID == "" || frame.TraceID == "" || frame.RouteEpoch == 0 {
		t.Fatalf("unexpected default frame: %+v", frame)
	}
	if frame.HopCount != 1 {
		t.Fatalf("expected hop_count=1, got %d", frame.HopCount)
	}
}

func TestNextForwardFrameIncrementsHopAndPreservesMetadata(t *testing.T) {
	orig := &ForwardFrame{
		RouteID:    "route-a",
		RouteEpoch: 1234,
		HopCount:   2,
		TraceID:    "trace-a",
		Payload:    []byte(`{"hops":["a","b"]}`),
	}
	next := nextForwardFrame(orig)
	if next.RouteID != orig.RouteID || next.RouteEpoch != orig.RouteEpoch || next.TraceID != orig.TraceID {
		t.Fatalf("metadata changed unexpectedly: orig=%+v next=%+v", orig, next)
	}
	if next.HopCount != 3 {
		t.Fatalf("expected hop_count=3, got %d", next.HopCount)
	}
	if string(next.Payload) != string(orig.Payload) {
		t.Fatalf("expected payload to be preserved, got %q", string(next.Payload))
	}
}
