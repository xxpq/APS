package main

import (
	"strings"
	"time"
)

func nextForwardFrame(frame *ForwardFrame) *ForwardFrame {
	nowEpoch := time.Now().UTC().UnixNano()
	next := &ForwardFrame{
		RouteID:    "relay-fallback",
		RouteEpoch: nowEpoch,
		HopCount:   1,
		TraceID:    "trace-fallback",
	}
	if traceID, err := randomGridTraceID(); err == nil && strings.TrimSpace(traceID) != "" {
		next.TraceID = traceID
	}
	if frame == nil {
		return next
	}

	if strings.TrimSpace(frame.RouteID) != "" {
		next.RouteID = strings.TrimSpace(frame.RouteID)
	}
	if frame.RouteEpoch > 0 {
		next.RouteEpoch = frame.RouteEpoch
	}
	if strings.TrimSpace(frame.TraceID) != "" {
		next.TraceID = strings.TrimSpace(frame.TraceID)
	}
	if frame.HopCount >= 0 {
		next.HopCount = frame.HopCount + 1
	}
	if next.HopCount <= 0 {
		next.HopCount = 1
	}
	if len(frame.Payload) > 0 {
		next.Payload = append([]byte(nil), frame.Payload...)
	}
	return next
}
