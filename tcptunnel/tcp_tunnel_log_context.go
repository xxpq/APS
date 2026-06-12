package tcptunnel

import (
	"fmt"
	"net/url"
	"strings"
)

func normalizeTCPTunnelLogValue(v string) string {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return "-"
	}
	return trimmed
}

func extractTCPTunnelTargetAddr(rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return "-"
	}

	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" {
		return trimmed
	}
	return parsed.Host
}

func buildTCPTunnelRoutePrefix(sourceIP, endpointName, endpointID, targetAddr string) string {
	ep := normalizeTCPTunnelLogValue(endpointName)
	id := normalizeTCPTunnelLogValue(endpointID)
	if ep == "-" {
		ep = id
	} else if id != "-" {
		ep = fmt.Sprintf("%s/%s", ep, id)
	}

	return fmt.Sprintf(
		"[SRC:%s][EP:%s][DST:%s]",
		normalizeTCPTunnelLogValue(sourceIP),
		ep,
		normalizeTCPTunnelLogValue(targetAddr),
	)
}

func buildTCPTunnelEndpointScope(endpointName, endpointID string) string {
	ep := normalizeTCPTunnelLogValue(endpointName)
	if ep != "-" {
		return ep
	}
	return normalizeTCPTunnelLogValue(endpointID)
}

func buildTCPTunnelLogScopeKey(sourceIP, endpointName, endpointID, targetAddr string) string {
	return fmt.Sprintf(
		"%s|%s|%s",
		normalizeTCPTunnelLogValue(sourceIP),
		buildTCPTunnelEndpointScope(endpointName, endpointID),
		normalizeTCPTunnelLogValue(targetAddr),
	)
}
