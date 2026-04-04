package main

import (
	"os"
	"testing"
)

func TestIsGridUPnPEnabledDefaultOn(t *testing.T) {
	prev := os.Getenv("APS_GRID_UPNP_ENABLE")
	t.Cleanup(func() {
		_ = os.Setenv("APS_GRID_UPNP_ENABLE", prev)
	})
	if err := os.Unsetenv("APS_GRID_UPNP_ENABLE"); err != nil {
		t.Fatalf("unsetenv failed: %v", err)
	}
	if !isGridUPnPEnabled() {
		t.Fatal("expected UPnP to be enabled by default")
	}
}

func TestIsGridUPnPEnabledExplicitOff(t *testing.T) {
	prev := os.Getenv("APS_GRID_UPNP_ENABLE")
	t.Cleanup(func() {
		_ = os.Setenv("APS_GRID_UPNP_ENABLE", prev)
	})
	if err := os.Setenv("APS_GRID_UPNP_ENABLE", "false"); err != nil {
		t.Fatalf("setenv failed: %v", err)
	}
	if isGridUPnPEnabled() {
		t.Fatal("expected UPnP to be disabled when explicitly set false")
	}
}
