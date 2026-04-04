package main

import "testing"

func cleanupGridRuntimeForTest() {
	if current := GetGlobalGridRuntime(); current != nil {
		_ = current.Close()
	}
	SetGlobalGridRuntime(nil)
}

func makeStandaloneGridConfig(t *testing.T) *Config {
	t.Helper()
	enabled := true
	cfg := &Config{
		Grid: &GridConfig{
			Deployment: &GridDeploymentConfig{
				Enabled:    &enabled,
				Mode:       GridDeploymentModeStandalone,
				SQLitePath: ":memory:",
			},
		},
	}
	if err := ensureGridConfigSettings(cfg); err != nil {
		t.Fatalf("ensureGridConfigSettings failed: %v", err)
	}
	return cfg
}

func makeInvalidClusterGridConfig() *Config {
	enabled := true
	return &Config{
		Grid: &GridConfig{
			Deployment: &GridDeploymentConfig{
				Enabled: &enabled,
				Mode:    GridDeploymentModeCluster,
			},
		},
	}
}

func makeDisabledGridConfig() *Config {
	enabled := false
	return &Config{
		Grid: &GridConfig{
			Deployment: &GridDeploymentConfig{
				Enabled: &enabled,
				Mode:    GridDeploymentModeStandalone,
			},
		},
	}
}

func TestReconcileGlobalGridRuntimeModeSwitchFailureKeepsOldRuntime(t *testing.T) {
	cleanupGridRuntimeForTest()
	defer cleanupGridRuntimeForTest()

	if err := ReconcileGlobalGridRuntime(makeStandaloneGridConfig(t)); err != nil {
		t.Fatalf("init standalone runtime failed: %v", err)
	}
	oldRuntime := GetGlobalGridRuntime()
	if oldRuntime == nil {
		t.Fatal("expected runtime to be initialized")
	}

	err := ReconcileGlobalGridRuntime(makeInvalidClusterGridConfig())
	if err == nil {
		t.Fatal("expected reconcile to fail for invalid cluster config")
	}
	if GetGlobalGridRuntime() != oldRuntime {
		t.Fatal("expected old runtime to remain active after failed mode switch")
	}
}

func TestReconcileGlobalGridRuntimeDisableClearsRuntime(t *testing.T) {
	cleanupGridRuntimeForTest()
	defer cleanupGridRuntimeForTest()

	if err := ReconcileGlobalGridRuntime(makeStandaloneGridConfig(t)); err != nil {
		t.Fatalf("init standalone runtime failed: %v", err)
	}
	if GetGlobalGridRuntime() == nil {
		t.Fatal("expected runtime to be initialized")
	}

	if err := ReconcileGlobalGridRuntime(makeDisabledGridConfig()); err != nil {
		t.Fatalf("disable runtime failed: %v", err)
	}
	if GetGlobalGridRuntime() != nil {
		t.Fatal("expected runtime to be cleared when grid is disabled")
	}
}
