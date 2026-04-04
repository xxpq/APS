package main

import "sync"

var gridRuntimeRegistry = struct {
	mu      sync.RWMutex
	runtime *GridControlPlane
}{}

func SetGlobalGridRuntime(runtime *GridControlPlane) {
	gridRuntimeRegistry.mu.Lock()
	gridRuntimeRegistry.runtime = runtime
	gridRuntimeRegistry.mu.Unlock()
}

func GetGlobalGridRuntime() *GridControlPlane {
	gridRuntimeRegistry.mu.RLock()
	defer gridRuntimeRegistry.mu.RUnlock()
	return gridRuntimeRegistry.runtime
}

func UpdateGlobalGridRuntimeConfig(config *Config) {
	runtime := GetGlobalGridRuntime()
	if runtime == nil {
		return
	}
	runtime.UpdateConfig(config)
}

func ReconcileGlobalGridRuntime(config *Config) error {
	gridRuntimeRegistry.mu.Lock()
	defer gridRuntimeRegistry.mu.Unlock()

	enabled := isGridEnabled(config)
	current := gridRuntimeRegistry.runtime

	if !enabled {
		if current != nil {
			_ = current.Close()
			gridRuntimeRegistry.runtime = nil
		}
		return nil
	}

	targetMode := ""
	if config != nil && config.Grid != nil && config.Grid.Deployment != nil {
		targetMode = config.Grid.Deployment.Mode
	}

	if current == nil {
		newRuntime, err := NewGridControlPlaneFromConfig(config)
		if err != nil {
			return err
		}
		gridRuntimeRegistry.runtime = newRuntime
		return nil
	}

	if current.mode != targetMode {
		newRuntime, err := NewGridControlPlaneFromConfig(config)
		if err != nil {
			return err
		}
		oldRuntime := current
		gridRuntimeRegistry.runtime = newRuntime
		if err := oldRuntime.Close(); err != nil {
			DebugLog("[GRID] close old runtime failed: %v", err)
		}
		return nil
	}

	current.UpdateConfig(config)
	return nil
}
