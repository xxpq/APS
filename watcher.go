package main

import (
	"log"
	"os"
	"reflect"
	"time"
)

type ConfigWatcher struct {
	filename          string
	config            *Config
	lastModTime       time.Time
	stopChan          chan struct{}
	serverManager     *ServerManager
	lastTunnelBinding map[string]bool
}

func NewConfigWatcher(filename string, config *Config, serverManager *ServerManager) (*ConfigWatcher, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}

	// 初始化每个 server 是否绑定了隧道的状态，用于后续变更检测与重启（/.tunnel 注册）
	binding := make(map[string]bool)
	if config != nil && config.Tunnels != nil {
		for _, t := range config.Tunnels {
			for _, sName := range t.Servers {
				binding[sName] = true
			}
		}
	}

	return &ConfigWatcher{
		filename:          filename,
		config:            config,
		lastModTime:       info.ModTime(),
		stopChan:          make(chan struct{}),
		serverManager:     serverManager,
		lastTunnelBinding: binding,
	}, nil
}

func (w *ConfigWatcher) Start() {
	go w.watch()
}

func (w *ConfigWatcher) Stop() {
	close(w.stopChan)
}

func (w *ConfigWatcher) watch() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	DebugLog("Config file watcher started for: %s", w.filename)

	for {
		select {
		case <-ticker.C:
			info, err := os.Stat(w.filename)
			if err != nil {
				log.Printf("Error checking config file: %v", err)
				continue
			}

			if info.ModTime().After(w.lastModTime) {
				log.Printf("Config file changed, reloading...")
				w.lastModTime = info.ModTime()

				oldServers, err := w.config.Reload(w.filename)
				if err != nil {
					log.Printf("Error reloading config: %v", err)
				} else {
					DebugLog("Config reloaded successfully, synchronizing servers...")

					// Update tunnel manager with new tunnel configurations
					if w.serverManager != nil && w.serverManager.tunnelManager != nil {
						DebugLog("Notifying TunnelManager of configuration changes...")
						w.serverManager.tunnelManager.UpdateTunnels(w.config)
					}

					// Re-initialize ACME with the new config
					InitACME(w.config)

					// Check if ACME is needed with the new config
					isACMEEnabled := false
					for _, serverConfig := range w.config.Servers {
						if certStr, ok := serverConfig.Cert.(string); ok && certStr == "acme" {
							isACMEEnabled = true
							break
						}
					}

					w.syncServers(oldServers, w.config.Servers, isACMEEnabled)

					// 重新计算每个 server 是否绑定了隧道；若绑定状态发生变化，则重启该 server
					// 以便让 createServerHandler() 重新注册或移除 '/.tunnel' 端点
					newBinding := make(map[string]bool)
					if w.config.Tunnels != nil {
						for _, t := range w.config.Tunnels {
							for _, sName := range t.Servers {
								newBinding[sName] = true
							}
						}
					}
					for name := range w.config.Servers {
						oldHas := w.lastTunnelBinding[name]
						newHas := newBinding[name]
						if oldHas != newHas {
							log.Printf("Tunnel binding changed for server '%s' (old=%v, new=%v). Restarting to re-register handlers...", name, oldHas, newHas)
							w.serverManager.Stop(name)
							// 确保端口释放
							time.Sleep(100 * time.Millisecond)
							w.serverManager.Start(name, w.config.Servers[name], isACMEEnabled)
						}
					}
					w.lastTunnelBinding = newBinding
				}
			}

		case <-w.stopChan:
			DebugLog("Config file watcher stopped")
			return
		}
	}
}

func (w *ConfigWatcher) syncServers(oldServers, newServers map[string]*ListenConfig, isACMEEnabled bool) {
	// Stop servers that are in the old config but not in the new one
	for name := range oldServers {
		if _, exists := newServers[name]; !exists {
			log.Printf("Server '%s' removed from config, stopping...", name)
			w.serverManager.Stop(name)
		}
	}

	// Start new servers or restart modified ones
	for name, newConfig := range newServers {
		if oldConfig, exists := oldServers[name]; !exists {
			// This is a new server
			log.Printf("New server '%s' found in config, starting...", name)
			w.serverManager.Start(name, newConfig, isACMEEnabled)
		} else {
			// Server exists, check if it was modified
			if !reflect.DeepEqual(oldConfig, newConfig) {
				log.Printf("Server '%s' configuration changed, restarting...", name)
				// Debug: Show what changed
				if oldConfig.Type != newConfig.Type {
					log.Printf("  [DEBUG] %s Type changed: %d -> %d", name, oldConfig.Type, newConfig.Type)
				}
				if oldConfig.Port != newConfig.Port {
					log.Printf("  [DEBUG] %s Port changed: %d -> %d", name, oldConfig.Port, newConfig.Port)
				}
				w.serverManager.Stop(name)
				// A small delay might be useful to ensure the port is released
				time.Sleep(100 * time.Millisecond)
				w.serverManager.Start(name, newConfig, isACMEEnabled)
			} else {
				log.Printf("[DEBUG] Server '%s' config unchanged (Type: %d, Port: %d)", name, newConfig.Type, newConfig.Port)
			}
		}
	}

	// Update mappings for all rawTCP servers (hot reload without restart)
	log.Printf("Updating mappings for all rawTCP servers...")
	w.serverManager.UpdateRawTCPMappings()
}
