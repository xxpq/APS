package main

import (
	"log"
	"os"
	"reflect"
	"time"
)

type ConfigWatcher struct {
	filename      string
	config        *Config
	lastModTime   time.Time
	stopChan      chan struct{}
	serverManager *ServerManager
}

func NewConfigWatcher(filename string, config *Config, serverManager *ServerManager) (*ConfigWatcher, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}

	return &ConfigWatcher{
		filename:      filename,
		config:        config,
		lastModTime:   info.ModTime(),
		stopChan:      make(chan struct{}),
		serverManager: serverManager,
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

	log.Printf("Config file watcher started for: %s", w.filename)

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
					log.Printf("Config reloaded successfully, synchronizing servers...")
					w.syncServers(oldServers, w.config.Servers)
				}
			}

		case <-w.stopChan:
			log.Printf("Config file watcher stopped")
			return
		}
	}
}

func (w *ConfigWatcher) syncServers(oldServers, newServers map[string]*ListenConfig) {
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
			w.serverManager.Start(name, newConfig)
		} else {
			// Server exists, check if it was modified
			if !reflect.DeepEqual(oldConfig, newConfig) {
				log.Printf("Server '%s' configuration changed, restarting...", name)
				w.serverManager.Stop(name)
				// A small delay might be useful to ensure the port is released
				time.Sleep(100 * time.Millisecond)
				w.serverManager.Start(name, newConfig)
			}
		}
	}
}