package main

import (
	"log"
	"os"
	"time"
)

type ConfigWatcher struct {
	filename    string
	config      *Config
	lastModTime time.Time
	stopChan    chan struct{}
}

func NewConfigWatcher(filename string, config *Config) (*ConfigWatcher, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}

	return &ConfigWatcher{
		filename:    filename,
		config:      config,
		lastModTime: info.ModTime(),
		stopChan:    make(chan struct{}),
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

				if err := w.config.Reload(w.filename); err != nil {
					log.Printf("Error reloading config: %v", err)
				} else {
					log.Printf("Config reloaded successfully")
				}
			}

		case <-w.stopChan:
			log.Printf("Config file watcher stopped")
			return
		}
	}
}
