package main

import (
	"log"
	"sync"
)

type HarLoggerManager struct {
	loggers map[string]*HarLogger
	entryCh chan harEntryJob
	wg      sync.WaitGroup
	mu      sync.Mutex
	config  *Config
}

type harEntryJob struct {
	entry    HarEntry
	dumpPath string
}

func NewHarLoggerManager(config *Config) *HarLoggerManager {
	manager := &HarLoggerManager{
		loggers: make(map[string]*HarLogger),
		entryCh: make(chan harEntryJob, 100), // Buffered channel
		config:  config,
	}
	manager.wg.Add(1)
	go manager.processEntries()
	return manager
}

func (m *HarLoggerManager) processEntries() {
	defer m.wg.Done()
	for job := range m.entryCh {
		m.mu.Lock()
		logger, exists := m.loggers[job.dumpPath]
		if !exists {
			logger = NewHarLogger()
			m.loggers[job.dumpPath] = logger
			log.Printf("[HAR DUMP] Initialized new HAR logger for: %s", job.dumpPath)
		}
		m.mu.Unlock()
		logger.AddEntry(job.entry)
	}
}

func (m *HarLoggerManager) LogEntry(entry HarEntry, serverName string, mapping *Mapping, user *User) {
	dumpPath := m.findDumpPath(serverName, mapping, user)
	if dumpPath != "" {
		m.entryCh <- harEntryJob{entry: entry, dumpPath: dumpPath}
	}
}

func (m *HarLoggerManager) findDumpPath(serverName string, mapping *Mapping, user *User) string {
	// 优先级: mapping > user > group > server
	if mapping != nil && mapping.Dump != "" {
		return mapping.Dump
	}

	if user != nil {
		if user.Dump != "" {
			return user.Dump
		}
		// 检查用户所属的组
		if m.config.Auth != nil && m.config.Auth.Groups != nil {
			for _, groupName := range user.Groups {
				if group, ok := m.config.Auth.Groups[groupName]; ok {
					if group.Dump != "" {
						return group.Dump
					}
				}
			}
		}
	}

	if serverConfig, ok := m.config.Servers[serverName]; ok {
		if serverConfig.Dump != "" {
			return serverConfig.Dump
		}
	}

	return ""
}

func (m *HarLoggerManager) Shutdown() {
	close(m.entryCh)
	m.wg.Wait() // 等待所有条目处理完毕

	m.mu.Lock()
	defer m.mu.Unlock()
	for path, logger := range m.loggers {
		logger.SaveToFile(path)
	}
	log.Println("[HAR DUMP] All HAR logs saved.")
}