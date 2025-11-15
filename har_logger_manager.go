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
			logger = NewHarLogger(job.dumpPath)
			m.loggers[job.dumpPath] = logger
		}
		m.mu.Unlock()
		logger.AddEntry(job.entry)
	}
}

func (m *HarLoggerManager) LogEntry(entry HarEntry, serverName string, mapping *Mapping, user *User) {
	dumpPaths := m.findDumpPaths(serverName, mapping, user)
	for _, path := range dumpPaths {
		if path != "" {
			m.entryCh <- harEntryJob{entry: entry, dumpPath: path}
		}
	}
}

func (m *HarLoggerManager) findDumpPaths(serverName string, mapping *Mapping, user *User) []string {
	paths := make(map[string]struct{}) // 使用 map 来自动去重

	// 检查所有层级并收集 dump 路径
	if mapping != nil && mapping.Dump != "" {
		paths[mapping.Dump] = struct{}{}
	}

	if user != nil {
		if user.Dump != "" {
			paths[user.Dump] = struct{}{}
		}
		// 检查用户所属的组
		if m.config.Auth != nil && m.config.Auth.Groups != nil {
			for _, groupName := range user.Groups {
				if group, ok := m.config.Auth.Groups[groupName]; ok {
					if group.Dump != "" {
						paths[group.Dump] = struct{}{}
					}
				}
			}
		}
	}

	if serverConfig, ok := m.config.Servers[serverName]; ok {
		if serverConfig.Dump != "" {
			paths[serverConfig.Dump] = struct{}{}
		}
	}

	// 将 map 的键转换为切片
	result := make([]string, 0, len(paths))
	for path := range paths {
		result = append(result, path)
	}
	return result
}

func (m *HarLoggerManager) Shutdown() {
	close(m.entryCh)
	m.wg.Wait() // 等待所有条目处理完毕

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, logger := range m.loggers {
		logger.SaveToFile()
	}
	log.Println("[HAR DUMP] All HAR logs saved.")
}