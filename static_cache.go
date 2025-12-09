package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CacheEntry 缓存条目，包含响应头和body
type CacheEntry struct {
	Headers    map[string][]string `json:"headers"`
	StatusCode int                 `json:"status_code"`
	Body       []byte              `json:"body"`
}

// StaticCacheManager 管理静态文件缓存
type StaticCacheManager struct {
	cacheDir   string
	ttl        time.Duration
	extensions map[string]bool
	mu         sync.RWMutex
	enabled    bool
	stopChan   chan struct{}
}

// 支持缓存的静态文件扩展名
var defaultCacheExtensions = []string{
	"css", "js", "jpg", "jpeg", "gif", "ico", "png", "bmp", "pict", "csv",
	"doc", "pdf", "pls", "ppt", "tif", "tiff", "eps", "ejs", "swf", "midi",
	"mida", "ttf", "eot", "woff", "otf", "svg", "svgz", "webp", "docx", "xlsx",
	"xls", "pptx", "ps", "class", "jar", "bz2", "bzip", "exe", "flv", "gzip",
	"rar", "rtf", "tgz", "gz", "txt", "zip", "mp3", "mp4", "ogg", "m4a",
	"m4v", "apk", "woff2",
}

// NewStaticCacheManager 创建新的静态缓存管理器
func NewStaticCacheManager(config *StaticCacheConfig) *StaticCacheManager {
	if config == nil || !config.Enabled {
		return &StaticCacheManager{enabled: false}
	}

	cacheDir := config.CacheDir
	if cacheDir == "" {
		cacheDir = "./cache"
	}

	ttl := time.Duration(config.TTL) * time.Second
	if ttl <= 0 {
		ttl = 24 * time.Hour // 默认1天
	}

	// 创建缓存目录
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		log.Printf("[CACHE] Failed to create cache directory %s: %v", cacheDir, err)
		return &StaticCacheManager{enabled: false}
	}

	// 构建扩展名映射
	extensions := make(map[string]bool)
	for _, ext := range defaultCacheExtensions {
		extensions["."+ext] = true
	}

	manager := &StaticCacheManager{
		cacheDir:   cacheDir,
		ttl:        ttl,
		extensions: extensions,
		enabled:    true,
		stopChan:   make(chan struct{}),
	}

	// 启动定期清理协程
	go manager.startCleanupRoutine()

	log.Printf("[CACHE] Static cache manager initialized: dir=%s, ttl=%v", cacheDir, ttl)
	return manager
}

// IsEnabled 返回缓存是否启用
func (m *StaticCacheManager) IsEnabled() bool {
	return m.enabled
}

// IsCacheable 检查URL路径是否可缓存
func (m *StaticCacheManager) IsCacheable(urlPath string) bool {
	if !m.enabled {
		return false
	}
	ext := strings.ToLower(filepath.Ext(urlPath))
	return m.extensions[ext]
}

// GetCacheKey 将URL转换为缓存文件名（使用MD5）
func (m *StaticCacheManager) GetCacheKey(fullURL string) string {
	hash := md5.Sum([]byte(fullURL))
	return hex.EncodeToString(hash[:])
}

// GetCachePath 获取缓存文件的完整路径
func (m *StaticCacheManager) GetCachePath(cacheKey string) string {
	return filepath.Join(m.cacheDir, cacheKey)
}

// Get 获取缓存内容
func (m *StaticCacheManager) Get(fullURL string) (*CacheEntry, bool) {
	if !m.enabled {
		return nil, false
	}

	cacheKey := m.GetCacheKey(fullURL)
	cachePath := m.GetCachePath(cacheKey)

	m.mu.RLock()
	defer m.mu.RUnlock()

	// 检查文件是否存在
	info, err := os.Stat(cachePath)
	if err != nil {
		return nil, false
	}

	// 检查是否过期
	if time.Since(info.ModTime()) > m.ttl {
		return nil, false
	}

	// 读取文件内容
	data, err := os.ReadFile(cachePath)
	if err != nil {
		log.Printf("[CACHE] Failed to read cache file %s: %v", cachePath, err)
		return nil, false
	}

	// 反序列化缓存条目
	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		log.Printf("[CACHE] Failed to unmarshal cache entry: %v", err)
		return nil, false
	}

	log.Printf("[CACHE] HIT: %s", fullURL)
	return &entry, true
}

// Set 保存缓存内容
func (m *StaticCacheManager) Set(fullURL string, headers http.Header, statusCode int, body []byte) error {
	if !m.enabled {
		return nil
	}

	cacheKey := m.GetCacheKey(fullURL)
	cachePath := m.GetCachePath(cacheKey)

	// 创建缓存条目
	entry := CacheEntry{
		Headers:    headers,
		StatusCode: statusCode,
		Body:       body,
	}

	// 序列化
	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("[CACHE] Failed to marshal cache entry: %v", err)
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.WriteFile(cachePath, data, 0644); err != nil {
		log.Printf("[CACHE] Failed to write cache file %s: %v", cachePath, err)
		return err
	}

	log.Printf("[CACHE] STORED: %s (%d bytes)", fullURL, len(body))
	return nil
}

// startCleanupRoutine 启动定期清理过期缓存的协程
func (m *StaticCacheManager) startCleanupRoutine() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.cleanupExpiredFiles()
		case <-m.stopChan:
			return
		}
	}
}

// cleanupExpiredFiles 清理过期的缓存文件
func (m *StaticCacheManager) cleanupExpiredFiles() {
	m.mu.Lock()
	defer m.mu.Unlock()

	entries, err := os.ReadDir(m.cacheDir)
	if err != nil {
		log.Printf("[CACHE] Failed to read cache directory: %v", err)
		return
	}

	now := time.Now()
	deletedCount := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(m.cacheDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		// 检查文件是否过期
		if now.Sub(info.ModTime()) > m.ttl {
			if err := os.Remove(filePath); err != nil {
				log.Printf("[CACHE] Failed to delete expired file %s: %v", filePath, err)
			} else {
				deletedCount++
			}
		}
	}

	if deletedCount > 0 {
		log.Printf("[CACHE] Cleanup completed: deleted %d expired files", deletedCount)
	}
}

// Stop 停止缓存管理器
func (m *StaticCacheManager) Stop() {
	if m.enabled && m.stopChan != nil {
		close(m.stopChan)
	}
}

// GetStats 获取缓存统计信息
func (m *StaticCacheManager) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["enabled"] = m.enabled

	if !m.enabled {
		return stats
	}

	stats["cache_dir"] = m.cacheDir
	stats["ttl_seconds"] = m.ttl.Seconds()

	// 统计缓存文件数量和大小
	var totalSize int64
	var fileCount int

	entries, err := os.ReadDir(m.cacheDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				if info, err := entry.Info(); err == nil {
					fileCount++
					totalSize += info.Size()
				}
			}
		}
	}

	stats["file_count"] = fileCount
	stats["total_size_bytes"] = totalSize
	stats["total_size_mb"] = float64(totalSize) / 1024 / 1024

	return stats
}
