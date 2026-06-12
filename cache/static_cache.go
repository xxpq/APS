package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"
)

// CacheMetadata 缓存元数据，存储在.meta文件中
type CacheMetadata struct {
	Headers         map[string][]string `json:"headers"`
	StatusCode      int                 `json:"status_code"`
	IsCompressed    bool                `json:"is_compressed,omitempty"`    // body是否已压缩
	CompressionType string              `json:"compression_type,omitempty"` // 压缩类型: "br", "gzip", "deflate", "" (未压缩)
	ETag            string              `json:"etag,omitempty"`             // ETag缓存标识
	LastModified    string              `json:"last_modified,omitempty"`    // 最后修改时间
	ContentType     string              `json:"content_type,omitempty"`     // Content-Type
}

// CacheEntry 缓存条目，包含响应头和body（用于内存缓存）
type CacheEntry struct {
	CacheMetadata
	Body []byte `json:"body,omitempty"` // 仅用于内存缓存
}

// StaticCacheManager 管理静态文件缓存
type StaticCacheManager struct {
	cacheDir      string
	ttl           time.Duration
	extensions    map[string]bool
	mu            sync.RWMutex
	enabled       bool
	stopChan      chan struct{}
	memCache      sync.Map // 内存热缓存: URL -> *memCacheEntry
	memEntryCount int64    // 当前内存缓存条目数（原子操作）
	maxMemEntries int      // 内存缓存最大条目数
}

// memCacheEntry 内存缓存条目（包含过期时间）
type memCacheEntry struct {
	entry     *CacheEntry
	expiresAt time.Time
}

// 支持缓存的静态文件扩展名
var defaultCacheExtensions = []string{
	".css", ".js", ".jpg", ".jpeg", ".gif", ".ico", ".png", ".bmp", ".pict", ".csv",
	".doc", ".pdf", ".pls", ".ppt", ".tif", ".tiff", ".eps", ".ejs", ".swf", ".midi",
	".mida", ".ttf", ".eot", ".woff", ".otf", ".svg", ".svgz", ".webp", ".docx", ".xlsx",
	".xls", ".pptx", ".ps", ".class", ".jar", ".bz2", ".bzip", ".exe", ".flv", ".gzip",
	".rar", ".rtf", ".tgz", ".gz", ".txt", ".zip", ".mp3", ".mp4", ".ogg", ".m4a",
	".m4v", ".apk", ".woff2",
}

// NewStaticCacheManager 创建新的静态缓存管理器
func NewStaticCacheManager(config *StaticCacheConfig) *StaticCacheManager {
	if config == nil || !config.Enabled {
		return &StaticCacheManager{enabled: false}
	}

	cacheDir := config.CacheDir
	if cacheDir == "" {
		cacheDir = ".cache"
	}

	// 创建缓存目录
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		log.Printf("[CACHE] Failed to create cache directory %s: %v", cacheDir, err)
		return &StaticCacheManager{enabled: false}
	}

	// 构建扩展名映射
	// 如果配置了 FileType，使用配置的；否则使用默认值
	extensions := make(map[string]bool)
	var extList []string
	if len(config.FileType) > 0 {
		extList = config.FileType
		log.Printf("[CACHE] Using custom file types from config: %v", extList)
	} else {
		extList = defaultCacheExtensions
		log.Printf("[CACHE] Using default file types (%d extensions)", len(extList))
	}
	for _, ext := range extList {
		// 确保扩展名以点开头
		if !strings.HasPrefix(ext, ".") {
			extensions["."+ext] = true
		} else {
			extensions[ext] = true
		}
	}

	manager := &StaticCacheManager{
		cacheDir:      cacheDir,
		ttl:           24 * time.Hour,
		extensions:    extensions,
		enabled:       true,
		stopChan:      make(chan struct{}),
		maxMemEntries: 1000, // 默认最多 1000 个内存缓存条目
	}

	// 启动定期清理协程
	go manager.startCleanupRoutine()

	log.Printf("[CACHE] Static cache manager initialized: dir=%s, ttl=%v", cacheDir, manager.ttl)
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

// GetCacheMetaPath 获取缓存元数据文件路径
func (m *StaticCacheManager) GetCacheMetaPath(cacheKey string) string {
	return filepath.Join(m.cacheDir, cacheKey+".meta")
}

// GetCacheBinPath 获取缓存内容文件路径
func (m *StaticCacheManager) GetCacheBinPath(cacheKey string) string {
	return filepath.Join(m.cacheDir, cacheKey+".bin")
}

// Get 获取缓存内容（优先从内存热缓存获取）
func (m *StaticCacheManager) Get(fullURL string) (*CacheEntry, bool) {
	if !m.enabled {
		return nil, false
	}

	// 优先检查内存热缓存
	if cached, ok := m.memCache.Load(fullURL); ok {
		memEntry := cached.(*memCacheEntry)
		if time.Now().Before(memEntry.expiresAt) {
			return memEntry.entry, true
		}
		// 过期则从内存中删除
		m.memCache.Delete(fullURL)
		atomic.AddInt64(&m.memEntryCount, -1)
	}

	// 内存未命中，从磁盘读取
	cacheKey := m.GetCacheKey(fullURL)
	metaPath := m.GetCacheMetaPath(cacheKey)
	binPath := m.GetCacheBinPath(cacheKey)

	m.mu.RLock()
	defer m.mu.RUnlock()

	// 检查元数据文件是否存在
	metaInfo, err := os.Stat(metaPath)
	if err != nil {
		return nil, false
	}

	// 检查是否过期
	if time.Since(metaInfo.ModTime()) > m.ttl {
		return nil, false
	}

	// 读取元数据
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		log.Printf("[CACHE] Failed to read cache meta file %s: %v", metaPath, err)
		return nil, false
	}

	// 反序列化元数据
	var metadata CacheMetadata
	if err := json.Unmarshal(metaData, &metadata); err != nil {
		log.Printf("[CACHE] Failed to unmarshal cache metadata: %v", err)
		return nil, false
	}

	// 读取body内容
	body, err := os.ReadFile(binPath)
	if err != nil {
		log.Printf("[CACHE] Failed to read cache bin file %s: %v", binPath, err)
		return nil, false
	}

	// 创建完整的缓存条目
	entry := &CacheEntry{
		CacheMetadata: metadata,
		Body:          body,
	}

	// 磁盘命中后写入内存热缓存
	m.addToMemCache(fullURL, entry)

	return entry, true
}

// Set 保存缓存内容（同时写入内存和磁盘，异步Brotli压缩）
// originalEncoding: 原始上游的Content-Encoding，如"gzip", "br", "deflate"等，空字符串表示未压缩
func (m *StaticCacheManager) Set(fullURL string, headers http.Header, statusCode int, body []byte, originalEncoding string) error {
	if !m.enabled {
		return nil
	}

	// Don't cache empty bodies to prevent "0 bytes" issues
	if len(body) == 0 {
		return nil
	}

	// 生成 ETag (基于内容的MD5哈希)
	hash := md5.Sum(body)
	etag := fmt.Sprintf(`W/"%s"`, hex.EncodeToString(hash[:]))

	// 生成 Last-Modified
	lastModified := time.Now().UTC().Format(http.TimeFormat)

	// 提取 Content-Type
	contentType := headers.Get("Content-Type")

	// 判断是否有原始压缩
	hasOriginalCompression := originalEncoding != ""

	// 创建未压缩的缓存条目（立即写入内存供即时使用）
	// 注意：如果有原始压缩，body实际是压缩的，但为了即时使用我们仍然存入内存
	uncompressedEntry := &CacheEntry{
		CacheMetadata: CacheMetadata{
			Headers:         headers,
			StatusCode:      statusCode,
			IsCompressed:    hasOriginalCompression,
			CompressionType: originalEncoding,
			ETag:            etag,
			LastModified:    lastModified,
			ContentType:     contentType,
		},
		Body: body,
	}

	// 立即写入内存热缓存
	m.addToMemCache(fullURL, uncompressedEntry)

	// 异步写入磁盘
	go func() {
		var diskBody []byte
		var compressionType string
		var isCompressed bool

		if hasOriginalCompression {
			// 保留原始压缩，直接存储
			diskBody = body
			compressionType = originalEncoding
			isCompressed = true
			DebugLog("[CACHE] Preserving original %s compression: %s (%d bytes)",
				originalEncoding, fullURL, len(body))
		} else {
			// 没有原始压缩，尝试Brotli压缩
			originalSize := len(body)

			// Brotli 压缩
			compressedBody, err := compressWithBrotli(body)
			if err != nil {
				log.Printf("[CACHE] Failed to compress with brotli: %v", err)
				compressedBody = body // 压缩失败使用原始数据
			}

			// 判断压缩是否有效（压缩后至少节省10%空间，且不为空）
			useCompression := err == nil && len(compressedBody) > 0 && len(compressedBody) < originalSize*9/10

			if useCompression {
				diskBody = compressedBody
				compressionType = "br"
				isCompressed = true
				DebugLog("[CACHE] Compressed with br: %s (%d -> %d bytes, %.1f%%)",
					fullURL, originalSize, len(compressedBody),
					float64(len(compressedBody))/float64(originalSize)*100)
			} else {
				diskBody = body
				compressionType = ""
				isCompressed = false
			}
		}

		// 创建元数据
		metadata := CacheMetadata{
			Headers:         headers,
			StatusCode:      statusCode,
			ETag:            etag,
			LastModified:    lastModified,
			ContentType:     contentType,
			IsCompressed:    isCompressed,
			CompressionType: compressionType,
		}

		// 创建带Body的条目用于更新内存缓存
		entry := &CacheEntry{
			CacheMetadata: metadata,
			Body:          diskBody,
		}

		// 更新内存热缓存
		m.addToMemCache(fullURL, entry)

		// 获取缓存文件路径
		cacheKey := m.GetCacheKey(fullURL)
		metaPath := m.GetCacheMetaPath(cacheKey)
		binPath := m.GetCacheBinPath(cacheKey)

		// 序列化元数据
		metaData, err := json.Marshal(metadata)
		if err != nil {
			log.Printf("[CACHE] Failed to marshal cache metadata: %v", err)
			return
		}

		m.mu.Lock()
		defer m.mu.Unlock()

		// 写入元数据文件
		if err := os.WriteFile(metaPath, metaData, 0644); err != nil {
			log.Printf("[CACHE] Failed to write cache meta file %s: %v", metaPath, err)
			return
		}

		// 写入body文件
		if err := os.WriteFile(binPath, diskBody, 0644); err != nil {
			log.Printf("[CACHE] Failed to write cache bin file %s: %v", binPath, err)
			// 删除已写入的meta文件
			os.Remove(metaPath)
			return
		}

		DebugLog("[CACHE] STORED: %s (%d bytes, compressed=%v, type=%s)", fullURL, len(diskBody), isCompressed, compressionType)
	}()

	return nil
}

// compressWithBrotli 使用Brotli压缩数据
func compressWithBrotli(data []byte) ([]byte, error) {
	buf := getBuffer()
	defer putBuffer(buf)

	writer := brotli.NewWriterLevel(buf, brotli.DefaultCompression)
	if _, err := writer.Write(data); err != nil {
		writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	// 复制结果（因为buffer会被归还到池中）
	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// addToMemCache 添加条目到内存热缓存
func (m *StaticCacheManager) addToMemCache(fullURL string, entry *CacheEntry) {
	// 检查是否超过最大条目数限制
	currentCount := atomic.LoadInt64(&m.memEntryCount)
	if currentCount >= int64(m.maxMemEntries) {
		// 简单随机淘汰策略：删除遇到的第一个条目
		m.memCache.Range(func(key, value interface{}) bool {
			m.memCache.Delete(key)
			atomic.AddInt64(&m.memEntryCount, -1)
			return false // 只删除一个
		})
	}

	// 存储新条目
	m.memCache.Store(fullURL, &memCacheEntry{
		entry:     entry,
		expiresAt: time.Now().Add(m.ttl),
	})
	atomic.AddInt64(&m.memEntryCount, 1)
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

		fileName := entry.Name()

		// 只处理.meta文件，删除时同时删除对应的.bin文件
		if !strings.HasSuffix(fileName, ".meta") {
			continue
		}

		metaPath := filepath.Join(m.cacheDir, fileName)
		info, err := entry.Info()
		if err != nil {
			continue
		}

		// 检查文件是否过期
		if now.Sub(info.ModTime()) > m.ttl {
			// 删除.meta文件
			if err := os.Remove(metaPath); err != nil {
				log.Printf("[CACHE] Failed to delete expired meta file %s: %v", metaPath, err)
			} else {
				deletedCount++
			}

			// 删除对应的.bin文件
			binPath := strings.TrimSuffix(metaPath, ".meta") + ".bin"
			if err := os.Remove(binPath); err != nil {
				// bin文件可能已经不存在，不记录错误
				DebugLog("[CACHE] Failed to delete corresponding bin file %s: %v", binPath, err)
			}
		}
	}

	if deletedCount > 0 {
		DebugLog("[CACHE] Cleanup completed: deleted %d expired cache entries", deletedCount)
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
