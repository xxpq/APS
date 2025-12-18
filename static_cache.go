package main

import (
	"container/list"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	LastAccess      int64               `json:"last_access,omitempty"`      // 最后访问时间 (Unix timestamp)
	CreatedAt       int64               `json:"created_at,omitempty"`       // 创建时间 (Unix timestamp)
}

// CacheEntry 缓存条目，包含响应头和body（用于内存缓存）
type CacheEntry struct {
	CacheMetadata
	Body []byte `json:"body,omitempty"` // 仅用于内存缓存
}

// StaticCacheManager 管理静态文件缓存
type StaticCacheManager struct {
	cacheDir   string
	extensions map[string]bool
	mu         sync.RWMutex
	enabled    bool
	stopChan   chan struct{}

	// Policies
	memPolicy  ParsedCachePolicy
	diskPolicy ParsedCachePolicy

	// Memory Cache
	memCache *LRUCache
}

// ParsedCachePolicy 解析后的缓存策略
type ParsedCachePolicy struct {
	Alloc int64         // Max size in bytes
	File  int64         // Max single file size in bytes
	Count int           // Max count
	TTL   time.Duration // Idle timeout
	Life  time.Duration // Absolute lifetime
}

// LRUCache 简单的LRU缓存实现
type LRUCache struct {
	capacity  int
	maxSize   int64
	size      int64
	mu        sync.Mutex
	items     map[string]*list.Element
	evictList *list.List
}

type lruItem struct {
	key   string
	value *CacheEntry
	size  int64
}

func NewLRUCache(capacity int, maxSize int64) *LRUCache {
	return &LRUCache{
		capacity:  capacity,
		maxSize:   maxSize,
		items:     make(map[string]*list.Element),
		evictList: list.New(),
	}
}

func (c *LRUCache) Get(key string) (*CacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ent, ok := c.items[key]; ok {
		c.evictList.MoveToFront(ent)
		return ent.Value.(*lruItem).value, true
	}
	return nil, false
}

func (c *LRUCache) Add(key string, value *CacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Calculate size
	itemSize := int64(len(value.Body))

	// Check if update
	if ent, ok := c.items[key]; ok {
		c.evictList.MoveToFront(ent)
		oldItem := ent.Value.(*lruItem)
		c.size -= oldItem.size
		oldItem.value = value
		oldItem.size = itemSize
		c.size += itemSize
	} else {
		ent := c.evictList.PushFront(&lruItem{key, value, itemSize})
		c.items[key] = ent
		c.size += itemSize
	}

	// Evict if needed (count or size)
	for (c.capacity > 0 && c.evictList.Len() > c.capacity) || (c.maxSize > 0 && c.size > c.maxSize) {
		c.removeOldest()
	}
}

func (c *LRUCache) Remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ent, ok := c.items[key]; ok {
		c.removeElement(ent)
	}
}

func (c *LRUCache) removeOldest() {
	ent := c.evictList.Back()
	if ent != nil {
		c.removeElement(ent)
	}
}

func (c *LRUCache) removeElement(e *list.Element) {
	c.evictList.Remove(e)
	kv := e.Value.(*lruItem)
	delete(c.items, kv.key)
	c.size -= kv.size
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

	// Parse Policies
	memPolicy := parsePolicy(config.Mem, true)
	diskPolicy := parsePolicy(config.Disk, false)

	// 创建缓存目录
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		log.Printf("[CACHE] Failed to create cache directory %s: %v", cacheDir, err)
		return &StaticCacheManager{enabled: false}
	}

	// 构建扩展名映射
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
		if !strings.HasPrefix(ext, ".") {
			extensions["."+ext] = true
		} else {
			extensions[ext] = true
		}
	}

	manager := &StaticCacheManager{
		cacheDir:   cacheDir,
		extensions: extensions,
		enabled:    true,
		stopChan:   make(chan struct{}),
		memPolicy:  memPolicy,
		diskPolicy: diskPolicy,
		memCache:   NewLRUCache(memPolicy.Count, memPolicy.Alloc),
	}

	// 启动定期清理协程
	go manager.startCleanupRoutine()

	log.Printf("[CACHE] Initialized. Dir: %s. Mem: %+v. Disk: %+v", cacheDir, memPolicy, diskPolicy)
	return manager
}

func parsePolicy(p *CachePolicy, isMem bool) ParsedCachePolicy {
	pp := ParsedCachePolicy{}
	if p == nil {
		// Defaults
		if isMem {
			pp.TTL = 1 * time.Minute
			pp.Life = 5 * time.Minute
		} else {
			pp.TTL = 24 * time.Hour
			pp.Life = 3 * 24 * time.Hour
		}
		return pp
	}

	pp.Alloc, _ = parseCacheSize(p.Alloc)
	pp.File, _ = parseCacheSize(p.File)
	pp.Count = p.Count

	var err error
	pp.TTL, err = parseDuration(p.TTL)
	if err != nil {
		if isMem {
			pp.TTL = 1 * time.Minute
		} else {
			pp.TTL = 24 * time.Hour
		}
	}

	pp.Life, err = parseDuration(p.Life)
	if err != nil {
		if isMem {
			pp.Life = 5 * time.Minute
		} else {
			pp.Life = 3 * 24 * time.Hour
		}
	}

	return pp
}

func parseCacheSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "0" {
		return 0, nil
	}

	multiplier := int64(1)
	if strings.HasSuffix(s, "g") || strings.HasSuffix(s, "gb") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimRight(s, "gb")
	} else if strings.HasSuffix(s, "m") || strings.HasSuffix(s, "mb") {
		multiplier = 1024 * 1024
		s = strings.TrimRight(s, "mb")
	} else if strings.HasSuffix(s, "k") || strings.HasSuffix(s, "kb") {
		multiplier = 1024
		s = strings.TrimRight(s, "kb")
	}

	val, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return val * multiplier, nil
}

func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	// Support simple days 'd'
	if strings.HasSuffix(s, "d") {
		daysStr := strings.TrimSuffix(s, "d")
		days, err := strconv.Atoi(daysStr)
		if err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
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

	now := time.Now()

	// 1. Check Memory Cache
	if entry, ok := m.memCache.Get(fullURL); ok {
		// Check TTL (Idle timeout)
		if m.memPolicy.TTL > 0 && now.Sub(time.Unix(entry.LastAccess, 0)) > m.memPolicy.TTL {
			m.memCache.Remove(fullURL)
			return nil, false
		}
		// Check Life (Absolute timeout)
		if m.memPolicy.Life > 0 && now.Sub(time.Unix(entry.CreatedAt, 0)) > m.memPolicy.Life {
			m.memCache.Remove(fullURL)
			return nil, false
		}

		// Update LastAccess
		entry.LastAccess = now.Unix()
		return entry, true
	}

	// 2. Check Disk Cache
	cacheKey := m.GetCacheKey(fullURL)
	metaPath := m.GetCacheMetaPath(cacheKey)
	binPath := m.GetCacheBinPath(cacheKey)

	// Read metadata
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, false
	}

	var metadata CacheMetadata
	if err := json.Unmarshal(metaData, &metadata); err != nil {
		log.Printf("[CACHE] Failed to unmarshal cache metadata: %v", err)
		return nil, false
	}

	// Check Disk Expiration
	createdAt := time.Unix(metadata.CreatedAt, 0)
	lastAccess := time.Unix(metadata.LastAccess, 0)

	// Fallback for old cache files without CreatedAt/LastAccess
	if metadata.CreatedAt == 0 {
		info, err := os.Stat(metaPath)
		if err == nil {
			createdAt = info.ModTime()
			lastAccess = info.ModTime()
		}
	}

	// Check TTL
	if m.diskPolicy.TTL > 0 && now.Sub(lastAccess) > m.diskPolicy.TTL {
		// Lazy cleanup
		go func() {
			os.Remove(metaPath)
			os.Remove(binPath)
		}()
		return nil, false
	}

	// Check Life
	if m.diskPolicy.Life > 0 && now.Sub(createdAt) > m.diskPolicy.Life {
		go func() {
			os.Remove(metaPath)
			os.Remove(binPath)
		}()
		return nil, false
	}

	// Read body
	body, err := os.ReadFile(binPath)
	if err != nil {
		return nil, false
	}

	// Update LastAccess on disk (throttled)
	// Only update if more than 1 minute has passed to avoid excessive writes
	if now.Sub(lastAccess) > 1*time.Minute {
		metadata.LastAccess = now.Unix()
		go func() {
			newMeta, _ := json.Marshal(metadata)
			os.WriteFile(metaPath, newMeta, 0644)
		}()
	}

	entry := &CacheEntry{
		CacheMetadata: metadata,
		Body:          body,
	}

	// Add to Memory Cache
	// Check file size limit for memory
	if m.memPolicy.File == 0 || int64(len(body)) <= m.memPolicy.File {
		// Update memory specific timestamps
		entry.LastAccess = now.Unix()
		// Keep original CreatedAt
		m.memCache.Add(fullURL, entry)
	}

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
	// Check file size limit for memory
	if m.memPolicy.File == 0 || int64(len(entry.Body)) <= m.memPolicy.File {
		m.memCache.Add(fullURL, entry)
	}
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

		// Read metadata to check expiration
		metaData, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}

		var metadata CacheMetadata
		if err := json.Unmarshal(metaData, &metadata); err != nil {
			continue
		}

		createdAt := time.Unix(metadata.CreatedAt, 0)
		lastAccess := time.Unix(metadata.LastAccess, 0)

		// Fallback
		if metadata.CreatedAt == 0 {
			info, err := entry.Info()
			if err == nil {
				createdAt = info.ModTime()
				lastAccess = info.ModTime()
			}
		}

		shouldDelete := false

		// Check TTL
		if m.diskPolicy.TTL > 0 && now.Sub(lastAccess) > m.diskPolicy.TTL {
			shouldDelete = true
		}

		// Check Life
		if !shouldDelete && m.diskPolicy.Life > 0 && now.Sub(createdAt) > m.diskPolicy.Life {
			shouldDelete = true
		}

		if shouldDelete {
			// 删除.meta文件
			if err := os.Remove(metaPath); err != nil {
				log.Printf("[CACHE] Failed to delete expired meta file %s: %v", metaPath, err)
			} else {
				deletedCount++
			}

			// 删除对应的.bin文件
			binPath := strings.TrimSuffix(metaPath, ".meta") + ".bin"
			if err := os.Remove(binPath); err != nil {
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

// Refresh 刷新指定URL的缓存（删除）
func (m *StaticCacheManager) Refresh(fullURL string) error {
	if !m.enabled {
		return nil
	}

	// 1. Remove from Memory Cache
	m.memCache.Remove(fullURL)

	// 2. Remove from Disk Cache
	cacheKey := m.GetCacheKey(fullURL)
	metaPath := m.GetCacheMetaPath(cacheKey)
	binPath := m.GetCacheBinPath(cacheKey)

	var errs []string

	if err := os.Remove(metaPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Sprintf("failed to remove meta: %v", err))
	}
	if err := os.Remove(binPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Sprintf("failed to remove bin: %v", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("cache refresh errors: %s", strings.Join(errs, "; "))
	}

	DebugLog("[CACHE] Refreshed: %s", fullURL)
	return nil
}

// GetStats 获取缓存统计信息
func (m *StaticCacheManager) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["enabled"] = m.enabled

	if !m.enabled {
		return stats
	}

	stats["cache_dir"] = m.cacheDir
	stats["mem_policy"] = m.memPolicy
	stats["disk_policy"] = m.diskPolicy

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
