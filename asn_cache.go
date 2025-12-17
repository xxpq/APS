package main

import (
	"container/list"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// IPAPIResponse represents the response from ip-api.com
type IPAPIResponse struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Query       string  `json:"query"`
}

// IPGeolocation represents the complete response from ip-api.com
type IPGeolocation struct {
	IP       string        `json:"ip"`
	Location *LocationInfo `json:"location,omitempty"`
}

// LocationInfo contains geographical location information
type LocationInfo struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	State       string  `json:"state"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

// cacheEntry represents an entry in the LRU cache
type cacheEntry struct {
	ip      string
	data    *IPGeolocation
	element *list.Element
}

// ASNCache manages IP geolocation data with three-tier caching
type ASNCache struct {
	// Memory cache (LRU, max 1000 entries)
	memoryCache map[string]*cacheEntry
	lruList     *list.List
	maxEntries  int
	mu          sync.RWMutex

	// Database cache
	db *sql.DB

	// HTTP client for API calls
	httpClient *http.Client
	apiURL     string

	// Rate limiting
	lastAPICall time.Time
	apiMu       sync.Mutex

	// Async lookup
	pendingLookups sync.Map    // map[string]bool
	lookupQueue    chan string // Queue for background lookups
}

var (
	globalASNCache *ASNCache
	cacheOnce      sync.Once
)

// GetASNCache returns the globally initialized ASN cache instance
// The cache is initialized in main() with the shared database connection
func GetASNCache() *ASNCache {
	return globalASNCache
}

// NewASNCache creates a new ASN cache with the provided database connection
func NewASNCache(db *sql.DB, maxEntries int) (*ASNCache, error) {
	cache := &ASNCache{
		memoryCache: make(map[string]*cacheEntry),
		lruList:     list.New(),
		maxEntries:  maxEntries,
		db:          db,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		apiURL:      "http://ip-api.com/json/",
		lookupQueue: make(chan string, 1000), // Buffer for pending lookups
	}

	// Start background worker
	go cache.backgroundWorker()

	if err := cache.initSchema(); err != nil {
		return nil, err
	}

	log.Printf("[ASN] Initialized ASN cache (max %d entries)", maxEntries)
	return cache, nil
}

func (c *ASNCache) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS ip_geolocation (
		ip TEXT PRIMARY KEY NOT NULL,
		data TEXT NOT NULL,
		latitude REAL,
		longitude REAL,
		timestamp INTEGER NOT NULL
	);
	`

	if _, err := c.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create ASN schema: %v", err)
	}

	return nil
}

// GetIPLocation retrieves location information for an IP address
// Uses three-tier lookup: memory → database → API
func GetIPLocation(ip string) (*LocationInfo, error) {
	cache := GetASNCache()

	// Extract IP from "ip:port" format if needed
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}

	// Validate IP
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Ignore private/loopback IPs
	parsedIP := net.ParseIP(ip)
	if parsedIP.IsLoopback() || parsedIP.IsPrivate() {
		return nil, fmt.Errorf("skipping private/loopback IP")
	}

	geo, err := cache.lookup(ip)
	if err != nil {
		return nil, err
	}

	if geo != nil && geo.Location != nil {
		return geo.Location, nil
	}

	return nil, fmt.Errorf("no location data available for IP: %s", ip)
}

// lookup performs the three-tier lookup
func (c *ASNCache) lookup(ip string) (*IPGeolocation, error) {
	// 1. Check memory cache
	if geo := c.getFromMemory(ip); geo != nil {
		DebugLog("[ASN] Memory cache hit for %s", ip)
		return geo, nil
	}

	// 2. Check database cache
	if geo := c.getFromDatabase(ip); geo != nil {
		DebugLog("[ASN] Database cache hit for %s", ip)
		// Add to memory cache
		c.addToMemory(ip, geo)
		return geo, nil
	}

	// 3. Async API Lookup
	// If not in cache, trigger background lookup and return nil immediately
	if _, pending := c.pendingLookups.Load(ip); !pending {
		c.pendingLookups.Store(ip, true)
		select {
		case c.lookupQueue <- ip:
			DebugLog("[ASN] Triggered background lookup for %s", ip)
		default:
			c.pendingLookups.Delete(ip)
			DebugLog("[ASN] Lookup queue full, skipping %s", ip)
		}
	}

	return nil, nil
}

// backgroundWorker processes IPs from the lookup queue
func (c *ASNCache) backgroundWorker() {
	for ip := range c.lookupQueue {
		go c.processIP(ip)
	}
}

// processIP handles the lookup retry logic for a single IP
func (c *ASNCache) processIP(ip string) {
	defer c.pendingLookups.Delete(ip)

	for {
		// Query API
		geo, err := c.queryAPI(ip)
		if err == nil && geo != nil {
			// Success: Cache and return
			c.addToMemory(ip, geo)
			c.addToDatabase(ip, geo)
			DebugLog("[ASN] Background lookup success for %s", ip)
			return
		}

		// Failure: Log and retry after delay
		DebugLog("[ASN] Background lookup failed for %s: %v. Retrying in 1s...", ip, err)
		time.Sleep(1 * time.Second)
	}
}

// getFromMemory retrieves an entry from the memory cache
func (c *ASNCache) getFromMemory(ip string) *IPGeolocation {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if entry, ok := c.memoryCache[ip]; ok {
		// Move to front (most recently used)
		c.lruList.MoveToFront(entry.element)
		return entry.data
	}

	return nil
}

// addToMemory adds an entry to the memory cache with LRU eviction
func (c *ASNCache) addToMemory(ip string, geo *IPGeolocation) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If already exists, update and move to front
	if entry, ok := c.memoryCache[ip]; ok {
		entry.data = geo
		c.lruList.MoveToFront(entry.element)
		return
	}

	// Evict oldest entry if cache is full
	if c.lruList.Len() >= c.maxEntries {
		oldest := c.lruList.Back()
		if oldest != nil {
			oldEntry := oldest.Value.(*cacheEntry)
			delete(c.memoryCache, oldEntry.ip)
			c.lruList.Remove(oldest)
			DebugLog("[ASN] Evicted %s from memory cache (LRU)", oldEntry.ip)
		}
	}

	// Add new entry
	entry := &cacheEntry{
		ip:   ip,
		data: geo,
	}
	entry.element = c.lruList.PushFront(entry)
	c.memoryCache[ip] = entry
}

// getFromDatabase retrieves an entry from the database cache
func (c *ASNCache) getFromDatabase(ip string) *IPGeolocation {
	if c.db == nil {
		return nil
	}

	var dataJSON string
	var timestamp int64

	err := c.db.QueryRow("SELECT data, timestamp FROM ip_geolocation WHERE ip = ?", ip).Scan(&dataJSON, &timestamp)
	if err != nil {
		if err != sql.ErrNoRows {
			DebugLog("[ASN] Database query error for %s: %v", ip, err)
		}
		return nil
	}

	var geo IPGeolocation
	if err := json.Unmarshal([]byte(dataJSON), &geo); err != nil {
		log.Printf("[ASN] Failed to unmarshal data for %s: %v", ip, err)
		return nil
	}

	return &geo
}

// addToDatabase adds an entry to the database cache
func (c *ASNCache) addToDatabase(ip string, geo *IPGeolocation) {
	if c.db == nil {
		return
	}

	dataJSON, err := json.Marshal(geo)
	if err != nil {
		log.Printf("[ASN] Failed to marshal data for %s: %v", ip, err)
		return
	}

	// Extract lat/lng for indexing
	var lat, lng float64
	if geo.Location != nil {
		lat = geo.Location.Latitude
		lng = geo.Location.Longitude
	}

	_, err = c.db.Exec(`
		INSERT OR REPLACE INTO ip_geolocation (ip, data, latitude, longitude, timestamp)
		VALUES (?, ?, ?, ?, ?)
	`, ip, string(dataJSON), lat, lng, time.Now().Unix())

	if err != nil {
		log.Printf("[ASN] Failed to insert data for %s: %v", ip, err)
	}
}

// queryAPI queries the ip-api.com API for IP geolocation data
func (c *ASNCache) queryAPI(ip string) (*IPGeolocation, error) {
	// Rate limiting: wait at least 1 second between API calls
	c.apiMu.Lock()
	timeSinceLastCall := time.Since(c.lastAPICall)
	if timeSinceLastCall < time.Second {
		time.Sleep(time.Second - timeSinceLastCall)
	}
	c.lastAPICall = time.Now()
	c.apiMu.Unlock()

	url := fmt.Sprintf("%s%s", c.apiURL, ip)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read API response: %v", err)
	}

	var apiResp IPAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse API response: %v", err)
	}

	if apiResp.Status != "success" {
		return nil, fmt.Errorf("API returned error status: %s", apiResp.Status)
	}

	geo := &IPGeolocation{
		IP: ip,
		Location: &LocationInfo{
			Country:     apiResp.Country,
			CountryCode: apiResp.CountryCode,
			State:       apiResp.RegionName,
			City:        apiResp.City,
			Latitude:    apiResp.Lat,
			Longitude:   apiResp.Lon,
		},
	}

	DebugLog("[ASN] Retrieved geolocation for %s: %s-%s-%s (%.6f, %.6f)",
		ip, apiResp.Country, apiResp.RegionName, apiResp.City, apiResp.Lat, apiResp.Lon)
	return geo, nil
}

// Close is a no-op as the database connection is managed externally
func (c *ASNCache) Close() error {
	// Database is closed in main.go
	return nil
}

// CleanupOldEntries removes database entries older than the specified duration
func (c *ASNCache) CleanupOldEntries(maxAge time.Duration) error {
	if c.db == nil {
		return nil
	}

	cutoff := time.Now().Add(-maxAge).Unix()
	result, err := c.db.Exec("DELETE FROM ip_geolocation WHERE timestamp < ?", cutoff)
	if err != nil {
		return fmt.Errorf("failed to cleanup old entries: %v", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		log.Printf("[ASN] Cleaned up %d old geolocation entries", rowsAffected)
	}

	return nil
}
