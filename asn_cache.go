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
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// BaiduIPResponse represents the response from Baidu Maps IP location API
type BaiduIPResponse struct {
	Status  int          `json:"status"`
	Address string       `json:"address"`
	Content BaiduContent `json:"content"`
}

type BaiduContent struct {
	Address string     `json:"address"`
	Point   BaiduPoint `json:"point"`
}

type BaiduPoint struct {
	X string `json:"x"` // Mercator X coordinate
	Y string `json:"y"` // Mercator Y coordinate
}

// IPGeolocation represents the complete response from Baidu Maps API
type IPGeolocation struct {
	IP           string        `json:"ip"`
	RIR          string        `json:"rir"`
	IsBogon      bool          `json:"is_bogon"`
	IsMobile     bool          `json:"is_mobile"`
	IsSatellite  bool          `json:"is_satellite"`
	IsCrawler    bool          `json:"is_crawler"`
	IsDatacenter bool          `json:"is_datacenter"`
	IsTor        bool          `json:"is_tor"`
	IsProxy      bool          `json:"is_proxy"`
	IsVPN        bool          `json:"is_vpn"`
	IsAbuser     bool          `json:"is_abuser"`
	Company      *CompanyInfo  `json:"company,omitempty"`
	Abuse        *AbuseInfo    `json:"abuse,omitempty"`
	ASN          *ASNInfo      `json:"asn,omitempty"`
	Location     *LocationInfo `json:"location,omitempty"`
	ElapsedMs    float64       `json:"elapsed_ms"`
}

// CompanyInfo contains company information for the IP
type CompanyInfo struct {
	Name        string `json:"name"`
	AbuserScore string `json:"abuser_score"`
	Domain      string `json:"domain"`
	Type        string `json:"type"`
	Network     string `json:"network"`
	Whois       string `json:"whois"`
}

// AbuseInfo contains abuse contact information
type AbuseInfo struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Email   string `json:"email"`
	Phone   string `json:"phone"`
}

// ASNInfo contains ASN information for the IP
type ASNInfo struct {
	ASN         int    `json:"asn"`
	AbuserScore string `json:"abuser_score"`
	Route       string `json:"route"`
	Descr       string `json:"descr"`
	Country     string `json:"country"`
	Active      bool   `json:"active"`
	Org         string `json:"org"`
	Domain      string `json:"domain"`
	Abuse       string `json:"abuse"`
	Type        string `json:"type"`
	Updated     string `json:"updated"`
	RIR         string `json:"rir"`
	Whois       string `json:"whois"`
}

// LocationInfo contains geographical location information
type LocationInfo struct {
	IsEUMember    bool    `json:"is_eu_member"`
	CallingCode   string  `json:"calling_code"`
	CurrencyCode  string  `json:"currency_code"`
	Continent     string  `json:"continent"`
	Country       string  `json:"country"`
	CountryCode   string  `json:"country_code"`
	State         string  `json:"state"`
	City          string  `json:"city"`
	Latitude      float64 `json:"latitude"`
	Longitude     float64 `json:"longitude"`
	Zip           string  `json:"zip"`
	Timezone      string  `json:"timezone"`
	LocalTime     string  `json:"local_time"`
	LocalTimeUnix int64   `json:"local_time_unix"`
	IsDST         bool    `json:"is_dst"`
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
		apiURL: "https://api.map.baidu.com/location/ip?ak=1CgrT8hhsdHdVYoUQeFyr6oA",
	}

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

	// 3. Query API
	DebugLog("[ASN] Cache miss for %s, querying API", ip)
	geo, err := c.queryAPI(ip)
	if err != nil {
		return nil, err
	}

	// Cache the result
	c.addToMemory(ip, geo)
	c.addToDatabase(ip, geo)

	return geo, nil
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

// queryAPI queries the Baidu Maps API for IP geolocation data
func (c *ASNCache) queryAPI(ip string) (*IPGeolocation, error) {
	// Rate limiting: wait at least 1 second between API calls
	c.apiMu.Lock()
	timeSinceLastCall := time.Since(c.lastAPICall)
	if timeSinceLastCall < time.Second {
		time.Sleep(time.Second - timeSinceLastCall)
	}
	c.lastAPICall = time.Now()
	c.apiMu.Unlock()

	url := fmt.Sprintf("%s&ip=%s", c.apiURL, ip)
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

	var baiduResp BaiduIPResponse
	if err := json.Unmarshal(body, &baiduResp); err != nil {
		return nil, fmt.Errorf("failed to parse API response: %v", err)
	}

	if baiduResp.Status != 0 {
		return nil, fmt.Errorf("Baidu API returned error status: %d", baiduResp.Status)
	}

	// Parse pipe-separated address: Country|Province|City|...
	// Format: US|Ohio|Franklin|None|None|100|0|0
	addressParts := strings.Split(baiduResp.Address, "|")
	var countryCode, province, city string
	if len(addressParts) >= 3 {
		countryCode = addressParts[0]
		province = addressParts[1]
		city = addressParts[2]
	}

	// Parse coordinates (no conversion needed per user's request)
	var lat, lng float64
	if baiduResp.Content.Point.Y != "" && baiduResp.Content.Point.X != "" {
		lat, _ = strconv.ParseFloat(baiduResp.Content.Point.Y, 64)
		lng, _ = strconv.ParseFloat(baiduResp.Content.Point.X, 64)
	}

	// Convert Baidu response to IPGeolocation structure
	geo := &IPGeolocation{
		IP: ip,
		Location: &LocationInfo{
			Country:     province, // Use province as country name for compatibility
			CountryCode: countryCode,
			State:       province,
			City:        city,
			Latitude:    lat,
			Longitude:   lng,
		},
	}

	DebugLog("[ASN] Retrieved geolocation for %s: %s-%s-%s (%.6f, %.6f)",
		ip, countryCode, province, city, lat, lng)
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
