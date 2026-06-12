package main

import (
	"aps/charts"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"aps/asn"
	"aps/firewall"
	"aps/logging"
	"aps/security"
	"aps/stats"
)

const apsTLSPinTokenPrefix = "apspt1."

// AuthHandlers contains the HTTP handlers for authentication management
type AuthHandlers struct{}

// RegisterHandlers registers the auth handlers to the given ServeMux
func (h *AuthHandlers) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/.auth/token/revoke", h.handleRevoke)
	mux.HandleFunc("/.auth/token/info", h.handleInfo)
}

func (h *AuthHandlers) handleRevoke(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}

	count := GetAuthCache().RevokeByToken(token)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"revoked": count,
	})
}

func (h *AuthHandlers) handleInfo(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}

	info := GetAuthCache().GetInfoByToken(token)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

// Session management
type Session struct {
	Username string
	Admin    bool
	Expires  time.Time
}
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]Session
}

func (s *SessionStore) Set(token string, sess Session) {
	s.mu.Lock()
	s.sessions[token] = sess
	s.mu.Unlock()
}
func (s *SessionStore) Get(token string) (Session, bool) {
	s.mu.RLock()
	v, ok := s.sessions[token]
	s.mu.RUnlock()
	return v, ok
}
func (s *SessionStore) Delete(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// Helper function to format time duration for UI
func formatDuration(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return time.Since(t).Round(time.Second).String()
}

var AdminSessions = &SessionStore{sessions: make(map[string]Session)}

// AdminHandlers contains the HTTP handlers for the admin panel.
type AdminHandlers struct {
	config        *Config
	configPath    string
	serverName    string
	configMux     sync.RWMutex
	sessions      *SessionStore
	tunnelManager TunnelManagerInterface
	// dataStore      *DataStore // Removed, no longer needed
	statsCollector *stats.StatsCollector
	statsDB        *stats.StatsDB
	loggingDB      *logging.LoggingDB
	logBroadcaster *logging.LogBroadcaster
	rateLimiter    *stats.RateLimitEngine
}

// NewAdminHandlers creates a new AdminHandlers instance.
func NewAdminHandlers(config *Config, configPath string, serverName string, statsCollector *stats.StatsCollector, statsDB *stats.StatsDB, loggingDB *logging.LoggingDB, logBroadcaster *logging.LogBroadcaster, rateLimiter *stats.RateLimitEngine) *AdminHandlers {
	return &AdminHandlers{
		config:         config,
		configPath:     configPath,
		serverName:     strings.TrimSpace(serverName),
		sessions:       AdminSessions,
		statsCollector: statsCollector,
		statsDB:        statsDB,
		loggingDB:      loggingDB,
		logBroadcaster: logBroadcaster,
		rateLimiter:    rateLimiter,
	}
}

// SetTunnelManager sets the tunnel manager reference for endpoint status queries
func (h *AdminHandlers) SetTunnelManager(tm TunnelManagerInterface) {
	h.tunnelManager = tm
}

func writeEmbeddedAdminAsset(w http.ResponseWriter, assetName, contentType string) {
	data, err := Asset(assetName)
	if err != nil {
		log.Printf("failed to load embedded admin asset %q: %v", assetName, err)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", contentType)
	if _, err := w.Write(data); err != nil {
		log.Printf("failed to write embedded admin asset %q: %v", assetName, err)
	}
}

// RegisterHandlers registers the admin panel handlers to the given ServeMux.
func (h *AdminHandlers) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/.api/login", h.handleLogin)
	mux.HandleFunc("/.api/logout", h.handleLogout)
	mux.HandleFunc("/.api/config", h.handleConfig)

	// 资源管理接口
	mux.HandleFunc("/.api/users", h.handleUsers)
	mux.HandleFunc("/.api/proxies", h.handleProxies)
	mux.HandleFunc("/.api/tunnels", h.handleTunnels)
	mux.HandleFunc("/.api/tunnels/endpoints", h.handleTunnelEndpoints)
	mux.HandleFunc("/.api/endpoints", h.handleEndpointConfigs) 
	mux.HandleFunc("/.api/tls-pin", h.handleTLSPin)
	mux.HandleFunc("/.api/tls-pin-token", h.handleTLSPinToken)
	mux.HandleFunc("/.api/servers", h.handleServers)
	mux.HandleFunc("/.api/rules", h.handleRules)
	mux.HandleFunc("/.api/rate_limit_rules", h.handleRateLimitRules)  // New endpoint
	mux.HandleFunc("/.api/online_endpoints", h.handleOnlineEndpoints) // New endpoint
	mux.HandleFunc("/.api/firewalls", h.handleFirewalls)
	mux.HandleFunc("/.api/auth_providers", h.handleAuthProviders)
	mux.HandleFunc("/.api/log", h.handleLogs)
	mux.HandleFunc("/.api/act", h.handleAct)
	mux.HandleFunc("/.api/stats/timeseries", h.handleTimeSeriesStats)
	mux.HandleFunc("/.api/stats/url", h.handleUrlStats)
	mux.HandleFunc("/.api/stats/ip", func(w http.ResponseWriter, r *http.Request) {
		// Admin authentication check
		if !isAdminRequest(r, h.config) {
			return
		}

		ipStats := h.statsCollector.GetIPStats()

		// Enrich ipStats with location and rate limiter status
		for i := range ipStats {
			// Get location from ASN cache
			location, err := asn.GetIPLocation(ipStats[i].IP)
			if err == nil && location != nil {
				ipStats[i].Location = location
			}

			// Get rate limiter status (true = not banned, false = banned)
			if h.rateLimiter != nil {
				ipStats[i].Status = !h.rateLimiter.IsBanned(ipStats[i].IP)
			} else {
				ipStats[i].Status = true
			}
		}

		response := struct {
			IPs       []stats.IPRequestStats `json:"ips"`
			TotalIPs  int                    `json:"totalIPs"`
			TimeRange string                 `json:"timeRange"`
		}{
			IPs:       ipStats,
			TotalIPs:  len(ipStats),
			TimeRange: "24h",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	charts.Register(mux)

	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	// 管理面板页面
	mux.HandleFunc("/.admin/", func(w http.ResponseWriter, r *http.Request) {
		writeEmbeddedAdminAsset(w, "index.html", "text/html; charset=utf-8")
	})
	mux.HandleFunc("/.admin/style.css", func(w http.ResponseWriter, r *http.Request) {
		writeEmbeddedAdminAsset(w, "style.css", "text/css; charset=utf-8")
	})
	mux.HandleFunc("/.admin/script.js", func(w http.ResponseWriter, r *http.Request) {
		writeEmbeddedAdminAsset(w, "script.js", "application/javascript; charset=utf-8")
	})

	mux.HandleFunc("/.admin/carbon.js", func(w http.ResponseWriter, r *http.Request) {
		writeEmbeddedAdminAsset(w, "carbon.js", "application/javascript; charset=utf-8")
	})
	mux.HandleFunc("/.admin/carbon.css", func(w http.ResponseWriter, r *http.Request) {
		writeEmbeddedAdminAsset(w, "carbon.css", "text/css; charset=utf-8")
	})
	mux.HandleFunc("/.admin/ibm-plex.css", func(w http.ResponseWriter, r *http.Request) {
		writeEmbeddedAdminAsset(w, "ibm-plex.css", "text/css; charset=utf-8")
	})
	mux.HandleFunc("/.admin/carbon/charts.js", func(w http.ResponseWriter, r *http.Request) {
		writeEmbeddedAdminAsset(w, "carbon/charts.js", "application/javascript; charset=utf-8")
	})
	mux.HandleFunc("/.admin/carbon/charts.css", func(w http.ResponseWriter, r *http.Request) {
		writeEmbeddedAdminAsset(w, "carbon/charts.css", "text/css; charset=utf-8")
	})

	log.Println("Admin panel API available at '/.api' and UI at '/.admin/'")
}

func (h *AdminHandlers) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	h.configMux.RLock()
	defer h.configMux.RUnlock()

	if h.config.Auth == nil || h.config.Auth.Users == nil {
		http.Error(w, "Authentication not configured", http.StatusInternalServerError)
		return
	}

	user, ok := h.config.Auth.Users[creds.Username]
	if !ok || user.Password != creds.Password {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}
	if !user.Admin {
		http.Error(w, "User is not an administrator", http.StatusForbidden)
		return
	}

	// Generate a random session token
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(buf)

	// Store session with expiration (24h)
	h.sessions.Set(token, Session{
		Username: creds.Username,
		Admin:    true,
		Expires:  time.Now().Add(24 * time.Hour),
	})

	// Set HttpOnly cookie
	cookie := &http.Cookie{
		Name:     "APS-Admin-Token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if r.TLS != nil {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "token": token})
}

// handleTunnelEndpoints returns detailed information about endpoints for a specific tunnel or all online endpoints.
func (h *AdminHandlers) handleTunnelEndpoints(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.tunnelManager == nil {
		http.Error(w, "Tunnel manager not initialized", http.StatusInternalServerError)
		return
	}

	type PublicEndpointInfo struct {
		Name         string      `json:"name"`
		Online       bool        `json:"online"`
		RemoteAddr   string      `json:"remoteAddr"`
		OnlineTime   string      `json:"onlineTime"`
		LastActivity string      `json:"lastActivity"`
		Latency      string      `json:"latency"`
		Stats        interface{} `json:"stats,omitempty"` // Stats enabled
	}

	response := struct {
		Endpoints []PublicEndpointInfo `json:"endpoints"`
		Tunnel    string               `json:"tunnel,omitempty"`
	}{
		Endpoints: make([]PublicEndpointInfo, 0),
	}

	tunnelName := r.URL.Query().Get("tunnel")

	if tunnelName != "" {
		// Return endpoints for a specific tunnel
		endpoints := h.tunnelManager.GetEndpointsInfo(tunnelName, h.statsCollector)
		if endpoints == nil {
			http.Error(w, "Tunnel not found", http.StatusNotFound)
			return
		}
		response.Tunnel = tunnelName

		for _, ep := range endpoints {
			// 显示标准时间格式而不是相对时间
			onlineTimeStr := "-"
			if !ep.OnlineTime.IsZero() {
				onlineTimeStr = ep.OnlineTime.Format("2006-01-02 15:04:05")
			}

			lastActivityStr := "-"
			if !ep.LastActivityTime.IsZero() {
				lastActivityStr = ep.LastActivityTime.Format("2006-01-02 15:04:05")
			}

			response.Endpoints = append(response.Endpoints, PublicEndpointInfo{
				Name:         ep.Name,
				Online:       true,
				RemoteAddr:   ep.RemoteAddr,
				OnlineTime:   onlineTimeStr,
				LastActivity: lastActivityStr,
				Latency:      "-",      // Latency measurement disabled
				Stats:        ep.Stats, // Include statistics from endpoint info
			})
		}
	} else {
		// Return all online endpoints across all tunnels
		allEndpoints := h.tunnelManager.GetAllOnlineEndpoints()

		for _, ep := range allEndpoints {
			// 显示标准时间格式而不是相对时间
			onlineTimeStr := "-"
			if !ep.OnlineTime.IsZero() {
				onlineTimeStr = ep.OnlineTime.Format("2006-01-02 15:04:05")
			}

			lastActivityStr := "-"
			if !ep.LastActivityTime.IsZero() {
				lastActivityStr = ep.LastActivityTime.Format("2006-01-02 15:04:05")
			}

			response.Endpoints = append(response.Endpoints, PublicEndpointInfo{
				Name:         ep.Name,
				Online:       true,
				RemoteAddr:   ep.RemoteAddr,
				OnlineTime:   onlineTimeStr,
				LastActivity: lastActivityStr,
				Latency:      "-",      // Latency measurement disabled
				Stats:        ep.Stats, // Include statistics from endpoint info
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *AdminHandlers) handleUrlStats(w http.ResponseWriter, r *http.Request) {
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	stats := h.statsCollector.GetUrlStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (h *AdminHandlers) handleConfig(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement config get/set logic with authentication
	switch r.Method {
	case http.MethodGet:
		h.getConfig(w, r)
	case http.MethodPost:
		h.setConfig(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func extractToken(r *http.Request) string {
	// Prefer Authorization: Bearer <token>
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	// Fallback to cookie
	if c, err := r.Cookie("APS-Admin-Token"); err == nil {
		return c.Value
	}
	return ""
}

// isAdminRequest checks admin via session token (cookie) or user.token (Bearer) with admin=true
func isAdminRequest(r *http.Request, config *Config) bool {
	// Prefer Authorization: Bearer <token>
	token := extractToken(r)
	if token == "" {
		return false
	}
	// Session tokens from login
	if sess, ok := AdminSessions.Get(token); ok {
		return sess.Admin && sess.Expires.After(time.Now())
	}
	// Config-defined API tokens
	if config != nil && config.Auth != nil && config.Auth.Users != nil {
		for _, u := range config.Auth.Users {
			if u != nil && u.Token == token && u.Admin {
				return true
			}
		}
	}
	return false
}

func (h *AdminHandlers) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token != "" {
		h.sessions.Delete(token)
		// Clear cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "APS-Admin-Token",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1,
			SameSite: http.SameSiteLaxMode,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
}

func (h *AdminHandlers) getConfig(w http.ResponseWriter, r *http.Request) {
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	section := r.URL.Query().Get("section")
	if section == "" {
		section = "all"
	}

	h.configMux.RLock()
	defer h.configMux.RUnlock()

	w.Header().Set("Content-Type", "application/json")

	switch section {
	case "all":
		json.NewEncoder(w).Encode(h.config)
	case "servers":
		json.NewEncoder(w).Encode(h.config.Servers)
	case "mappings":
		json.NewEncoder(w).Encode(h.config.Mappings)
	case "tunnels":
		json.NewEncoder(w).Encode(h.config.Tunnels)
	case "firewalls":
		json.NewEncoder(w).Encode(h.config.Firewalls)
	case "proxies":
		json.NewEncoder(w).Encode(h.config.Proxies)
	case "auth":
		json.NewEncoder(w).Encode(h.config.Auth)
	case "p12s":
		json.NewEncoder(w).Encode(h.config.P12s)
	case "auth_providers":
		json.NewEncoder(w).Encode(h.config.AuthProviders)
	default:
		http.Error(w, "Invalid section. Valid values: all, servers, mappings, tunnels, firewalls, proxies, auth, p12s, auth_providers", http.StatusBadRequest)
	}
}

func (h *AdminHandlers) setConfig(w http.ResponseWriter, r *http.Request) {
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var newConfig Config
	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		http.Error(w, "Invalid config format", http.StatusBadRequest)
		return
	}

	h.configMux.Lock()
	defer h.configMux.Unlock()

	file, err := os.OpenFile(h.configPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		http.Error(w, "Failed to open config file for writing", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(&newConfig); err != nil {
		http.Error(w, "Failed to write config file", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success, reload triggered"})
}

// ===== 辅助：保存当前内存配置到文件（需持有写锁）=====
func (h *AdminHandlers) saveConfigLocked() error {
	kdfTunnels := make(map[string]*security.TunnelKDFConfig)
	for name, t := range h.config.Tunnels {
		if t == nil { continue }
		kdfTunnels[name] = &security.TunnelKDFConfig{
			KDFVersion: t.KDFVersion,
			KDFSalt:    stringPtr(t.KDFSalt),
		}
	}
	if err := security.EnsureTunnelKDFSettings(kdfTunnels); err != nil {
		return err
	}


	// Increment version for concurrent editing detection
	h.config.Version++

	file, err := os.OpenFile(h.configPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(h.config)
}

func (h *AdminHandlers) getTunnelKDFParamsLocked(tunnelName string) (string, string, error) {
	if h.config == nil || h.config.Tunnels == nil {
		return "", "", errors.New("tunnel configuration is not initialized")
	}
	tunnelName = strings.TrimSpace(tunnelName)
	tunnel, exists := h.config.Tunnels[tunnelName]
	if !exists || tunnel == nil {
		return "", "", fmt.Errorf("tunnel '%s' not found", tunnelName)
	}

	kdfVersion, err := security.NormalizeKDFVersion(tunnel.KDFVersion)
	if err != nil {
		return "", "", err
	}
	kdfSalt := strings.TrimSpace(tunnel.KDFSalt)
	if kdfSalt == "" {
		return "", "", fmt.Errorf("tunnel '%s' kdfSalt is missing", tunnelName)
	}

	return kdfVersion, kdfSalt, nil
}

func appendNormalizedFromEntries(dst []string, seen map[string]struct{}, raw interface{}) []string {
	switch v := raw.(type) {
	case string:
		entry := strings.TrimSpace(v)
		if entry == "" {
			return dst
		}
		if _, ok := seen[entry]; ok {
			return dst
		}
		seen[entry] = struct{}{}
		return append(dst, entry)
	case []string:
		for _, item := range v {
			dst = appendNormalizedFromEntries(dst, seen, item)
		}
		return dst
	case []interface{}:
		for _, item := range v {
			dst = appendNormalizedFromEntries(dst, seen, item)
		}
		return dst
	default:
		return dst
	}
}

func mappingFromEntries(mapping Mapping) ([]string, error) {
	seen := make(map[string]struct{})
	entries := make([]string, 0)

	switch v := mapping.From.(type) {
	case nil:
		return nil, nil
	case string, []string, []interface{}:
		entries = appendNormalizedFromEntries(entries, seen, v)
	case map[string]interface{}:
		if urlVal, ok := v["url"]; ok {
			entries = appendNormalizedFromEntries(entries, seen, urlVal)
		}
		if urlsVal, ok := v["urls"]; ok {
			entries = appendNormalizedFromEntries(entries, seen, urlsVal)
		}
	case EndpointConfig:
		entries = appendNormalizedFromEntries(entries, seen, v.URL)
		entries = appendNormalizedFromEntries(entries, seen, v.URLs)
	case *EndpointConfig:
		if v != nil {
			entries = appendNormalizedFromEntries(entries, seen, v.URL)
			entries = appendNormalizedFromEntries(entries, seen, v.URLs)
		}
	default:
		return nil, fmt.Errorf("unsupported from format: %T", mapping.From)
	}

	return entries, nil
}

func findConflictingFromEntry(mappings []Mapping, target Mapping, ignoreIndex int) (int, string, error) {
	targetEntries, err := mappingFromEntries(target)
	if err != nil {
		return -1, "", err
	}
	if len(targetEntries) == 0 {
		return -1, "", nil
	}

	targetSet := make(map[string]struct{}, len(targetEntries))
	for _, entry := range targetEntries {
		targetSet[entry] = struct{}{}
	}

	for idx, existing := range mappings {
		if idx == ignoreIndex {
			continue
		}
		existingEntries, err := mappingFromEntries(existing)
		if err != nil {
			return -1, "", err
		}
		for _, entry := range existingEntries {
			if _, ok := targetSet[entry]; ok {
				return idx, entry, nil
			}
		}
	}

	return -1, "", nil
}

// ===== 用户管理 =====
func (h *AdminHandlers) handleUsers(w http.ResponseWriter, r *http.Request) {
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.configMux.RLock()
		defer h.configMux.RUnlock()
		resp := make(map[string]interface{})
		if h.config.Auth != nil && h.config.Auth.Users != nil {
			for name, u := range h.config.Auth.Users {
				if u == nil {
					continue
				}
				resp[name] = map[string]interface{}{
					"admin":              u.Admin,
					"token":              u.Token,
					"groups":             u.Groups,
					"endpoint":           u.Endpoint,
					"tunnel":             u.Tunnel,
					"connectionPolicies": u.ConnectionPolicies,
					"trafficPolicies":    u.TrafficPolicies,
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	case http.MethodPost:
		var req struct {
			Name string `json:"name"`
			User User   `json:"user"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}
		h.configMux.Lock()
		defer h.configMux.Unlock()
		if h.config.Auth == nil {
			h.config.Auth = &AuthConfig{}
		}
		if h.config.Auth.Users == nil {
			h.config.Auth.Users = make(map[string]*User)
		}
		// 覆盖或新增
		u := req.User
		// 如果是更新已存在用户,且password/token为空,则保留原值
		if existingUser, exists := h.config.Auth.Users[req.Name]; exists && existingUser != nil {
			if u.Password == "" {
				u.Password = existingUser.Password
			}
			if u.Token == "" {
				u.Token = existingUser.Token
			}
		}
		h.config.Auth.Users[req.Name] = &u
		if err := h.saveConfigLocked(); err != nil {
			http.Error(w, "Failed to persist config", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "upserted"})
	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		h.configMux.Lock()
		defer h.configMux.Unlock()
		if h.config.Auth != nil && h.config.Auth.Users != nil {
			delete(h.config.Auth.Users, name)
		}
		if err := h.saveConfigLocked(); err != nil {
			http.Error(w, "Failed to persist config", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ===== 代理管理 =====
func (h *AdminHandlers) handleProxies(w http.ResponseWriter, r *http.Request) {
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.configMux.RLock()
		defer h.configMux.RUnlock()
		resp := make(map[string]*ProxyConfig)
		if h.config.Proxies != nil {
			for name, p := range h.config.Proxies {
				resp[name] = p
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	case http.MethodPost:
		var req struct {
			Name  string      `json:"name"`
			Proxy ProxyConfig `json:"proxy"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}
		h.configMux.Lock()
		defer h.configMux.Unlock()
		if h.config.Proxies == nil {
			h.config.Proxies = make(map[string]*ProxyConfig)
		}
		p := req.Proxy
		h.config.Proxies[req.Name] = &p
		if err := h.saveConfigLocked(); err != nil {
			http.Error(w, "Failed to persist config", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "upserted"})
	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		h.configMux.Lock()
		defer h.configMux.Unlock()
		if h.config.Proxies != nil {
			delete(h.config.Proxies, name)
		}
		if err := h.saveConfigLocked(); err != nil {
			http.Error(w, "Failed to persist config", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ===== 隧道管理 =====
func (h *AdminHandlers) handleTunnels(w http.ResponseWriter, r *http.Request) {
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.configMux.RLock()
		defer h.configMux.RUnlock()
		resp := make(map[string]*TunnelConfig)
		if h.config.Tunnels != nil {
			for name, t := range h.config.Tunnels {
				resp[name] = t
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	case http.MethodPost:
		var req struct {
			Name   string       `json:"name"`
			Tunnel TunnelConfig `json:"tunnel"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}
		h.configMux.Lock()
		defer h.configMux.Unlock()
		if h.config.Tunnels == nil {
			h.config.Tunnels = make(map[string]*TunnelConfig)
		}
		t := req.Tunnel
		// 如果是更新已存在隧道,且password为空,则保留原密码
		if existingTunnel, exists := h.config.Tunnels[req.Name]; exists && existingTunnel != nil {
			if t.Password == "" {
				t.Password = existingTunnel.Password
			}
			if strings.TrimSpace(t.KDFVersion) == "" {
				t.KDFVersion = existingTunnel.KDFVersion
			}
			if strings.TrimSpace(t.KDFSalt) == "" {
				t.KDFSalt = existingTunnel.KDFSalt
			}
		}
		h.config.Tunnels[req.Name] = &t
		if err := h.saveConfigLocked(); err != nil {
			http.Error(w, "Failed to persist config", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "upserted"})
	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		h.configMux.Lock()
		defer h.configMux.Unlock()
		if h.config.Tunnels != nil {
			delete(h.config.Tunnels, name)
		}
		if err := h.saveConfigLocked(); err != nil {
			http.Error(w, "Failed to persist config", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ===== Endpoint配置管理 =====
func (h *AdminHandlers) handleTLSPin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pinKey, host, err := getTLSPinHashForRequest(r)
	if err != nil {
		http.Error(w, "TLS pin not available for host", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"alg":     TLSPinAlgorithm,
		"host":    host,
		"hash":    hex.EncodeToString(pinKey),
	})
}

func deriveAPSTLSPinTokenKey(cid, host string) []byte {
	h := sha256.New()
	h.Write([]byte("aps-pin-token-v1"))
	h.Write([]byte("|"))
	h.Write([]byte(strings.TrimSpace(cid)))
	h.Write([]byte("|"))
	h.Write([]byte(normalizeTLSPinHost(host)))
	return h.Sum(nil)
}

func encodeAPSTLSPinToken(pinHash []byte, cid, host string, expUnix int64) (string, error) {
	if len(pinHash) != sha256.Size {
		return "", fmt.Errorf("pin hash length must be %d bytes, got %d", sha256.Size, len(pinHash))
	}
	payload := map[string]interface{}{
		"pin":  hex.EncodeToString(pinHash),
		"cid":  strings.TrimSpace(cid),
		"host": normalizeTLSPinHost(host),
		"exp":  expUnix,
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(deriveAPSTLSPinTokenKey(cid, host))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plain, nil)
	return apsTLSPinTokenPrefix + base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func (h *AdminHandlers) handleTLSPinToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	cid := strings.TrimSpace(r.URL.Query().Get("cid"))
	if cid == "" {
		http.Error(w, "cid is required", http.StatusBadRequest)
		return
	}

	host := normalizeTLSPinHost(strings.TrimSpace(r.URL.Query().Get("host")))
	var pinKey []byte
	if host != "" {
		var ok bool
		pinKey, ok = lookupTLSPinHashForHost(host)
		if !ok {
			http.Error(w, "TLS pin not available for host", http.StatusBadRequest)
			return
		}
	} else {
		var err error
		pinKey, host, err = getTLSPinHashForRequest(r)
		if err != nil {
			http.Error(w, "TLS pin not available for host", http.StatusBadRequest)
			return
		}
		host = normalizeTLSPinHost(host)
	}

	ttlSeconds := int64(600)
	if rawTTL := strings.TrimSpace(r.URL.Query().Get("ttl")); rawTTL != "" {
		parsedTTL, err := strconv.ParseInt(rawTTL, 10, 64)
		if err != nil || parsedTTL <= 0 {
			http.Error(w, "invalid ttl", http.StatusBadRequest)
			return
		}
		if parsedTTL > 86400 {
			parsedTTL = 86400
		}
		ttlSeconds = parsedTTL
	}
	expUnix := time.Now().UTC().Unix() + ttlSeconds
	token, err := encodeAPSTLSPinToken(pinKey, cid, host, expUnix)
	if err != nil {
		http.Error(w, "failed to encode tls pin token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"alg":     "apspt1-aesgcm",
		"host":    host,
		"cid":     cid,
		"exp":     expUnix,
		"token":   token,
	})
}

func (h *AdminHandlers) handleEndpointConfigs(w http.ResponseWriter, r *http.Request) {
	// Endpoint self-fetch supports encrypted eid only.
	legacyID := strings.TrimSpace(r.URL.Query().Get("id"))
	encryptedConfigID := strings.TrimSpace(r.URL.Query().Get(TLSEncryptedConfigIDParam))
	encryptedSalt := strings.TrimSpace(r.URL.Query().Get(TLSEncryptedSaltParam))

	if r.Method == http.MethodGet && legacyID != "" {
		http.Error(w, "plaintext id mode is disabled; use encrypted eid", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet && encryptedConfigID != "" {
		configID, requestSalt, pinKey, err := decryptEndpointConfigIDFromRequest(r, encryptedConfigID, encryptedSalt, h.statsDB)
		if err != nil {
			http.Error(w, "invalid encrypted config id", http.StatusBadRequest)
			return
		}

		writeConfigPayload := func(payload map[string]interface{}) {
			if err := writeEncryptedJSONWithTLSPin(w, pinKey, requestSalt, payload); err != nil {
				http.Error(w, "failed to write encrypted response", http.StatusInternalServerError)
			}
		}

		// Allow endpoint clients to fetch their own config without admin auth
		h.configMux.RLock()
		defer h.configMux.RUnlock()

		if h.config.Endpoints == nil {
			writeConfigPayload(map[string]interface{}{
				"success": false,
				"error":   "endpoint not found",
			})
			return
		}

		endpoint, exists := h.config.Endpoints[configID]
		if !exists {
			writeConfigPayload(map[string]interface{}{
				"success": false,
				"error":   "endpoint not found",
			})
			return
		}
		kdfVersion, kdfSalt, kdfErr := h.getTunnelKDFParamsLocked(endpoint.TunnelName)
		if kdfErr != nil {
			writeConfigPayload(map[string]interface{}{
				"success": false,
				"error":   "tunnel KDF parameters are invalid",
			})
			return
		}

		sessionCredential, sessionExpiresAt, issueErr := security.IssueEndpointSessionCredential(configID, endpoint.TunnelName, endpoint.EndpointName)
		if issueErr != nil {
			writeConfigPayload(map[string]interface{}{
				"success": false,
				"error":   "failed to issue session credential",
			})
			return
		}

		writeConfigPayload(map[string]interface{}{
			"success": true,
			"config": map[string]interface{}{
				"id":                  configID,
				"serverName":          h.serverName,
				"tunnelName":          endpoint.TunnelName,
				"endpointName":        endpoint.EndpointName,
				"sessionCredential":   sessionCredential,
				"sessionExpiresAt":    sessionExpiresAt,
				"kdfVersion":          kdfVersion,
				"kdfSalt":             kdfSalt,
				"portMappings":        endpoint.PortMappings,
				"gatewayListen":       endpoint.GatewayListen,
				"gatewayAddress":      endpoint.GatewayAddress,
				"gatewayDiscovery":    endpoint.GatewayDiscovery,
				"gatewayDiscoverPort": endpoint.GatewayDiscoverPort,
				"ssh":                 endpoint.SSH,
			},
		})
		return
	}

	// All other operations require admin authentication
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.configMux.RLock()
		defer h.configMux.RUnlock()
		resp := make(map[string]*EndpointConfig_APS)
		if h.config.Endpoints != nil {
			for name, ep := range h.config.Endpoints {
				resp[name] = ep
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)

	case http.MethodPost:
		var req struct {
			Name     string             `json:"name"`
			Endpoint EndpointConfig_APS `json:"endpoint"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}
		h.configMux.Lock()
		if h.config.Endpoints == nil {
			h.config.Endpoints = make(map[string]*EndpointConfig_APS)
		}
		ep := req.Endpoint
		// If updating existing endpoint and password is empty, preserve original password
		var oldTunnelName, oldEndpointName string
		if existingEp, exists := h.config.Endpoints[req.Name]; exists && existingEp != nil {
			oldTunnelName = existingEp.TunnelName
			oldEndpointName = existingEp.EndpointName
			if ep.Password == "" {
				ep.Password = existingEp.Password
			}
		}
		h.config.Endpoints[req.Name] = &ep
		if err := h.saveConfigLocked(); err != nil {
			h.configMux.Unlock()
			http.Error(w, "Failed to persist config", http.StatusInternalServerError)
			return
		}
		h.configMux.Unlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "upserted"})

		// Push config update to connected endpoint (if online)
		// Use old names to find the active connection if names were changed
		targetTunnel := ep.TunnelName
		targetEndpoint := ep.EndpointName
		if oldTunnelName != "" {
			targetTunnel = oldTunnelName
		}
		if oldEndpointName != "" {
			targetEndpoint = oldEndpointName
		}
		go h.pushConfigToEndpoint(req.Name, targetTunnel, targetEndpoint, &ep)

	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		h.configMux.Lock()
		defer h.configMux.Unlock()
		if h.config.Endpoints != nil {
			delete(h.config.Endpoints, name)
		}
		if err := h.saveConfigLocked(); err != nil {
			http.Error(w, "Failed to persist config", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// pushConfigToEndpoint sends a config update message to a connected endpoint.
// It always issues a fresh one-time session credential instead of pushing static passwords.
func (h *AdminHandlers) pushConfigToEndpoint(configID, tunnelName, endpointName string, config *EndpointConfig_APS) {
	if h.tunnelManager == nil {
		log.Println("[CONFIG] Cannot push config: tunnel manager not set")
		return
	}

	h.configMux.RLock()
	kdfVersion, kdfSalt, kdfErr := h.getTunnelKDFParamsLocked(config.TunnelName)
	h.configMux.RUnlock()
	if kdfErr != nil {
		log.Printf("[CONFIG] Failed to resolve tunnel KDF params for %s: %v", config.TunnelName, kdfErr)
		return
	}

	sessionCredential, sessionExpiresAt, issueErr := security.IssueEndpointSessionCredential(configID, config.TunnelName, config.EndpointName)
	if issueErr != nil {
		log.Printf("[CONFIG] Failed to issue session credential for %s: %v", configID, issueErr)
		return
	}

	// Build config update payload
	payload := map[string]interface{}{
		"tunnelName":          config.TunnelName,
		"endpointName":        config.EndpointName,
		"sessionCredential":   sessionCredential,
		"sessionExpiresAt":    sessionExpiresAt,
		"kdfVersion":          kdfVersion,
		"kdfSalt":             kdfSalt,
		"portMappings":        config.PortMappings,
		"gatewayListen":       config.GatewayListen,
		"gatewayAddress":      config.GatewayAddress,
		"gatewayDiscovery":    config.GatewayDiscovery,
		"gatewayDiscoverPort": config.GatewayDiscoverPort,
		"ssh":                 config.SSH,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[CONFIG] Failed to marshal config update payload: %v", err)
		return
	}

	// Send config update via tunnel manager interface
	if err := h.tunnelManager.SendConfigUpdate(tunnelName, endpointName, payloadBytes); err != nil {
		log.Printf("[CONFIG] Failed to send config update to %s/%s: %v", tunnelName, endpointName, err)
		return
	}

	log.Printf("[CONFIG] Config update pushed to endpoint %s/%s", tunnelName, endpointName)
}

// ===== 服务器管理 =====
func (h *AdminHandlers) handleServers(w http.ResponseWriter, r *http.Request) {
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.configMux.RLock()
		defer h.configMux.RUnlock()
		resp := make(map[string]*ListenConfig)
		if h.config.Servers != nil {
			for name, s := range h.config.Servers {
				resp[name] = s
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	case http.MethodPost:
		var req struct {
			Name   string       `json:"name"`
			Server ListenConfig `json:"server"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}
		h.configMux.Lock()
		defer h.configMux.Unlock()

		// IMPORTANT: Do NOT modify h.config.Servers here!
		// Only modify the file and let watcher update memory.
		// This ensures watcher can properly compare oldServers vs newServers.

		// Read current config from memory to build new file content
		if h.config.Servers == nil {
			h.config.Servers = make(map[string]*ListenConfig)
		}
		s := req.Server

		// Create a temporary copy for saving to file
		updatedServers := make(map[string]*ListenConfig)
		for name, srv := range h.config.Servers {
			updatedServers[name] = srv
		}
		updatedServers[req.Name] = &s

		// Temporarily update config for saveConfigLocked
		oldServers := h.config.Servers
		h.config.Servers = updatedServers
		if err := h.saveConfigLocked(); err != nil {
			h.config.Servers = oldServers // Restore on error
			http.Error(w, "Failed to persist config", http.StatusInternalServerError)
			return
		}
		// Restore original - watcher will update it
		h.config.Servers = oldServers
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "upserted"})
	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		h.configMux.Lock()
		defer h.configMux.Unlock()
		if h.config.Servers != nil {
			delete(h.config.Servers, name)
		}
		if err := h.saveConfigLocked(); err != nil {
			http.Error(w, "Failed to persist config", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ===== 规则管理 =====
func (h *AdminHandlers) handleRules(w http.ResponseWriter, r *http.Request) {
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.configMux.RLock()
		defer h.configMux.RUnlock()
		// 直接返回当前配置中的 Mappings（内部解析字段为非导出，不会泄露）
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(h.config.Mappings)
	case http.MethodPost:
		// Read body once
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		// Try to decode as wrapped format first
		var req struct {
			Index   *int    `json:"index,omitempty"`
			Mapping Mapping `json:"mapping"`
		}

		// Check if "mapping" key exists in JSON
		var rawMap map[string]interface{}
		if err := json.Unmarshal(body, &rawMap); err != nil {
			http.Error(w, "Invalid JSON format", http.StatusBadRequest)
			return
		}

		h.configMux.Lock()
		defer h.configMux.Unlock()

		var mapping Mapping
		var index *int

		if _, hasMapping := rawMap["mapping"]; hasMapping {
			// Wrapped format
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, "Invalid payload format", http.StatusBadRequest)
				return
			}
			mapping = req.Mapping
			index = req.Index
		} else {
			// Flat format (backward compatibility or frontend convenience)
			// Check if "index" is present at top level
			if idxVal, ok := rawMap["index"]; ok {
				if idxFloat, ok := idxVal.(float64); ok {
					idx := int(idxFloat)
					index = &idx
				}
			}
			// Unmarshal entire body as Mapping
			if err := json.Unmarshal(body, &mapping); err != nil {
				http.Error(w, "Invalid mapping format", http.StatusBadRequest)
				return
			}
		}

		if index != nil {
			if *index < 0 || *index >= len(h.config.Mappings) {
				http.Error(w, "index out of range", http.StatusBadRequest)
				return
			}
		}

		ignoreIndex := -1
		if index != nil {
			ignoreIndex = *index
		}
		conflictIndex, conflictFrom, err := findConflictingFromEntry(h.config.Mappings, mapping, ignoreIndex)
		if err != nil {
			http.Error(w, "Failed to validate from-entry uniqueness", http.StatusInternalServerError)
			return
		}
		if conflictIndex >= 0 {
			http.Error(w, fmt.Sprintf("conflicting from entry '%s' already exists at mapping index %d", conflictFrom, conflictIndex), http.StatusConflict)
			return
		}

		if index != nil {
			h.config.Mappings[*index] = mapping
		} else {
			h.config.Mappings = append(h.config.Mappings, mapping)
		}
		if err := h.saveConfigLocked(); err != nil {
			http.Error(w, "Failed to persist config", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "upserted"})
	case http.MethodDelete:
		idxStr := r.URL.Query().Get("index")
		if idxStr == "" {
			http.Error(w, "index is required", http.StatusBadRequest)
			return
		}
		idx, err := strconv.Atoi(idxStr)
		if err != nil || idx < 0 || idx >= len(h.config.Mappings) {
			http.Error(w, "invalid index", http.StatusBadRequest)
			return
		}
		h.configMux.Lock()
		defer h.configMux.Unlock()
		h.config.Mappings = append(h.config.Mappings[:idx], h.config.Mappings[idx+1:]...)
		if err := h.saveConfigLocked(); err != nil {
			http.Error(w, "Failed to persist config", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ===== 防火墙管理 =====
func (h *AdminHandlers) handleFirewalls(w http.ResponseWriter, r *http.Request) {
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.configMux.RLock()
		defer h.configMux.RUnlock()
		resp := make(map[string]*firewall.FirewallRule)
		if h.config.Firewalls != nil {
			for name, fw := range h.config.Firewalls {
				resp[name] = fw
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	case http.MethodPost:
		var req struct {
			Name     string       `json:"name"`
			Firewall firewall.FirewallRule `json:"firewall"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}
		h.configMux.Lock()
		defer h.configMux.Unlock()
		if h.config.Firewalls == nil {
			h.config.Firewalls = make(map[string]*firewall.FirewallRule)
		}
		fw := req.Firewall
		h.config.Firewalls[req.Name] = &fw
		// Parse the firewall rule
		if err := firewall.ParseFirewallRule(&fw); err != nil {
			log.Printf("[FIREWALL] Warning: failed to parse firewall rule '%s': %v", req.Name, err)
		} else {
			log.Printf("[FIREWALL] Loaded firewall rule '%s'", req.Name)
		}
		if err := h.saveConfigLocked(); err != nil {
			http.Error(w, "Failed to persist config", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "upserted"})
	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		h.configMux.Lock()
		defer h.configMux.Unlock()
		if h.config.Firewalls != nil {
			delete(h.config.Firewalls, name)
		}
		if err := h.saveConfigLocked(); err != nil {
			http.Error(w, "Failed to persist config", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ===== 认证提供商管理 =====
func (h *AdminHandlers) handleAuthProviders(w http.ResponseWriter, r *http.Request) {
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.configMux.RLock()
		defer h.configMux.RUnlock()
		resp := make(map[string]*AuthProviderConfig)
		if h.config.AuthProviders != nil {
			for name, ap := range h.config.AuthProviders {
				resp[name] = ap
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	case http.MethodPost:
		var req struct {
			Name         string             `json:"name"`
			AuthProvider AuthProviderConfig `json:"authProvider"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}
		h.configMux.Lock()
		defer h.configMux.Unlock()
		if h.config.AuthProviders == nil {
			h.config.AuthProviders = make(map[string]*AuthProviderConfig)
		}
		ap := req.AuthProvider
		h.config.AuthProviders[req.Name] = &ap
		if err := h.saveConfigLocked(); err != nil {
			http.Error(w, "Failed to persist config", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "upserted"})
	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		h.configMux.Lock()
		defer h.configMux.Unlock()
		if h.config.AuthProviders != nil {
			delete(h.config.AuthProviders, name)
		}
		if err := h.saveConfigLocked(); err != nil {
			http.Error(w, "Failed to persist config", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ===== 日志管理 =====
func (h *AdminHandlers) handleLogs(w http.ResponseWriter, r *http.Request) {
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if h.loggingDB == nil {
		http.Error(w, "Logging DB not initialized", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Parsing query parameters
		query := r.URL.Query()
		filter := logging.LogQueryFilter{
			Page:     1,
			PageSize: 50,
		}

		if pageStr := query.Get("page"); pageStr != "" {
			if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
				filter.Page = p
			}
		}
		if sizeStr := query.Get("pageSize"); sizeStr != "" {
			if s, err := strconv.Atoi(sizeStr); err == nil && s > 0 {
				filter.PageSize = s
			}
		}

		if startStr := query.Get("startTime"); startStr != "" {
			if t, err := time.Parse(time.RFC3339, startStr); err == nil {
				filter.StartTime = &t
			} else if ts, err := strconv.ParseInt(startStr, 10, 64); err == nil {
				t := time.Unix(ts, 0)
				filter.StartTime = &t
			}
		}
		if endStr := query.Get("endTime"); endStr != "" {
			if t, err := time.Parse(time.RFC3339, endStr); err == nil {
				filter.EndTime = &t
			} else if ts, err := strconv.ParseInt(endStr, 10, 64); err == nil {
				t := time.Unix(ts, 0)
				filter.EndTime = &t
			}
		}

		// Helper to split comma-separated values
		splitParams := func(param string) []string {
			val := query.Get(param)
			if val == "" {
				return nil
			}
			return strings.Split(val, ",")
		}

		filter.Protocols = splitParams("protocols")
		filter.Servers = splitParams("servers")
		filter.Tunnels = splitParams("tunnels")
		filter.Proxies = splitParams("proxies")
		filter.Endpoints = splitParams("endpoints")
		filter.Firewalls = splitParams("firewalls")
		filter.Users = splitParams("users")
		filter.UserGroups = splitParams("userGroups")

		logs, total, err := h.loggingDB.QueryLogs(filter)
		if err != nil {
			http.Error(w, "Failed to query logs: "+err.Error(), http.StatusInternalServerError)
			return
		}

		response := struct {
			Logs  []logging.LogEntry `json:"logs"`
			Total int        `json:"total"`
			Page  int        `json:"page"`
			Size  int        `json:"pageSize"`
		}{
			Logs:  logs,
			Total: total,
			Page:  filter.Page,
			Size:  filter.PageSize,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

	case http.MethodDelete:
		// Bulk delete by IDs or time range
		var req struct {
			IDs       []int64 `json:"ids"`
			StartTime string  `json:"startTime"` // Optional: Delete range
			EndTime   string  `json:"endTime"`   // Optional: Delete range
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if len(req.IDs) > 0 {
			if err := h.loggingDB.DeleteLogs(req.IDs); err != nil {
				http.Error(w, "Failed to delete logs: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			// Handle time range deletion if needed (not strictly required by prompt but good to have)
			// For now, basic ID deletion is implemented as requested ("删除（批量）操作")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *AdminHandlers) handleAct(w http.ResponseWriter, r *http.Request) {
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	if h.logBroadcaster == nil {
		http.Error(w, "Log broadcaster not initialized", http.StatusInternalServerError)
		return
	}

	ch := h.logBroadcaster.Subscribe()
	defer h.logBroadcaster.Unsubscribe(ch)

	// Send initial comment to establish connection
	fmt.Fprintf(w, ": Connected to log stream\n\n")
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case msg := <-ch:
			// Write data: <msg>\n\n
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-ctx.Done():
			return
		}
	}
}

// ===== 时间序列统计数据 =====
func (h *AdminHandlers) handleTimeSeriesStats(w http.ResponseWriter, r *http.Request) {
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.statsDB == nil {
		http.Error(w, "Stats DB not initialized", http.StatusInternalServerError)
		return
	}

	dimension := r.URL.Query().Get("dimension") // global, rules, users, servers, tunnels, proxies
	key := r.URL.Query().Get("key")             // specific rule/user/server/tunnel/proxy name

	w.Header().Set("Content-Type", "application/json")

	// If no dimension specified or global, return global stats
	if dimension == "" || dimension == "global" {
		data, err := h.statsDB.GetGlobalTimeSeries()
		if err != nil {
			http.Error(w, "Failed to get stats: "+err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(data)
		return
	}

	// Return dimensional stats
	data, err := h.statsDB.GetDimensionTimeSeries(dimension, key)
	if err != nil {
		http.Error(w, "Failed to get stats: "+err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(data)
}

// extractGlobalTimeSeries extracts global statistics from snapshots
func extractGlobalTimeSeries(snapshots []stats.TimeSeriesSnapshot) []map[string]interface{} {
	result := make([]map[string]interface{}, len(snapshots))
	for i, s := range snapshots {
		result[i] = map[string]interface{}{
			"timestamp":         s.Timestamp,
			"totalRequests":     s.Global.TotalRequests,
			"activeConnections": s.Global.ActiveConnections,
			"requestsPerSecond": s.Global.RequestsPerSecond,
			"bytesReceived":     s.Global.BytesReceived,
			"bytesSent":         s.Global.BytesSent,
		}
	}
	return result
}

// extractDimensionTimeSeries extracts dimensional statistics for a specific key
func extractDimensionTimeSeries(snapshots []stats.TimeSeriesSnapshot, dimension, key string) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(snapshots))

	for _, s := range snapshots {
		var dimStats *stats.DimensionStats

		switch dimension {
		case "rules":
			dimStats = s.Rules[key]
		case "users":
			dimStats = s.Users[key]
		case "servers":
			dimStats = s.Servers[key]
		case "tunnels":
			dimStats = s.Tunnels[key]
		case "proxies":
			dimStats = s.Proxies[key]
		}

		if dimStats != nil {
			result = append(result, map[string]interface{}{
				"timestamp":   s.Timestamp,
				"requests":    dimStats.Requests,
				"bytesRecv":   dimStats.BytesRecv,
				"bytesSent":   dimStats.BytesSent,
				"errors":      dimStats.Errors,
				"avgRespTime": dimStats.AvgRespTime,
			})
		}
	}

	return result
}

func (h *AdminHandlers) handleRateLimitRules(w http.ResponseWriter, r *http.Request) {
	if !isAdminRequest(r, h.config) {
		return
	}

	h.configMux.Lock()
	defer h.configMux.Unlock()

	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(h.config.RateLimitRules)
		return
	}

	if r.Method == http.MethodPost {
		var rule stats.RateLimitRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if h.config.RateLimitRules == nil {
			h.config.RateLimitRules = make(map[string]*stats.RateLimitRule)
		}
		h.config.RateLimitRules[rule.Name] = &rule
		if err := h.saveConfigLocked(); err != nil {
			http.Error(w, "Failed to save config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if h.rateLimiter != nil {
			h.rateLimiter.UpdateRule(&rule)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rule)
		return
	}

	if r.Method == http.MethodDelete {
		name := r.URL.Query().Get("name")
		delete(h.config.RateLimitRules, name)
		if err := h.saveConfigLocked(); err != nil {
			http.Error(w, "Failed to save config: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if h.rateLimiter != nil {
			h.rateLimiter.DeleteRule(name)
		}
		w.WriteHeader(http.StatusOK)
		return
	}
}

func (h *AdminHandlers) handleOnlineEndpoints(w http.ResponseWriter, r *http.Request) {
	if !isAdminRequest(r, h.config) {
		return
	}

	endpoints := h.tunnelManager.GetAllOnlineEndpoints()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"endpoints": endpoints,
	})
}