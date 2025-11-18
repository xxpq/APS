package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CertHandlers contains the HTTP handlers for the certificate download page.
type CertHandlers struct{}

// RegisterHandlers registers the certificate download handlers to the given ServeMux.
func (h *CertHandlers) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/.ssl", h.handleCertPage)
	mux.HandleFunc("/.ssl/cert", h.handleCertDownload)
	mux.HandleFunc("/.ssl/cert.crt", h.handleCertDownload)
	mux.HandleFunc("/.ssl/cert.pem", h.handleCertDownload)
	log.Println("Certificate download page available at '/.ssl'")
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
	configMux     sync.RWMutex
	sessions      *SessionStore
	tunnelManager *TunnelManager
}

// NewAdminHandlers creates a new AdminHandlers instance.
func NewAdminHandlers(config *Config, configPath string) *AdminHandlers {
	return &AdminHandlers{
		config:     config,
		configPath: configPath,
		sessions:   AdminSessions,
	}
}

// SetTunnelManager sets the tunnel manager reference for endpoint status queries
func (h *AdminHandlers) SetTunnelManager(tm *TunnelManager) {
	h.tunnelManager = tm
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
	mux.HandleFunc("/.api/servers", h.handleServers)
	mux.HandleFunc("/.api/rules", h.handleRules)

	// 管理面板页面
	mux.HandleFunc("/.admin/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(admin_page_content))
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

// handleTunnelEndpoints returns detailed information about endpoints for a specific tunnel.
func (h *AdminHandlers) handleTunnelEndpoints(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tunnelName := r.URL.Query().Get("tunnel")
	if tunnelName == "" {
		http.Error(w, "Missing tunnel query parameter", http.StatusBadRequest)
		return
	}

	if h.tunnelManager == nil {
		http.Error(w, "Tunnel manager not initialized", http.StatusInternalServerError)
		return
	}

	h.tunnelManager.mu.RLock()
	tunnel, exists := h.tunnelManager.tunnels[tunnelName]
	h.tunnelManager.mu.RUnlock()

	if !exists {
		http.Error(w, "Tunnel not found", http.StatusNotFound)
		return
	}

	type PublicEndpointInfo struct {
		Name         string         `json:"name"`
		Online       bool           `json:"online"`
		RemoteAddr   string         `json:"remoteAddr"`
		OnlineTime   string         `json:"onlineTime"`
		LastActivity string         `json:"lastActivity"`
		Latency      string         `json:"latency"`
		Stats        *PublicMetrics `json:"stats"`
	}

	response := struct {
		Endpoints []PublicEndpointInfo `json:"endpoints"`
	}{
		Endpoints: make([]PublicEndpointInfo, 0),
	}

	tunnel.mu.RLock()
	for endpointName, pool := range tunnel.streams {
		pool.mu.RLock()
		for _, stream := range pool.streams {
			stream.Mu.Lock()
			stats := stream.Stats
			stats.mutex.Lock()
			// Create a copy of metrics to avoid holding the lock during JSON marshal
			requestCount := atomic.LoadUint64(&stats.RequestCount)
			publicStats := &PublicMetrics{
				RequestCount: requestCount,
				Errors:       atomic.LoadUint64(&stats.Errors),
				BytesSent: PublicNumericMetric{
					Total: atomic.LoadUint64(&stats.BytesSent.Total),
					Avg:   0, // Will be calculated if needed
					Min:   stats.BytesSent.Min,
					Max:   stats.BytesSent.Max,
				},
				BytesRecv: PublicNumericMetric{
					Total: atomic.LoadUint64(&stats.BytesRecv.Total),
					Avg:   0, // Will be calculated if needed
					Min:   stats.BytesRecv.Min,
					Max:   stats.BytesRecv.Max,
				},
				ResponseTime: PublicTimeMetric{
					TotalMs: float64(atomic.LoadInt64(&stats.ResponseTime.Total)) / 1e6,
					AvgMs:   0, // Will be calculated if needed
					MinMs:   stats.ResponseTime.Min / 1e6,
					MaxMs:   stats.ResponseTime.Max / 1e6,
				},
			}
			// Calculate averages
			if publicStats.RequestCount > 0 {
				publicStats.BytesSent.Avg = float64(publicStats.BytesSent.Total) / float64(publicStats.RequestCount)
				publicStats.BytesRecv.Avg = float64(publicStats.BytesRecv.Total) / float64(publicStats.RequestCount)
				publicStats.ResponseTime.AvgMs = float64(atomic.LoadInt64(&stats.ResponseTime.Total)) / float64(publicStats.RequestCount) / 1e6
			}
			// Calculate QPS
			if !stats.firstRequestTime.IsZero() && !stats.lastRequestTime.IsZero() {
				duration := stats.lastRequestTime.Sub(stats.firstRequestTime).Seconds()
				if duration > 1 {
					publicStats.QPS = float64(publicStats.RequestCount) / duration
				} else {
					publicStats.QPS = float64(publicStats.RequestCount)
				}
			}
			stats.mutex.Unlock()

			// Measure latency for this endpoint
			latency, latencyErr := h.tunnelManager.MeasureEndpointLatency(tunnelName, endpointName)
			latencyStr := "-"
			if latencyErr == nil {
				latencyStr = latency.Round(time.Millisecond).String()
			}

			response.Endpoints = append(response.Endpoints, PublicEndpointInfo{
				Name:         endpointName,
				Online:       true, // We only iterate over online streams
				RemoteAddr:   stream.RemoteAddr,
				OnlineTime:   formatDuration(stream.OnlineTime),
				LastActivity: formatDuration(stream.LastActivityTime),
				Latency:      latencyStr,
				Stats:        publicStats,
			})
			stream.Mu.Unlock()
			break // Only show info for one stream per endpoint name for simplicity
		}
		pool.mu.RUnlock()
	}
	tunnel.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
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

func (h *AdminHandlers) isAdminToken(token string) bool {
	if token == "" {
		return false
	}
	// Session store (login-issued tokens)
	if sess, ok := h.sessions.Get(token); ok {
		if sess.Expires.After(time.Now()) && sess.Admin {
			return true
		}
	}
	// Config-defined API tokens (user.token) for admin users
	if h.config != nil && h.config.Auth != nil && h.config.Auth.Users != nil {
		for _, u := range h.config.Auth.Users {
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
	if !h.isAdminToken(extractToken(r)) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	h.configMux.RLock()
	defer h.configMux.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.config)
}

func (h *AdminHandlers) setConfig(w http.ResponseWriter, r *http.Request) {
	if !h.isAdminToken(extractToken(r)) {
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
	file, err := os.OpenFile(h.configPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(h.config)
}

// ===== 用户管理 =====
func (h *AdminHandlers) handleUsers(w http.ResponseWriter, r *http.Request) {
	if !h.isAdminToken(extractToken(r)) {
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
					"admin":  u.Admin,
					"token":  u.Token,
					"groups": u.Groups,
					"dump":   u.Dump,
					"endpoint": u.Endpoint,
					"tunnel":   u.Tunnel,
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
	if !h.isAdminToken(extractToken(r)) {
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
	if !h.isAdminToken(extractToken(r)) {
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


// ===== 服务器管理 =====
func (h *AdminHandlers) handleServers(w http.ResponseWriter, r *http.Request) {
	if !h.isAdminToken(extractToken(r)) {
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
		if h.config.Servers == nil {
			h.config.Servers = make(map[string]*ListenConfig)
		}
		s := req.Server
		// 保持未提供字段为默认值
		h.config.Servers[req.Name] = &s
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
	if !h.isAdminToken(extractToken(r)) {
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
		var req struct {
			Index   *int    `json:"index,omitempty"`
			Mapping Mapping `json:"mapping"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}
		h.configMux.Lock()
		defer h.configMux.Unlock()
		if req.Index != nil {
			if *req.Index < 0 || *req.Index >= len(h.config.Mappings) {
				http.Error(w, "index out of range", http.StatusBadRequest)
				return
			}
			h.config.Mappings[*req.Index] = req.Mapping
		} else {
			h.config.Mappings = append(h.config.Mappings, req.Mapping)
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

func (h *CertHandlers) handleCertPage(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>APS - 证书安装</title>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/ibm-plex/6.0.0/css/ibm-plex.min.css" rel="stylesheet">
  <link href="https://unpkg.com/carbon-components@10.58.14/css/carbon-components.min.css" rel="stylesheet">
  <style>
    body {
      font-family: "IBM Plex Sans", system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji";
      background: #f4f4f4;
    }
    .container {
      max-width: 1100px;
      margin: 0 auto;
      padding: 1rem;
    }
    .hero {
      background: white;
      border-radius: 8px;
      padding: 1.25rem 1.5rem;
      box-shadow: 0 2px 6px rgba(0,0,0,0.06);
      border: 1px solid #e0e0e0;
    }
    .title {
      display: flex;
      align-items: center;
      gap: .5rem;
      margin-bottom: .5rem;
    }
    .subtitle {
      color: #525252;
      margin-bottom: .75rem;
    }
    .grid {
      margin-top: 1rem;
    }
    .tile {
      background: white;
      border-radius: 8px;
      border: 1px solid #e0e0e0;
      padding: 1rem;
      height: 100%;
    }
    .download-area {
      display: flex;
      align-items: center;
      gap: .75rem;
      flex-wrap: wrap;
    }
    code {
      background: #e9ecef;
      padding: 2px 6px;
      border-radius: 4px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 0.85rem;
    }
    .warning {
      background: #fff3cd;
      border: 1px solid #ffc107;
      border-radius: 8px;
      padding: 12px;
      color: #856404;
      margin-top: .75rem;
    }
  </style>
</head>
<body>
  <header class="bx--header" role="banner" aria-label="APS">
    <a class="bx--header__name" href="#" title="APS">APS</a>
    <nav class="bx--header__nav" aria-label="导航">
      <ul class="bx--header__menu-bar">
        <li><a class="bx--header__menu-item" href="/.admin/" target="_self">管理面板</a></li>
        <li><a class="bx--header__menu-item" href="/.api/stats" target="_blank">统计 JSON</a></li>
      </ul>
    </nav>
  </header>

  <main class="container">
    <section class="hero">
      <div class="title">
        <svg width="28" height="28" viewBox="0 0 32 32" fill="currentColor" aria-hidden="true"><path d="M16,2,2,7.5V14c0,7.07,5.16,13.73,14,16,8.84-2.27,14-8.93,14-16V7.5ZM28,14c0,6-4.31,11.4-12,13.6C8.31,25.4,4,20,4,14V9.23L16,5.14,28,9.23Z"/><path d="M7 13H25V15H7zM7 18H20V20H7z"/></svg>
        <h2>HTTPS 根证书安装</h2>
      </div>
      <p class="subtitle">为启用 HTTPS 流量解密，请在系统中安装并信任代理根证书。</p>

      <div class="download-area">
        <a class="bx--btn bx--btn--primary" href="/.ssl/cert" download="APS_Root_CA.crt">下载根证书</a>
        <a class="bx--btn bx--btn--tertiary" href="/.admin/" target="_self">打开管理面板</a>
        <span class="bx--tag bx--tag--cool-gray">文件名: APS_Root_CA.crt</span>
      </div>

      <div class="warning">
        <strong>注意</strong> 此证书仅用于开发与测试环境。安装后，代理可解密 HTTPS 流量，请勿在生产环境或公共网络中使用。
      </div>
    </section>

    <section class="grid">
      <div class="bx--grid bx--grid--condensed">
        <div class="bx--row">
          <div class="bx--col-lg-8 bx--col-md-8 bx--col-sm-4">
            <div class="tile">
              <h4>Windows</h4>
              <ol>
                <li>双击下载的证书文件，点击“安装证书”。</li>
                <li>选择“本地计算机”（需要管理员权限）。</li>
                <li>选择“将所有的证书都放入下列存储”。</li>
                <li>点击“浏览”，选择“受信任的根证书颁发机构”。</li>
                <li>完成向导并确认。</li>
              </ol>
            </div>
          </div>
          <div class="bx--col-lg-8 bx--col-md-8 bx--col-sm-4">
            <div class="tile">
              <h4>macOS</h4>
              <ol>
                <li>双击证书，在钥匙串访问中打开。</li>
                <li>双击列表中的证书，展开“信任”。</li>
                <li>将“使用此证书时”设为“始终信任”。</li>
                <li>关闭窗口并输入密码确认。</li>
              </ol>
            </div>
          </div>
          <div class="bx--col-lg-8 bx--col-md-8 bx--col-sm-4">
            <div class="tile">
              <h4>Linux (Ubuntu/Debian)</h4>
              <ol>
                <li>复制证书至系统目录：<br><code>sudo cp APS_Root_CA.crt /usr/local/share/ca-certificates/</code></li>
                <li>更新证书存储：<br><code>sudo update-ca-certificates</code></li>
              </ol>
            </div>
          </div>
          <div class="bx--col-lg-8 bx--col-md-8 bx--col-sm-4">
            <div class="tile">
              <h4>iOS / iPadOS</h4>
              <ol>
                <li>用 Safari 下载证书。</li>
                <li>设置 → 通用 → VPN与设备管理 → 安装描述文件。</li>
                <li>设置 → 通用 → 关于本机 → 证书信任设置 → 启用完全信任。</li>
              </ol>
            </div>
          </div>
          <div class="bx--col-lg-8 bx--col-md-8 bx--col-sm-4">
            <div class="tile">
              <h4>Android</h4>
              <ol>
                <li>下载证书。</li>
                <li>设置 → 安全 → 加密与凭据 → 从存储设备安装。</li>
                <li>选择下载的证书并确认名称。</li>
              </ol>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section class="grid">
      <div class="tile">
        <h4>下一步</h4>
        <p>安装完成后，重启浏览器或应用并配置系统代理，然后可在 <code>/.admin/</code> 访问管理面板，在 <code>/.api/stats</code> 查看实时统计 JSON。</p>
      </div>
    </section>
  </main>

  <script src="https://unpkg.com/carbon-components@10.58.14/scripts/carbon-components.min.js"></script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func (h *CertHandlers) handleCertDownload(w http.ResponseWriter, r *http.Request) {
	certPEM := GetCACertPEM()
	if certPEM == nil {
		http.Error(w, "Certificate not available", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=Any_Proxy_Service.crt")
	w.Write(certPEM)

	clientIP := r.RemoteAddr
	userAgent := r.Header.Get("User-Agent")
	os := detectOS(userAgent)
	log.Printf("Certificate downloaded by %s (OS: %s, UA: %s)", clientIP, os, userAgent)
}

func detectOS(userAgent string) string {
	switch {
	case contains(userAgent, "Windows"):
		return "Windows"
	case contains(userAgent, "Macintosh"):
		return "macOS"
	case contains(userAgent, "iPhone") || contains(userAgent, "iPad"):
		return "iOS"
	case contains(userAgent, "Android"):
		return "Android"
	case contains(userAgent, "Linux"):
		return "Linux"
	default:
		return "Unknown"
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) &&
			(hasPrefix(s, substr) || hasSuffix(s, substr) || indexOf(s, substr) >= 0))
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[0:len(prefix)] == prefix
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
