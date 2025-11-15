package main

import (
	"crypto/rand"
	"encoding/json"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
	"strings"
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
var AdminSessions = &SessionStore{sessions: make(map[string]Session)}

// AdminHandlers contains the HTTP handlers for the admin panel.
type AdminHandlers struct {
	config     *Config
	configPath string
	configMux  sync.RWMutex
	sessions   *SessionStore
}

// NewAdminHandlers creates a new AdminHandlers instance.
func NewAdminHandlers(config *Config, configPath string) *AdminHandlers {
	return &AdminHandlers{
		config:     config,
		configPath: configPath,
		sessions:   AdminSessions,
	}
}

// RegisterHandlers registers the admin panel handlers to the given ServeMux.
func (h *AdminHandlers) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/.api/login", h.handleLogin)
	mux.HandleFunc("/.api/logout", h.handleLogout)
	mux.HandleFunc("/.api/config", h.handleConfig)
	// Serve static files for the admin panel
	mux.Handle("/.admin/", http.StripPrefix("/.admin/", http.FileServer(http.Dir("./admin-ui/dist"))))
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

func (h *CertHandlers) handleCertPage(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cato Proxy Service - 证书安装</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 800px;
            width: 100%;
            padding: 40px;
        }
        h1 {
            color: #333;
            font-size: 32px;
            margin-bottom: 10px;
            text-align: center;
        }
        .subtitle {
            color: #666;
            text-align: center;
            margin-bottom: 30px;
            font-size: 16px;
        }
        .download-section {
            background: #f7f9fc;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
            text-align: center;
        }
        .download-btn {
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 40px;
            border-radius: 8px;
            text-decoration: none;
            font-size: 18px;
            font-weight: 600;
            transition: transform 0.2s, box-shadow 0.2s;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }
        .download-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
        }
        .instructions {
            margin-top: 30px;
        }
        .os-section {
            margin-bottom: 25px;
            padding: 20px;
            border-left: 4px solid #667eea;
            background: #f7f9fc;
            border-radius: 8px;
        }
        .os-section h3 {
            color: #667eea;
            margin-bottom: 12px;
            font-size: 20px;
        }
        .os-section ol {
            margin-left: 20px;
            color: #555;
            line-height: 1.8;
        }
        .os-section li {
            margin-bottom: 8px;
        }
        .warning {
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 8px;
            padding: 15px;
            margin-top: 20px;
            color: #856404;
        }
        .warning strong {
            display: block;
            margin-bottom: 5px;
        }
        code {
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
        }
        .status {
            text-align: center;
            margin-top: 20px;
            padding: 15px;
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 8px;
            color: #155724;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Cato Proxy Service</h1>
        <p class="subtitle">Root Certificate Installation</p>
        
        <div class="download-section">
            <p style="margin-bottom: 20px; color: #666;">下载根证书以信任 HTTPS 代理连接</p>
            <a href="/.ssl/cert" class="download-btn" download="Cato_Proxy_Service.crt">
                📥 下载根证书
            </a>
        </div>

        <div class="instructions">
            <h2 style="margin-bottom: 20px; color: #333;">📋 安装说明</h2>

            <div class="os-section">
                <h3>🪟 Windows</h3>
                <ol>
                    <li>双击下载的 <code>Cato_Proxy_Service.crt</code> 文件</li>
                    <li>点击"安装证书"</li>
                    <li>选择"本地计算机"（需要管理员权限）</li>
                    <li>选择"将所有的证书都放入下列存储"</li>
                    <li>点击"浏览"，选择"受信任的根证书颁发机构"</li>
                    <li>点击"确定"，完成安装</li>
                </ol>
            </div>

            <div class="os-section">
                <h3>🍎 macOS</h3>
                <ol>
                    <li>双击下载的 <code>Cato_Proxy_Service.crt</code> 文件</li>
                    <li>在钥匙串访问中找到"Cato Proxy Service Root CA"</li>
                    <li>双击证书，展开"信任"部分</li>
                    <li>将"使用此证书时"设置为"始终信任"</li>
                    <li>关闭窗口，输入密码确认</li>
                </ol>
            </div>

            <div class="os-section">
                <h3>🐧 Linux (Ubuntu/Debian)</h3>
                <ol>
                    <li>复制证书到系统目录：<br>
                        <code>sudo cp Cato_Proxy_Service.crt /usr/local/share/ca-certificates/</code>
                    </li>
                    <li>更新证书存储：<br>
                        <code>sudo update-ca-certificates</code>
                    </li>
                </ol>
            </div>

            <div class="os-section">
                <h3>📱 iOS/iPadOS</h3>
                <ol>
                    <li>使用 Safari 浏览器下载证书</li>
                    <li>前往"设置" > "通用" > "VPN与设备管理"</li>
                    <li>点击下载的描述文件，点击"安装"</li>
                    <li>前往"设置" > "通用" > "关于本机" > "证书信任设置"</li>
                    <li>启用"Cato Proxy Service Root CA"的完全信任</li>
                </ol>
            </div>

            <div class="os-section">
                <h3>🤖 Android</h3>
                <ol>
                    <li>下载证书文件</li>
                    <li>前往"设置" > "安全" > "加密与凭据"</li>
                    <li>选择"从存储设备安装"</li>
                    <li>找到并选择下载的证书文件</li>
                    <li>输入证书名称，确认安装</li>
                </ol>
            </div>

            <div class="warning">
                <strong>⚠️ 重要提示</strong>
                此证书仅用于开发和测试环境。安装后，代理可以解密您的 HTTPS 流量。
                请勿在生产环境或公共网络中使用。
            </div>

            <div class="status">
                <strong>✅ 安装完成后</strong><br>
                请重启浏览器或应用程序，并配置系统代理。
            </div>
        </div>
    </div>
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
	w.Header().Set("Content-Disposition", "attachment; filename=Cato_Proxy_Service.crt")
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
