package main

import (
	"bufio"
	"context"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ProxyManager 管理代理配置
type ProxyManager struct {
	proxyConfig interface{} // 原始配置：string、[]string 或 nil
	proxyList   []string    // 解析后的代理列表
	mu          sync.RWMutex
	updateTimer *time.Timer
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewProxyManager 创建新的代理管理器
func NewProxyManager(proxyConfig interface{}) *ProxyManager {
	ctx, cancel := context.WithCancel(context.Background())
	pm := &ProxyManager{
		proxyConfig: proxyConfig,
		proxyList:   make([]string, 0),
		ctx:         ctx,
		cancel:      cancel,
	}

	// 初始化代理列表
	pm.loadProxies()

	return pm
}

// loadProxies 加载代理配置
func (pm *ProxyManager) loadProxies() {
	if pm.proxyConfig == nil {
		return
	}

	// 情况 1: 字符串
	if strValue, ok := pm.proxyConfig.(string); ok {
		pm.handleStringProxy(strValue)
		return
	}

	// 情况 2: 字符串数组
	if arrValue, ok := pm.proxyConfig.([]interface{}); ok {
		proxies := make([]string, 0)
		for _, item := range arrValue {
			if str, ok := item.(string); ok {
				proxies = append(proxies, strings.TrimSpace(str))
			}
		}
		pm.mu.Lock()
		pm.proxyList = proxies
		pm.mu.Unlock()
		log.Printf("[PROXY MANAGER] Loaded %d proxies from array", len(proxies))
		return
	}

	// 情况 3: []string 类型
	if arrValue, ok := pm.proxyConfig.([]string); ok {
		proxies := make([]string, 0)
		for _, str := range arrValue {
			proxies = append(proxies, strings.TrimSpace(str))
		}
		pm.mu.Lock()
		pm.proxyList = proxies
		pm.mu.Unlock()
		log.Printf("[PROXY MANAGER] Loaded %d proxies from string array", len(proxies))
		return
	}
}

// handleStringProxy 处理字符串类型的代理配置
func (pm *ProxyManager) handleStringProxy(proxyStr string) {
	proxyStr = strings.TrimSpace(proxyStr)

	// 检查是否是远程 URL（以 http 开头，且后缀是 .json 或 .txt，不含 ?）
	if strings.HasPrefix(proxyStr, "http://") || strings.HasPrefix(proxyStr, "https://") {
		// 提取路径部分（不含查询参数）
		if parsed, err := url.Parse(proxyStr); err == nil {
			path := parsed.Path
			if strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".txt") {
				// 这是远程配置文件
				log.Printf("[PROXY MANAGER] Detected remote proxy config: %s", proxyStr)
				pm.loadRemoteProxies(proxyStr)
				pm.startAutoUpdate(proxyStr)
				return
			}
		}
		// 否则就是单个代理 URL
		pm.mu.Lock()
		pm.proxyList = []string{proxyStr}
		pm.mu.Unlock()
		log.Printf("[PROXY MANAGER] Loaded 1 proxy from string: %s", maskProxyURL(proxyStr))
		return
	}

	// 检查是否是本地文件路径
	if _, err := os.Stat(proxyStr); err == nil {
		log.Printf("[PROXY MANAGER] Detected local proxy file: %s", proxyStr)
		pm.loadLocalProxies(proxyStr)
		return
	}

	// 否则当作单个代理 URI
	pm.mu.Lock()
	pm.proxyList = []string{proxyStr}
	pm.mu.Unlock()
	log.Printf("[PROXY MANAGER] Loaded 1 proxy from string: %s", maskProxyURL(proxyStr))
}

// loadLocalProxies 从本地文件加载代理列表
func (pm *ProxyManager) loadLocalProxies(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("[PROXY MANAGER] Error opening local proxy file %s: %v", filePath, err)
		return
	}
	defer file.Close()

	proxies := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			proxies = append(proxies, line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[PROXY MANAGER] Error reading local proxy file %s: %v", filePath, err)
		return
	}

	pm.mu.Lock()
	pm.proxyList = proxies
	pm.mu.Unlock()
	log.Printf("[PROXY MANAGER] Loaded %d proxies from local file: %s", len(proxies), filePath)
}

// loadRemoteProxies 从远程 URL 加载代理列表
func (pm *ProxyManager) loadRemoteProxies(remoteURL string) {
	resp, err := http.Get(remoteURL)
	if err != nil {
		log.Printf("[PROXY MANAGER] Error fetching remote proxy config from %s: %v", remoteURL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[PROXY MANAGER] Remote proxy config returned status %d from %s", resp.StatusCode, remoteURL)
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[PROXY MANAGER] Error reading remote proxy config from %s: %v", remoteURL, err)
		return
	}

	proxies := make([]string, 0)
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			proxies = append(proxies, line)
		}
	}

	pm.mu.Lock()
	pm.proxyList = proxies
	pm.mu.Unlock()
	log.Printf("[PROXY MANAGER] Loaded %d proxies from remote URL: %s", len(proxies), remoteURL)
}

// startAutoUpdate 启动自动更新定时器（每 5 分钟）
func (pm *ProxyManager) startAutoUpdate(remoteURL string) {
	// 取消之前的定时器
	if pm.updateTimer != nil {
		pm.updateTimer.Stop()
	}

	pm.updateTimer = time.AfterFunc(5*time.Minute, func() {
		select {
		case <-pm.ctx.Done():
			return
		default:
			log.Printf("[PROXY MANAGER] Auto-updating proxies from %s", remoteURL)
			pm.loadRemoteProxies(remoteURL)
			pm.startAutoUpdate(remoteURL) // 递归调度下一次更新
		}
	})

	log.Printf("[PROXY MANAGER] Scheduled auto-update every 5 minutes for %s", remoteURL)
}

// GetRandomProxy 随机获取一个代理 URL
func (pm *ProxyManager) GetRandomProxy() string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if len(pm.proxyList) == 0 {
		return ""
	}

	if len(pm.proxyList) == 1 {
		return pm.proxyList[0]
	}

	index := rand.Intn(len(pm.proxyList))
	proxyURL := pm.proxyList[index]
	log.Printf("[PROXY] Selected proxy [%d/%d]: %s", index+1, len(pm.proxyList), maskProxyURL(proxyURL))
	return proxyURL
}

// Close 关闭代理管理器
func (pm *ProxyManager) Close() {
	if pm.cancel != nil {
		pm.cancel()
	}
	if pm.updateTimer != nil {
		pm.updateTimer.Stop()
	}
}

// maskProxyURL 遮蔽代理 URL 中的敏感信息
func maskProxyURL(proxyURL string) string {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return proxyURL
	}

	// 如果有用户信息，遮蔽密码部分
	if parsed.User != nil {
		username := parsed.User.Username()
		if password, ok := parsed.User.Password(); ok {
			maskedPassword := "***"
			if len(password) > 3 {
				maskedPassword = password[:2] + "***"
			}
			parsed.User = url.UserPassword(username, maskedPassword)
		}
	}

	return parsed.String()
}