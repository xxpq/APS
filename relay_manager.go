package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// RelayMode 中继模式
type RelayMode string

const (
	RelayModeDirect  RelayMode = "direct"  // 直连模式
	RelayModeRelay   RelayMode = "relay"   // 中继模式
	RelayModeHybrid  RelayMode = "hybrid"  // 混合模式（自动切换）
)

// RelayEndpoint 中继端点信息
type RelayEndpoint struct {
	Name         string    `json:"name"`
	Address      string    `json:"address"`
	Mode         RelayMode `json:"mode"`
	Priority     int       `json:"priority"`     // 优先级，数字越小优先级越高
	Latency      int64     `json:"latency"`      // 延迟（毫秒）
	Available    bool      `json:"available"`    // 是否可用
	LastCheck    time.Time `json:"last_check"`   // 最后检查时间
	ConnectedClients int   `json:"connected_clients"` // 连接的客户端数量
}

// RelayRoute 中继路由信息
type RelayRoute struct {
	Path        []string  `json:"path"`         // 路由路径 [E3, E99, S]
	HopCount    int       `json:"hop_count"`    // 跳数
	TotalLatency int64    `json:"total_latency"` // 总延迟
	Reliability float64   `json:"reliability"`   // 可靠性评分
}

// RelayManager 中继管理器
type RelayManager struct {
	mu              sync.RWMutex
	selfName        string
	serverAddr      string
	mode            RelayMode
	relayEndpoints  map[string]*RelayEndpoint // 可用的中继端点
	activeRoute     *RelayRoute               // 当前活跃路由
	routingService  RoutingService            // 路由服务客户端
	relayServer     *RelayServer              // 中继服务器
	relayClient     *RelayClient              // 中继客户端
	stats           *RelayStats                 // 统计信息
}

// RelayStats 中继统计信息
type RelayStats struct {
	mu                    sync.RWMutex
	TotalConnections      int64
	FailedConnections     int64
	RouteChanges          int64
	CurrentMode           RelayMode
	ActiveRelays          int
	AverageLatency        int64
}

// NewRelayManager 创建中继管理器
func NewRelayManager(selfName, serverAddr string, mode RelayMode) *RelayManager {
	return &RelayManager{
		selfName:       selfName,
		serverAddr:     serverAddr,
		mode:           mode,
		relayEndpoints: make(map[string]*RelayEndpoint),
		stats:          &RelayStats{CurrentMode: mode},
	}
}

// Initialize 初始化中继管理器
func (rm *RelayManager) Initialize(ctx context.Context) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	log.Printf("[RelayManager] Initializing with mode: %s", rm.mode)

	// 启动中继服务器
	if rm.mode == RelayModeRelay || rm.mode == RelayModeHybrid {
		rm.relayServer = NewRelayServer(rm.selfName)
		if err := rm.relayServer.Start(ctx); err != nil {
			return fmt.Errorf("failed to start relay server: %v", err)
		}
	}

	// 初始化中继客户端
	rm.relayClient = NewRelayClient(rm.selfName)

	// 初始化路由服务
	rm.routingService = NewRoutingService(rm.serverAddr)

	// 启动后台任务
	go rm.backgroundTasks(ctx)

	log.Printf("[RelayManager] Initialization completed")
	return nil
}

// AddRelayEndpoint 添加中继端点
func (rm *RelayManager) AddRelayEndpoint(endpoint *RelayEndpoint) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.relayEndpoints[endpoint.Name] = endpoint
	log.Printf("[RelayManager] Added relay endpoint: %s at %s", endpoint.Name, endpoint.Address)
}

// RemoveRelayEndpoint 移除中继端点
func (rm *RelayManager) RemoveRelayEndpoint(name string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	delete(rm.relayEndpoints, name)
	log.Printf("[RelayManager] Removed relay endpoint: %s", name)
}

// ConnectToServer 连接到服务器
func (rm *RelayManager) ConnectToServer(ctx context.Context) error {
	switch rm.mode {
	case RelayModeDirect:
		return rm.connectDirect(ctx)
	case RelayModeRelay:
		return rm.connectViaRelay(ctx)
	case RelayModeHybrid:
		return rm.connectHybrid(ctx)
	default:
		return fmt.Errorf("invalid relay mode: %s", rm.mode)
	}
}

// connectDirect 直连模式
func (rm *RelayManager) connectDirect(ctx context.Context) error {
	log.Printf("[RelayManager] Attempting direct connection to server")
	
	// 尝试直连
	if err := rm.testDirectConnection(ctx); err == nil {
		log.Printf("[RelayManager] Direct connection successful")
		rm.updateStats(RelayModeDirect, true)
		return nil
	}

	log.Printf("[RelayManager] Direct connection failed, checking if relay mode is available")
	
	// 如果直连失败且是混合模式，尝试中继
	if rm.mode == RelayModeHybrid {
		return rm.connectViaRelay(ctx)
	}

	return fmt.Errorf("direct connection failed and relay mode not available")
}

// connectViaRelay 中继模式
func (rm *RelayManager) connectViaRelay(ctx context.Context) error {
	log.Printf("[RelayManager] Attempting connection via relay")
	
	// 获取最优路由
	route, err := rm.getOptimalRoute(ctx)
	if err != nil {
		return fmt.Errorf("failed to get optimal route: %v", err)
	}

	log.Printf("[RelayManager] Selected route: %v (hop count: %d, latency: %dms)", 
		route.Path, route.HopCount, route.TotalLatency)

	// 通过中继连接
	if err := rm.establishRelayConnection(ctx, route); err != nil {
		rm.updateStats(RelayModeRelay, false)
		return fmt.Errorf("failed to establish relay connection: %v", err)
	}

	rm.activeRoute = route
	rm.updateStats(RelayModeRelay, true)
	log.Printf("[RelayManager] Relay connection established successfully")
	return nil
}

// connectHybrid 混合模式
func (rm *RelayManager) connectHybrid(ctx context.Context) error {
	// 首先尝试直连
	if err := rm.connectDirect(ctx); err == nil {
		return nil
	}

	// 直连失败，尝试中继
	log.Printf("[RelayManager] Direct connection failed, falling back to relay mode")
	return rm.connectViaRelay(ctx)
}

// getOptimalRoute 获取最优路由
func (rm *RelayManager) getOptimalRoute(ctx context.Context) (*RelayRoute, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// 获取可用的中继端点
	availableEndpoints := make([]*RelayEndpoint, 0)
	for _, endpoint := range rm.relayEndpoints {
		if endpoint.Available {
			availableEndpoints = append(availableEndpoints, endpoint)
		}
	}

	if len(availableEndpoints) == 0 {
		return nil, fmt.Errorf("no available relay endpoints")
	}

	// 使用路由服务获取最优路径
	routes, err := rm.routingService.CalculateOptimalRoutes(rm.selfName, availableEndpoints)
	if err != nil {
		// 如果路由服务不可用，使用简单的本地算法
		return rm.calculateLocalRoute(availableEndpoints), nil
	}

	if len(routes) == 0 {
		return nil, fmt.Errorf("no valid routes found")
	}

	// 返回最优路由（第一个就是最优的）
	return routes[0], nil
}

// calculateLocalRoute 本地路由计算（简单算法）
func (rm *RelayManager) calculateLocalRoute(endpoints []*RelayEndpoint) *RelayRoute {
	if len(endpoints) == 0 {
		return nil
	}

	// 按优先级排序
	bestEndpoint := endpoints[0]
	for _, endpoint := range endpoints {
		if endpoint.Priority < bestEndpoint.Priority {
			bestEndpoint = endpoint
		}
	}

	return &RelayRoute{
		Path:         []string{rm.selfName, bestEndpoint.Name, "S"},
		HopCount:     2,
		TotalLatency: bestEndpoint.Latency,
		Reliability:  0.8,
	}
}

// establishRelayConnection 建立中继连接
func (rm *RelayManager) establishRelayConnection(ctx context.Context, route *RelayRoute) error {
	if len(route.Path) < 2 {
		return fmt.Errorf("invalid route path")
	}

	// 连接到第一个中继节点
	nextHop := route.Path[1]
	endpoint, exists := rm.relayEndpoints[nextHop]
	if !exists {
		return fmt.Errorf("relay endpoint %s not found", nextHop)
	}

	return rm.relayClient.ConnectToRelay(ctx, endpoint)
}

// testDirectConnection 测试直连
func (rm *RelayManager) testDirectConnection(ctx context.Context) error {
	// 简单的连接测试
	conn, err := net.DialTimeout("tcp", rm.serverAddr, 5*time.Second)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// updateStats 更新统计信息
func (rm *RelayManager) updateStats(mode RelayMode, success bool) {
	rm.stats.mu.Lock()
	defer rm.stats.mu.Unlock()

	rm.stats.CurrentMode = mode
	if success {
		rm.stats.TotalConnections++
	} else {
		rm.stats.FailedConnections++
	}
}

// GetStats 获取统计信息
func (rm *RelayManager) GetStats() map[string]interface{} {
	rm.stats.mu.RLock()
	defer rm.stats.mu.RUnlock()

	return map[string]interface{}{
		"current_mode":        rm.stats.CurrentMode,
		"total_connections":   rm.stats.TotalConnections,
		"failed_connections":  rm.stats.FailedConnections,
		"route_changes":       rm.stats.RouteChanges,
		"active_relays":       rm.stats.ActiveRelays,
		"average_latency":     rm.stats.AverageLatency,
		"active_route":        rm.activeRoute,
		"relay_endpoints":     rm.getRelayEndpointsInfo(),
	}
}

// getRelayEndpointsInfo 获取中继端点信息
func (rm *RelayManager) getRelayEndpointsInfo() []map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	info := make([]map[string]interface{}, 0)
	for _, endpoint := range rm.relayEndpoints {
		info = append(info, map[string]interface{}{
			"name":              endpoint.Name,
			"address":           endpoint.Address,
			"mode":              endpoint.Mode,
			"priority":          endpoint.Priority,
			"latency":           endpoint.Latency,
			"available":         endpoint.Available,
			"connected_clients": endpoint.ConnectedClients,
		})
	}
	return info
}

// backgroundTasks 后台任务
func (rm *RelayManager) backgroundTasks(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rm.performHealthCheck(ctx)
		}
	}
}

// performHealthCheck 执行健康检查
func (rm *RelayManager) performHealthCheck(ctx context.Context) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	log.Printf("[RelayManager] Performing health check")
	
	for _, endpoint := range rm.relayEndpoints {
		// 检查中继端点可用性
		available := rm.checkEndpointAvailability(endpoint.Address)
		if endpoint.Available != available {
			endpoint.Available = available
			endpoint.LastCheck = time.Now()
			log.Printf("[RelayManager] Relay endpoint %s availability changed to: %v", endpoint.Name, available)
		}
	}
}

// checkEndpointAvailability 检查端点可用性
func (rm *RelayManager) checkEndpointAvailability(address string) bool {
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Shutdown 关闭中继管理器
func (rm *RelayManager) Shutdown() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	log.Printf("[RelayManager] Shutting down")

	if rm.relayServer != nil {
		rm.relayServer.Stop()
	}

	if rm.relayClient != nil {
		rm.relayClient.Disconnect()
	}

	return nil
}