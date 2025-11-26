package main

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// RelayRouteRequest 路由请求
type RelayRouteRequest struct {
	Source      string   `json:"source"`
	Target      string   `json:"target"`
	Constraints []string `json:"constraints"`
}

// RelayRouteResponse 路由响应
type RelayRouteResponse struct {
	Source   string   `json:"source"`
	Target   string   `json:"target"`
	Path     []string `json:"path"`
	HopCount int      `json:"hop_count"`
	Latency  int64    `json:"latency"`
}

// RelayRouteInfo 路由信息
type RelayRouteInfo struct {
	Path         []string  `json:"path"`
	HopCount     int       `json:"hop_count"`
	TotalLatency int64     `json:"total_latency"`
	Reliability  float64   `json:"reliability"`
	Available    bool      `json:"available"`
	LastUpdate   int64     `json:"last_update"`
}

// RelayNodeInfo 中继节点信息
type RelayNodeInfo struct {
	Name         string    `json:"name"`
	Address      string    `json:"address"`
	Mode         RelayMode `json:"mode"`
	Priority     int       `json:"priority"`
	Latency      int64     `json:"latency"`
	Available    bool      `json:"available"`
	LastCheck    time.Time `json:"last_check"`
	ConnectedClients int   `json:"connected_clients"`
	Routes       []RelayRouteInfo `json:"routes"`
}

// RoutingService 路由服务接口
type RoutingService interface {
	CalculateOptimalRoutes(source string, endpoints []*RelayEndpoint) ([]*RelayRoute, error)
	UpdateRouteInfo(endpoint string, routes []RelayRouteInfo) error
	GetRouteInfo(source, target string) (*RelayRouteInfo, error)
}

// SimpleRoutingService 简单的路由服务实现
type SimpleRoutingService struct {
	serverAddr string
	routes     map[string]map[string]*RelayRouteInfo // source -> target -> route
	mu         sync.RWMutex
}

// NewRoutingService 创建路由服务
func NewRoutingService(serverAddr string) *SimpleRoutingService {
	return &SimpleRoutingService{
		serverAddr: serverAddr,
		routes:     make(map[string]map[string]*RelayRouteInfo),
	}
}

// CalculateOptimalRoutes 计算最优路由
func (rs *SimpleRoutingService) CalculateOptimalRoutes(source string, endpoints []*RelayEndpoint) ([]*RelayRoute, error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	routes := make([]*RelayRoute, 0)

	// 简单的路由算法：按优先级和延迟排序
	for _, endpoint := range endpoints {
		if !endpoint.Available {
			continue
		}

		route := &RelayRoute{
			Path:         []string{source, endpoint.Name, "SERVER"},
			HopCount:     2,
			TotalLatency: endpoint.Latency,
			Reliability:  0.8, // 默认可靠性
		}

		// 添加优先级权重
		reliability := 0.8 - float64(endpoint.Priority)*0.1
		if reliability < 0.1 {
			reliability = 0.1
		}
		route.Reliability = reliability

		routes = append(routes, route)
	}

	// 按可靠性排序（降序）
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Reliability > routes[j].Reliability
	})

	return routes, nil
}

// UpdateRouteInfo 更新路由信息
func (rs *SimpleRoutingService) UpdateRouteInfo(endpoint string, routes []RelayRouteInfo) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	for _, route := range routes {
		if _, exists := rs.routes[endpoint]; !exists {
			rs.routes[endpoint] = make(map[string]*RelayRouteInfo)
		}
		
		target := "SERVER" // 假设所有路由都指向服务器
		rs.routes[endpoint][target] = &route
	}

	return nil
}

// GetRouteInfo 获取路由信息
func (rs *SimpleRoutingService) GetRouteInfo(source, target string) (*RelayRouteInfo, error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if sourceRoutes, exists := rs.routes[source]; exists {
		if route, exists := sourceRoutes[target]; exists {
			return route, nil
		}
	}

	return nil, fmt.Errorf("route not found: %s -> %s", source, target)
}