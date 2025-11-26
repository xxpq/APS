# WebSocket连接池实现文档

## 概述

本文档描述了在APS代理服务中实现的WebSocket连接池机制，该机制支持gRPC到WebSocket的自动fallback，以及对WebSocket链路数量进行池化管理。

## 核心功能

### 1. 连接池管理
- **池化机制**：维护固定数量的WebSocket连接，避免频繁创建和销毁连接
- **动态扩展**：当池中没有空闲连接时，自动创建新连接（不超过最大限制）
- **连接复用**：传输完成后自动归还连接到池中，供后续请求使用

### 2. gRPC到WebSocket Fallback
- **自动切换**：当gRPC通信失败时，自动fallback到WebSocket
- **智能检测**：识别网络错误、连接超时等gRPC失败场景
- **无缝切换**：对上层应用透明，无需修改业务逻辑

### 3. 连接生命周期管理
- **闲置超时**：长时间未使用的连接会被自动关闭
- **生命周期限制**：防止连接长时间运行导致的资源泄漏
- **健康检查**：定期ping/pong检测连接状态

## 架构设计

### 核心组件

1. **HybridTunnelManager**：混合隧道管理器，统一管理gRPC和WebSocket
2. **WebSocketPoolManager**：WebSocket连接池管理器
3. **WebSocketPool**：单个连接池实例
4. **WebSocketConnection**：单个WebSocket连接封装

### 类图关系

```
HybridTunnelManager
├── grpcManager: *TunnelManager (gRPC隧道管理)
├── wsManager: *WebSocketPoolManager (WebSocket连接池管理)
└── fallback logic (自动切换逻辑)

WebSocketPoolManager
└── pools: map[string]*WebSocketPool (多个连接池)

WebSocketPool
├── connections: []*WebSocketConnection (连接列表)
├── maxSize: int (最大连接数)
├── idleTimeout: time.Duration (闲置超时)
└── maxLifetime: time.Duration (最大生命周期)

WebSocketConnection
├── Conn: *websocket.Conn (WebSocket连接)
├── Status: ConnectionStatus (连接状态)
├── inUse: bool (是否在使用中)
└── pendingRequests: map[string]chan *WebSocketResponse (待处理请求)
```

## 配置说明

### 隧道配置示例

```json
{
  "tunnels": {
    "tunnel1": {
      "servers": ["main"],
      "password": "test123",
      "websocket_pool": {
        "enabled": true,              // 启用WebSocket连接池
        "pool_size": 5,               // 连接池大小
        "max_pool_size": 10,          // 最大连接池大小
        "idle_timeout": 300,          // 闲置超时时间（秒）
        "max_lifetime": 1800,         // 连接最大生命周期（秒）
        "fallback_enabled": true,     // 启用gRPC到WebSocket fallback
        "fallback_threshold": 3       // gRPC失败多少次后启用fallback
      }
    }
  }
}
```

### 配置参数说明

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| enabled | bool | true | 是否启用WebSocket连接池 |
| pool_size | int | 3 | 连接池大小 |
| max_pool_size | int | 10 | 最大连接池大小 |
| idle_timeout | int | 300 | 连接闲置超时时间（秒） |
| max_lifetime | int | 1800 | 连接最大生命周期（秒） |
| fallback_enabled | bool | true | 是否启用gRPC到WebSocket的fallback |
| fallback_threshold | int | 3 | gRPC失败多少次后启用fallback |

## 使用示例

### 1. 启动代理服务器

```bash
# 使用支持WebSocket的配置文件
./aps -config config.websocket.example.json
```

### 2. 连接WebSocket客户端

```bash
# 编译WebSocket测试客户端
go build -o ws_client cmd/ws_client/main.go

# 运行客户端
./ws_client -server localhost:8080 -tunnel tunnel1 -endpoint test-endpoint -password test123
```

### 3. 配置映射规则使用隧道

```json
{
  "mappings": [
    {
      "from": "http://example.com",
      "to": "http://localhost:3000",
      "via": {
        "tunnels": ["tunnel1"]
      }
    }
  ]
}
```

## 工作流程

### 1. 请求处理流程

```
HTTP Request → MapRemoteProxy → HybridTunnelManager
    ↓
gRPC SendRequest() → 成功 → 返回响应
    ↓ 失败
检查是否应该fallback → 是 → WebSocket SendRequest()
    ↓
WebSocketPool.GetConnection() → 获取连接
    ↓
发送请求 → 等待响应 → 归还连接
    ↓
返回响应
```

### 2. 连接池管理流程

```
需要连接 → GetConnection()
    ↓
检查空闲连接 → 有 → 标记为使用中 → 返回
    ↓ 无
检查是否达到最大数量 → 否 → 创建新连接 → 返回
    ↓ 是
返回错误（无可用连接）
```

### 3. 连接生命周期管理

```
连接创建 → 加入池 → 被获取使用 → 归还到池
    ↓
定期清理检查 → 闲置超时？→ 关闭连接
    ↓
生命周期到期？→ 关闭连接
```

## 监控和统计

### 连接池统计信息

可以通过管理面板或API获取连接池的实时统计信息：

```json
{
  "grpc": {
    "tunnels": 2,
    "tunnel_details": {
      "tunnel1": {
        "endpoints": 3,
        "streams": 5
      }
    }
  },
  "websocket": {
    "pools": 2,
    "total_connections": 8,
    "active_connections": 3
  },
  "fallback_enabled": true
}
```

### 日志输出

系统会输出详细的日志信息，包括：

- 连接池创建和销毁
- 连接的获取和归还
- Fallback切换事件
- 连接生命周期管理
- 错误和异常信息

示例日志：
```
[WS-POOL] Created new pool for tunnel1.endpoint1 with size 5, idle timeout 5m0s, max lifetime 30m0s
[WS-POOL] Connection ws-abc123 acquired from pool tunnel1.endpoint1 (active: 1)
[HYBRID] gRPC request failed for tunnel1.endpoint1, trying WebSocket fallback: connection refused
[WS-POOL] Connection ws-abc123 returned to pool tunnel1.endpoint1 (active: 0)
[WS-POOL] Closing expired connection ws-def456 in pool tunnel1.endpoint1
```

## 性能优化建议

### 1. 连接池大小配置
- **小型应用**：pool_size = 3-5
- **中型应用**：pool_size = 5-10
- **大型应用**：pool_size = 10-20

### 2. 超时时间配置
- **idle_timeout**：根据业务特点设置，建议300-600秒
- **max_lifetime**：防止连接泄漏，建议1800-3600秒

### 3. Fallback配置
- **fallback_threshold**：建议设置为3-5次失败
- **网络不稳定环境**：可以适当降低阈值

## 故障排除

### 常见问题

1. **WebSocket连接失败**
   - 检查服务器地址和端口
   - 验证隧道名称和密码
   - 查看防火墙设置

2. **连接池满**
   - 增加max_pool_size
   - 检查连接是否正确归还
   - 调整idle_timeout减少闲置连接

3. **Fallback不生效**
   - 确认fallback_enabled为true
   - 检查gRPC错误类型是否被识别
   - 查看日志中的fallback触发记录

### 调试方法

1. **启用详细日志**：设置debug模式查看详细日志
2. **监控连接状态**：通过管理面板查看连接池状态
3. **网络抓包**：使用Wireshark等工具分析WebSocket通信

## 安全考虑

1. **密码保护**：隧道密码用于WebSocket连接验证
2. **来源验证**：可以配置WebSocket的Origin检查
3. **连接加密**：支持WSS协议进行加密传输
4. **访问控制**：结合用户认证系统控制访问权限

## 扩展功能

未来可以考虑的扩展功能：

1. **连接池预热**：启动时预先创建连接
2. **智能负载均衡**：根据连接延迟和负载选择最优连接
3. **连接健康评分**：根据历史表现评估连接质量
4. **自动扩缩容**：根据负载动态调整连接池大小
5. **多协议支持**：支持除WebSocket外的其他备用协议

## 总结

WebSocket连接池实现提供了以下核心价值：

1. **高可用性**：通过gRPC到WebSocket的自动fallback确保服务连续性
2. **性能优化**：连接池化减少连接建立开销
3. **资源管理**：智能的生命周期管理防止资源泄漏
4. **可扩展性**：灵活的配置支持不同规模的应用场景
5. **可观测性**：完善的监控和日志支持运维管理

该实现为APS代理服务提供了强大的隧道通信能力，确保在各种网络环境下的稳定运行。