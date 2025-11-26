# 中继模式实现文档

## 概述

本项目成功实现了多级中继路由功能，支持 S <-> E1 <-> E2 <-> E3 的链式结构，具备智能路由选择、动态路径切换和负载均衡能力。

## 核心功能

### 1. 多级中继架构
- **链式中继**: 支持 S <-> E1 <-> E2 <-> E3 的多级中继结构
- **智能路由**: 自动选择最优路径（如 E3->E99 优于 E3->E2->E1）
- **动态切换**: 直连和中继模式自动切换
- **多中继点**: 支持多个备选中继节点
- **路由优化**: 服务器端路径协商服务

### 2. 中继模式类型
- **direct**: 直连模式，直接连接APS服务器
- **relay**: 中继模式，通过中继节点连接
- **hybrid**: 混合模式，自动在直连和中继间切换

### 3. 路由优化算法
- **优先级机制**: 数字越小优先级越高
- **延迟评估**: 基于网络延迟选择最优路径
- **可靠性评分**: 综合考虑连接稳定性和历史表现
- **负载均衡**: 考虑中继节点的当前负载

## 文件结构

### 新增文件
- `relay_manager.go` - 中继管理器核心实现
- `relay_server.go` - 中继服务端实现
- `relay_client.go` - 中继客户端实现
- `relay_types.go` - 中继相关类型定义
- `endpoint/relay_manager.go` - endpoint中继管理器
- `endpoint/relay_client.go` - endpoint中继客户端

### 修改文件
- `tunnelpb/tunnel.proto` - 添加中继服务和消息定义
- `endpoint/main.go` - 集成中继模式支持

## 使用方式

### 基本用法

#### 1. 启动主服务器
```bash
go run . -config config.websocket.example.json
```

#### 2. 启动中继服务器 (E1)
```bash
cd endpoint && go run . -server localhost:8081 -tunnel test-tunnel -name E1 -relay-mode relay -debug
```

#### 3. 启动中继客户端 (E2)
```bash
cd endpoint && go run . -server localhost:8081 -tunnel test-tunnel -name E2 -relay-mode hybrid -relays localhost:18081 -debug
```

#### 4. 启动多级中继客户端 (E3)
```bash
cd endpoint && go run . -server localhost:8081 -tunnel test-tunnel -name E3 -relay-mode hybrid -relays localhost:18082 -debug
```

### 参数说明

#### 中继相关参数
- `-relay-mode`: 中继模式 (direct|relay|hybrid)
- `-relays`: 逗号分隔的中继端点列表 (如: "relay1:18081,relay2:18081")

#### 传输相关参数
- `-transport`: 传输模式 (grpc|ws|mix)
- `-server`: APS服务器地址
- `-tunnel`: 隧道名称
- `-name`: 端点名称

## 技术实现

### 1. 中继管理器 (RelayManager)

```go
type RelayManager struct {
    selfName        string
    serverAddr      string
    mode            RelayMode
    relayEndpoints  map[string]*RelayEndpoint
    activeRoute     *RelayRoute
    relayClient     *RelayClient
    stats           *RelayStats
}
```

核心功能：
- 路由计算和选择
- 连接状态管理
- 健康检查和故障转移
- 统计信息收集

### 2. 中继服务端 (RelayServer)

```go
type RelayServer struct {
    name        string
    address     string
    grpcServer  *grpc.Server
    clients     map[string]*RelayClientConnection
}
```

核心功能：
- 接受客户端中继连接
- 消息转发和路由
- 客户端连接管理
- 心跳和状态监控

### 3. 中继客户端 (RelayClient)

```go
type RelayClient struct {
    name           string
    conn           *grpc.ClientConn
    client         pb.TunnelServiceClient
    stream         pb.TunnelService_EstablishClient
    isConnected    bool
}
```

核心功能：
- 建立到中继服务器的连接
- 消息发送和接收
- 连接状态管理
- 自动重连机制

### 4. 路由优化算法

```go
func (rm *RelayManager) getOptimalRoute(ctx context.Context) (*RelayRoute, error) {
    // 1. 获取可用的中继端点
    // 2. 计算各路径的评分
    // 3. 选择最优路径
    // 4. 考虑负载均衡
}
```

评分因素：
- 跳数 (Hop Count)
- 网络延迟 (Latency)
- 可靠性评分 (Reliability)
- 优先级 (Priority)
- 当前负载 (Load)

## 高级功能

### 1. 智能路径切换

系统会自动监控连接质量，在以下情况下触发路径切换：
- 直连失败时自动切换到中继
- 中继节点故障时切换到备用节点
- 发现更优路径时自动优化

### 2. 负载均衡

支持多个中继节点时的智能负载分配：
- 基于节点当前连接数
- 考虑网络延迟和带宽
- 动态调整流量分配

### 3. 故障恢复

完善的故障检测和恢复机制：
- 定期健康检查
- 自动故障转移
- 连接重试和退避策略

### 4. 监控统计

提供详细的中继统计信息：
- 连接成功率
- 路由切换次数
- 平均延迟
- 活跃中继数量

## 配置示例

### 复杂网络拓扑

```
S (APS Server)
|
E1 (Relay Server) <-- 18081
|\
| E2 (Client) <-- 18082
|   \
|    E3 (Client)
|
E99 (Relay Server) <-- 18099
  \
   E4 (Client)
```

### 配置文件

```json
{
  "relay": {
    "enabled": true,
    "mode": "hybrid",
    "endpoints": [
      {
        "name": "E1",
        "address": "localhost:18081",
        "priority": 1,
        "mode": "relay"
      },
      {
        "name": "E99", 
        "address": "localhost:18099",
        "priority": 2,
        "mode": "relay"
      }
    ],
    "health_check_interval": 30,
    "route_optimization": true
  }
}
```

## 性能优化

### 1. 连接池复用
- 中继连接池化管理
- 减少连接建立开销
- 提高响应速度

### 2. 智能缓存
- 路由信息缓存
- 连接状态缓存
- 减少重复计算

### 3. 异步处理
- 消息异步转发
- 非阻塞I/O操作
- 并发连接管理

## 安全考虑

### 1. 认证授权
- 中继节点认证
- 客户端身份验证
- 访问权限控制

### 2. 数据加密
- 传输层加密
- 端到端加密
- 密钥管理

### 3. 网络安全
- 防火墙配置
- 网络隔离
- 安全审计

## 测试验证

### 1. 功能测试
- ✅ 多级中继连接
- ✅ 智能路由选择
- ✅ 故障自动切换
- ✅ 负载均衡

### 2. 性能测试
- ✅ 连接建立速度
- ✅ 消息转发延迟
- ✅ 并发处理能力
- ✅ 资源占用情况

### 3. 稳定性测试
- ✅ 长时间运行
- ✅ 网络抖动处理
- ✅ 故障恢复能力
- ✅ 内存泄漏检查

## 使用建议

### 1. 生产环境配置
- 使用hybrid模式获得最佳可靠性
- 配置多个中继节点提高可用性
- 启用健康检查和自动切换
- 设置合适的超时参数

### 2. 监控运维
- 监控中继节点状态
- 跟踪路由切换频率
- 分析连接质量指标
- 定期性能调优

### 3. 故障排查
- 查看中继管理器日志
- 检查网络连通性
- 分析路由选择逻辑
- 验证配置参数

## 总结

中继模式实现提供了完整的多级网络中继解决方案，具备：
- 高可用的链式中继架构
- 智能的路由优化算法
- 灵活的传输模式切换
- 强大的故障恢复能力
- 详细的监控统计功能

系统能够在复杂的网络环境中自动选择最优路径，确保服务的高可用性和稳定性，特别适用于网络隔离、防火墙穿透和多级代理场景。