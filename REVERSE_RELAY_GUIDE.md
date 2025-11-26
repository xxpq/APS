# 反向中继模式指南

## 概述

反向中继模式解决了在受限网络环境中端点无法监听端口的问题。在这种模式下，受限端点（E1）主动连接可监听端点（E2），建立反向隧道，使得E2可以通过E1访问APS服务器。

## 架构设计

```
传统模式: S <-> E1 <-> E2 (E1监听，E2连接)
反向模式: S <-> E2 <-> E1 (E2监听，E1主动连接)
```

## 使用场景

1. **E1位于受限网络**：无法开放端口监听，但可以主动发起出站连接
2. **E2位于开放网络**：可以监听端口，接受入站连接
3. **需要E2通过E1访问服务器**：形成 S <-> E2 <-> E1 的反向路径

## 配置说明

### E2端点配置（反向等待模式）

```json
{
  "relay": {
    "enabled": true,
    "mode": "reverse-wait",
    "endpoints": []
  }
}
```

### E1端点配置（反向连接模式）

```json
{
  "relay": {
    "enabled": true,
    "mode": "reverse",
    "endpoints": [
      {
        "name": "E2",
        "address": "e2.example.com:18081",
        "mode": "reverse-wait",
        "priority": 1,
        "available": true
      }
    ]
  }
}
```

## 工作原理

### 1. 连接建立过程

1. **E2启动**：在反向等待模式下，E2启动中继服务器，监听指定端口
2. **E1连接**：E1在反向模式下，主动连接E2的监听端口
3. **隧道建立**：连接成功后，建立反向隧道，E2可以通过E1访问APS服务器

### 2. 数据传输流程

```
客户端 -> E2 -> E1 -> APS服务器
```

### 3. 连接管理

- **连接池管理**：WebSocket连接池管理反向连接的生命周期
- **自动重连**：连接断开时自动尝试重新建立连接
- **闲置超时**：长期闲置的连接会被断开并回收

## 命令行使用

### 启动E2（反向等待模式）

```bash
aps.exe -config config.json -mode endpoint -name E2 -relay-mode reverse-wait
```

### 启动E1（反向连接模式）

```bash
aps.exe -config config.json -mode endpoint -name E1 -relay-mode reverse
```

## 代码实现

### 关键组件

1. **RelayServer**：处理反向连接请求
2. **RelayClient**：发起反向连接
3. **RelayManager**：管理反向中继逻辑
4. **WebSocket连接池**：管理连接生命周期

### 核心方法

- `WaitForReverseConnection()`：等待反向连接
- `ConnectToReverseRelay()`：建立反向连接
- `handleReverseConnection()`：处理反向连接

## 测试验证

使用提供的测试脚本验证功能：

```bash
test_reverse_relay.bat
```

测试场景：
1. 启动APS服务器
2. 启动E2（反向等待模式）
3. 启动E1（反向连接模式）
4. 验证E1成功连接E2
5. 验证E2可以通过E1访问APS服务器

## 故障排除

### 常见问题

1. **连接失败**：检查网络连通性和端口开放情况
2. **认证失败**：验证端点名称和配置一致性
3. **路由问题**：检查中继端点配置和可用性

### 日志分析

查看日志中的关键信息：
- `[RelayManager] Reverse relay connection established`
- `[RelayClient] Successfully connected to reverse relay`
- `反向连接已建立`

## 性能优化

1. **连接池配置**：调整连接池大小和超时参数
2. **路由选择**：使用智能路由算法选择最优路径
3. **负载均衡**：支持多个E2端点的负载均衡

## 安全考虑

1. **连接认证**：所有反向连接都需要认证
2. **数据加密**：支持TLS加密传输
3. **访问控制**：限制可访问的端点和资源

## 扩展功能

1. **多级反向中继**：支持多级反向中继架构
2. **动态路由**：根据网络状况动态调整路由
3. **监控告警**：实时监控反向连接状态