# Any Proxy Service - 高级 HTTP/HTTPS/gRPC 代理转发工具

## 简介

Any Proxy Service 是一个功能强大、高度可配置、可编写脚本的多协议 API 网关和代理服务器。它专为现代开发、测试和网络调试而设计，为您提供对网络流量无与伦比的精细化控制能力，允许您检查、修改、重定向、转换和模拟各种网络条件。

## ✨ 功能矩阵

| 类别                 | 功能点                                                                                                                                                                                                                                                           |
| :------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **核心代理**   | 同时运行多个 HTTP/HTTPS 代理、自动化的 HTTPS 流量拦截、上游代理链。                                                                                                                                                                                              |
| **高级路由**   | 基于 URL (支持通配符 `*`、正则表达式和 `*://` 协议通配)、方法、标头、查询参数的灵活映射规则。                                                                                                                                                                |
| **协议网关**   | gRPC 代理、WebSocket 代理与双向消息拦截、动态 REST-to-gRPC 转换 (无需代码生成)。                                                                                                                                                                                 |
| **流量策略**   | 速率限制 (e.g.,`500kbps`)、流量配额 (e.g., `10gb`)、请求次数配额、网络质量模拟 (丢包率)。                                                                                                                                                                    |
| **安全与认证** | 基于用户/组的访问控制，可在服务器、规则、隧道等多个级别应用。                                                                                                                                                                                                    |
| **自动化**     | 使用 Python/Node.js 脚本在请求和响应阶段进行动态修改、HAR 日志记录、配置热重载。                                                                                                                                                                                 |
| **持久化**     | 流量和请求次数的配额用量会自动保存到配置文件，防止因服务重启而重置。                                                                                                                                                                                             |
| **管理面板**   | 碳设计风格静态 UI（/.admin/），登录/退出（/.api/login, /.api/logout）、配置编辑器（GET/POST /.api/config）、统计仪表盘（1s 自动刷新，消费 /.api/stats；未认证维度键名脱敏、认证显示真实名称；支持 QPS、响应时长平均/最短/最长、请求/响应包大小平均/最小/最大）。 |

## 🚀 快速上手

### 1. 安装

确保您已经安装了 Go 语言环境。

```bash
# 构建可执行文件
go build .
```

### 2. 配置

创建一个名为 `config.json` 的文件。这是一个最简化的配置，它启动一个在 `8080` 端口的反向代理服务，并将所有对 `http://example.com` 的请求重定向到 `http://httpbin.org`。

```json
{
  "servers": {
    "http-proxy": {
      "port": 8080
    }
  },
  "mappings": [
    {
      "from": "http://example.com/*",
      "to": "http://httpbin.org/*",
      "servers": ["http-proxy"]
    }
  ]
}
```

### 3. 运行

```bash
./aps -config=config.json
```

## 核心概念

- **服务器 (`servers`)**: 代理的入口点，定义了监听的端口和基础行为。每个服务器可以有自己独立的认证、策略和日志配置。
- **映射规则 (`mappings`)**: 代理的核心。每一条规则都定义了“当一个请求满足 `from` 的条件时，应该如何通过 `to` 来处理它”。
- **端点配置 (`EndpointConfig`)**: `from` 和 `to` 字段都可以是一个详细的配置对象，而不仅仅是 URL 字符串。这个对象是进行高级匹配、修改和协议转换的关键。
- **策略 (`policies`)**: 用于定义连接和流量的限制。策略可以应用在服务器、规则、用户、组等多个层级，最终生效的将是所有适用策略中最严格的一个 (例如，最低的速率限制)。

## 配置详解

### `servers`

定义一个或多个代理服务器实例。`key` 是服务器的唯一名称。

- `port`: (必需) `integer` 监听端口。
- `cert`: (可选) `string` 或 `object`。用于启用 HTTPS。
  - 值为 `"auto"`: 自动生成 CA 证书用于 HTTPS 拦截。
  - 值为一个对象: `{ "cert": "path/to/cert.pem", "key": "path/to/key.pem" }`，指定证书和私钥文件的路径。
- `auth`: (可选) `object`。为此服务器启用代理认证。
  - `users`: `array` of `string`。允许访问的用户列表。
  - `groups`: `array` of `string`。允许访问的用户组列表。
- `dump`: (可选) `string`。HAR 文件路径，用于记录通过此服务器的所有流量。
- `public`: (可选) `boolean`。默认 `true`。为 `true` 时监听 `0.0.0.0:port`，为 `false` 时仅监听 `127.0.0.1:port`。
- `panel`: (可选) `boolean`。默认 `false`。为 `true` 时注册管理端路由 `/.api/*` 与 `/.admin/`；为 `false` 时不注册这些路由（`/.replay` 始终可用）。
- `endpoint`: (可选) `string` 或 `array` of `string`。服务级端点配置，用于请求转发。当请求未命中mapping规则时，如果server配置了endpoints，请求将被转发到这些端点。
- `tunnel`: (可选) `string` 或 `array` of `string`。服务级隧道配置，用于请求转发。当请求未命中mapping规则时，如果server配置了tunnels，请求将通过这些隧道转发。
- `ConnectionPolicies` & `TrafficPolicies`: (可选) 为此服务器上的所有连接设置默认策略。

**示例:**

```json
"servers": {
  "http-proxy": {
    "port": 8080,
    "public": false
  },
  "https-server-with-auth": {
    "port": 8443,
    "cert": "acme",
    "panel": true,
    "auth": {
      "users": ["user1"],
      "groups": ["admin_group"]
    },
    "rateLimit": "1mbps"
  }
}
```

**进一步案例：服务器作为隧道接入点与端点路由**

- 配置片段：

```json
{
  "servers": {
    "edge": { "port": 3000, "panel": true }
  },
  "tunnels": {
    "my-secure-tunnel": {
      "servers": ["edge"],
      "password": "shared-secret"
    }
  },
  "mappings": [
    {
      "from": "https://remote-app.com/*",
      "to": "https://remote-app.com/*",
      "servers": ["edge"],
      "via": {
        "tunnels": "my-secure-tunnel"
      }
    },
    {
      "from": "https://remote-app.com/*",
      "to": "https://remote-app.com/*",
      "servers": ["edge"],
      "via": {
        "endpoints": "app-instance-1"
      }
    }
  ]
}
```

- 端点客户端启动示例：

```bash
go run ./endpoint/main.go -server 127.0.0.1:3000 -tunnel my-secure-tunnel -name app-instance-1 -password "shared-secret"
```

- 说明：
  - 将某隧道绑定到服务器需在 `tunnels.<name>.servers` 中声明；绑定后该服务器自动开放 `/.tunnel` 接入。
  - 映射规则中使用 `via.tunnels` 或 `via.endpoints` 字段决定路由；当隧道内无在线端点或指定端点离线时会回退为直连。
  - `servers.endpoint` / `servers.tunnel` 字段当前仅用于标识与未来默认路由扩展；不影响路由行为。

### `mappings`

定义请求处理规则的数组。规则按顺序匹配。

- `from`: (必需) `string` 或 `EndpointConfig` 对象。匹配传入请求的源。
- `to`: (必需) `string` 或 `EndpointConfig` 对象。定义请求的目标。
  - **远程目标**: `http://...`, `https://://...`, `ws://...`
  - **本地文件/目录**: `file:///path/to/your/file` 或 `file://./relative/path`
- `servers`: (可选) `array` of `string`。此规则适用的服务器名称列表。如果省略，则适用于所有服务器。
- `via`: (可选) `object`。通过该字段配置代理、隧道和端点路由。
  - `proxies`: (可选) `string` 或 `array` of `string`。指定一个或多个上游代理 (在 `proxies` 中定义)。
  - `tunnels`: (可选) `string` 或 `array` of `string`。按名称选择一个或多个隧道 (`tunnels` 中定义)。如果指定多个，将在其中随机选择一个隧道内的在线端点；当隧道中没有在线端点时回退为直连传输。
  - `endpoints`: (可选) `string` 或 `array` of `string`。按名称选择已连接的端点客户端（通过隧道注册的在线实例）。当提供多个端点名称时会随机选择一个；若目标端点离线则回退为直连传输。
  - 优先级：`from.proxy`（在 `from` 的 EndpointConfig 中声明）优先于 `via.proxies`，合并与选择逻辑见 [processConfig()](config.go:576)。
- `cc`: (可选) `array` of `string`。将请求“抄送”(Carbon Copy) 到一个或多个额外的目标 URL。抄送请求会复制原请求的 Method/URL/Headers/Body，异步发送，不影响主请求响应，且忽略抄送响应（仅记录日志）。
- `auth`: (可选) `object`。为此规则覆盖服务器级别的认证，或为无认证的服务器添加认证。
- `dump`: (可选) `string`。HAR 文件路径，仅记录匹配此规则的流量。
- `p12`: (可选) `string`。指定一个在 `p12s` 中定义的 P12 客户端证书，用于与目标服务器进行 mTLS 通信。
- `ConnectionPolicies` & `TrafficPolicies`: (可选) 为此规则设置特定的策略。

#### `EndpointConfig` 对象详解

`from` 和 `to` 字段都可以使用此对象进行高级配置。

- `url`: (必需) `string`。URL 字符串。
  - **通配符**: `*` 可用于匹配路径的其余部分，例如 `http://api.example.com/v1/*`。
  - **协议匹配**: `from.url` 的协议头会精确匹配请求协议。
    - `http://`: 只匹配 HTTP 请求。
    - `https://`: 只匹配 HTTPS 请求。
    - `ws://` / `wss://`: 匹配 WebSocket 升级请求。
    - `*://`: 匹配任何协议。
  - **正则匹配**: 支持在 `from.url` 使用正则表达式与捕获组替换，详见 [配置指南](CONFIGURATION_GUIDE.md:1) 的“正则表达式 URL 匹配”章节。
- `method`: (可选) `string` 或 `array` of `string`。匹配一个或多个 HTTP 方法，例如 `"POST"` 或 `["GET", "POST"]`。
- `headers`: (可选) `object`。匹配或修改标头。
  - `{"Header-Name": "value"}`: 在 `from` 中用于匹配，在 `to` 中用于添加或覆盖。
  - `{"Header-Name": null}`: 在 `to` 中用于移除标头。
  - `{"Header-Name": ["val1", "val2"]}`: 在 `to` 中用于从列表中随机选择一个值。
  - 特殊说明：当值为数组时会随机选择，其中 `Authorization` 键的值会在日志中进行脱敏展示，参见 [EndpointConfig.GetHeader()](config.go:176)。
- `querystring`: (可选) `object`。匹配或修改查询参数。用法同 `headers`。
- `proxy`: (可选) `string` 或 `array` of `string` 或本地/远程文件路径。为该端点单独指定上游代理：
  - 直接填写代理 URL（支持 `http://`、`https://`、`socks5://`）。
  - 指向本地文本文件路径，每行一个代理；或远程 `.txt`/`.json` 列表 URL，系统会定时（每 5 分钟）自动更新。
    - 当与 `via.proxies` 同时存在时，`from.proxy` 优先，参见 [processConfig()](config.go:576)。
- `script`: (可选) `string`。指定用于处理请求或响应的脚本路径。
  - 在 `from` 中使用: 脚本在 **请求** 发送到目标之前执行。
  - 在 `to` 中使用: 脚本在从目标收到 **响应** 之后执行。
- `grpc`: (可选) `GRPCConfig` 对象。用于 gRPC 代理和转换。
- `websocket`: (可选) `WebSocketConfig` 对象。用于 WebSocket 消息拦截。

**示例: 高级映射规则**

```json
"mappings": [
  {
    "from": "http://api.service.com/users/*",
    "to": "http://internal.service.com/users/*",
    "servers": ["http-proxy"],
    "cc": ["http://log-service/ingress", "http://audit-service/new-request"]
  },
  {
    "from": "http://remote-app.com/*",
    "to": "http://remote-app.com/*",
    "via": {
      "tunnels": "my-secure-tunnel",
      "endpoints": "app-instance-1"
    }
  }
]
```

#### cc（Carbon Copy）抄送

- 行为：对每个匹配的原请求，异步再发起一份相同的请求到 `cc` 列表中的目标 URL。
- 细节：
  - 复制 Method、URL、Headers 与 Body；抄送响应不参与主流程，仅做日志记录。
  - 抄送失败不会影响主请求的成功与否。
  - 大体积 Body 会被读取并复用一份用于主请求，注意内存占用。
- 示例：

```json
{
  "from": "https://api.example.com/v1/events",
  "to": "https://collector.internal/v1/events",
  "cc": [
    "https://audit.service.local/ingest",
    "https://ml.service.local/learn"
  ]
}
```

#### Via 配置对象

`via` 字段是一个统一的对象，用于配置代理、隧道和端点路由。它提供了一种结构化的方式来指定请求的中间路由。

- `proxies`: 指定上游代理服务器
- `tunnels`: 指定隧道进行端点路由
- `endpoints`: 直接指定端点进行路由

**配置优先级**：
1. `from.proxy`（端点配置中的代理）优先级最高
2. `via.proxies`（via对象中的代理）次之
3. 规则级的独立代理字段（已废弃）

#### 隧道与端点路由（via.tunnels / via.endpoints）

- `via.tunnels`: 选择一个或多个隧道名称，系统将从目标隧道中随机挑选在线端点转发请求；若隧道内无在线端点则回退为直连。
- `via.endpoints`: 直接按名称选择一个或多个具体端点（跨隧道全局查找），随机挑选在线实例；若目标端点离线则回退为直连。
- **Server级别配置**：除了映射规则中的`via`配置，还可以在`servers`级别配置`endpoint`和`tunnel`字段：
  - 当请求未命中任何mapping规则时，如果server配置了`endpoints`或`tunnels`，请求仍会被转发到相应的端点
  - 这提供了更灵活的路由能力，即使在没有匹配规则的情况下也能将请求转发到指定端点
- 使用步骤：

  1) 在配置中定义 `tunnels` 并将其绑定到一个或多个监听 `servers`（详见本文下方 `tunnels` 小节）。
  2) 在目标机器上运行端点客户端，使其以某个 `-name` 挂到指定 `-tunnel` 下。
  3) 在映射规则中使用 `via.tunnels` 或 `via.endpoints` 字段进行路由，或在server级别配置`endpoint`/`tunnel`字段。
- 端点客户端启动示例：

```bash
go run ./endpoint/main.go -server 127.0.0.1:3000 -tunnel my-secure-tunnel -name app-instance-1 -password "your-aes-password"
```

- 按隧道路由示例（在隧道内挑任一在线端点）：

```json
{
  "from": "https://remote-app.com/*",
  "to": "https://remote-app.com/*",
  "via": {
    "tunnels": ["my-secure-tunnel", "backup-tunnel"]
  }
}
```

- 按端点名路由示例（跨隧道查找指定端点名）：

```json
{
  "from": "https://remote-app.com/*",
  "to": "https://remote-app.com/*",
  "via": {
    "endpoints": ["app-instance-1", "app-instance-2"]
  }
}
```

- Server级别端点配置示例（未命中mapping时仍然转发）：

```json
{
  "servers": {
    "main-gateway": {
      "port": 443,
      "cert": "acme",
      "endpoints": ["fallback-instance-1", "fallback-instance-2"]
    }
  }
}
```

### `proxies`

定义可供 `mappings` 使用的上游代理池。`key` 是代理的唯一名称。

- `urls`: (必需) `array` of `string`。上游代理服务器的 URL 列表。如果提供多个，将进行轮询。
- `ConnectionPolicies` & `TrafficPolicies`: (可选) 为通过此代理的连接设置策略。

**示例:**

```json
"proxies": {
  "datacenter-a": {
    "urls": ["http://user:pass@proxy-a1.com:8080", "http://user:pass@proxy-a2.com:8080"]
  },
  "datacenter-b": {
    "urls": ["socks5://proxy-b.com:1080"]
  }
}
```

### `tunnels`

定义可被端点客户端连接的隧道。端点通过 WebSocket 连接到服务器的 `/.tunnel` 路径，并以某个名称注册到指定隧道下。映射规则中的 `via.tunnels` 与 `via.endpoints` 依赖此处定义及端点在线状态。

- `servers`: (必需) `array` of `string`。允许此隧道在这些监听服务上接入端点（这些 server 会接受端点到 `/.tunnel` 的接入）。
- `password`: (可选) `string`。用于隧道内请求/响应数据的 AES-GCM 加密密钥；为空则不加密。
- `auth`: (可选) `object`。对通过该隧道路由的请求施加的访问控制（字段同 `mappings.auth` 的 `users`/`groups`）。
- `ConnectionPolicies` & `TrafficPolicies`: (可选) 应用于通过该隧道路由的连接/流量策略（如 `rateLimit`、`trafficQuota`、`requestQuota`）。

**示例:**

```json
"tunnels": {
  "my-secure-tunnel": {
    "servers": ["main-gateway"],
    "password": "shared-secret",
    "rateLimit": "5mbps",
    "trafficQuota": "10gb"
  },
  "edge-pop": {
    "servers": ["http-proxy", "https-proxy-with-auth"]
  }
}
```

端点客户端运行示例：

```bash
go run ./endpoint/main.go -server 127.0.0.1:3000 -tunnel my-secure-tunnel -name app-instance-1 -password "shared-secret"
```

### `auth`

定义用户、组和访问策略。

- `users`: `object`。`key` 是用户名。
  - `password`: (必需) `string`。用户密码。
  - `groups`: (可选) `array` of `string`。用户所属的组。
  - `ConnectionPolicies` & `TrafficPolicies`: (可选) 为此用户设置特定的策略。
- `groups`: `object`。`key` 是组名。
  - `ConnectionPolicies` & `TrafficPolicies`: (可选) 为此组设置特定的策略。

**策略继承与优先级**:
最终生效的策略是所有适用策略中最严格的一个。策略应用的层级顺序为：服务器 -> 映射规则 -> 用户 -> 组。

具体规则：
- **连接策略**：取所有适用策略中的最小值（最严格值）
  - `timeout`：最小超时时间生效
  - `idleTimeout`：最小空闲超时时间生效
  - `maxThread`：最小线程数限制生效
  - `quality`：最小质量系数生效
- **流量策略**：速率限制取最小值，配额按层级分别累积
  - `rateLimit`：最小速率限制生效
  - `trafficQuota`：各层级配额分别跟踪，任意层级超出都会触发限制
  - `requestQuota`：各层级配额分别跟踪，任意层级超出都会触发限制

例如，如果服务器限制 `1mbps`，用户限制 `500kbps`，则最终速率为 `500kbps`。

**端点/隧道配置优先级**:
当请求需要转发到端点或隧道时，优先级顺序为：用户 -> 组 -> 服务器 -> 映射规则（作为fallback）

具体规则：
- **用户级别**：用户在 `auth.users.<user>.endpoint` 或 `auth.users.<user>.tunnel` 中指定的配置具有最高优先级
- **组级别**：当用户级别没有配置时，使用用户所属组的 `auth.groups.<group>.endpoint` 或 `auth.groups.<group>.tunnel` 配置
- **服务器级别**：当用户和组级别都没有配置时，使用 `servers.<server>.endpoint` 或 `servers.<server>.tunnel` 配置
- **映射规则级别**：当以上级别都没有配置时，作为fallback使用映射规则中的 `via.endpoints` 或 `via.tunnels` 配置

**未命中mapping的处理**：
- 如果请求未命中任何mapping规则，但有任何级别（用户/组/服务器）的Endpoints/Tunnels配置，请求仍会被转发到相应的端点
- 只有在既未命中mapping规则，也没有任何级别的Endpoints/Tunnels配置时，才会返回404错误

**示例:**

```json
"auth": {
  "users": {
    "john": {
      "password": "password123",
      "groups": ["developers"],
      "trafficQuota": "10gb",
      "endpoint": ["john-instance-1", "john-instance-2"]
    },
    "guest": {
      "password": "guest",
      "rateLimit": "100kbps"
    },
    "special-user": {
      "password": "special123",
      "tunnel": ["user-tunnel-1", "user-tunnel-2"]
    }
  },
  "groups": {
    "developers": {
      "rateLimit": "10mbps",
      "tunnel": ["group-tunnel-1"]
    }
  }
}
```

**用户/组端点配置优先级示例：**
- 用户`john`有自己的`endpoint`配置，将优先使用用户级别的端点
- 用户`special-user`有自己的`tunnel`配置，将优先使用用户级别的隧道
- 用户`john`也属于`developers`组，但由于用户级别已有配置，组级别的`tunnel`配置不会被使用
- 用户`guest`没有用户级别的配置，如果属于某个有`endpoint`或`tunnel`配置的组，将使用组级别的配置

### `scripting`

配置脚本解释器的路径。如果留空，系统会尝试从 `PATH` 环境变量中查找。

- `pythonPath`: (可选) `string`。Python 解释器的路径 (例如 `/usr/bin/python3`)。
- `nodePath`: (可选) `string`。Node.js 解释器的路径。

### `p12s`

定义 P12/PFX 客户端证书，用于 mTLS 认证。`key` 是证书的唯一名称。

- `path`: (必需) `string`。`.p12` 或 `.pfx` 文件的路径。
- `password`: (必需) `string`。证书的密码。

**示例:**

```json
"p12s": {
  "my-client-cert": {
    "path": "./certs/client.p12",
    "password": "cert-password"
  }
}
```

### `quotaUsage`

此字段由 Any Proxy Service 自动管理，用于持久化流量和请求次数的配额用量。**请勿手动修改**。

配额用量会自动保存到 `data.json` 文件（可在启动时通过 `-data` 参数指定），并在服务重启后自动恢复。这确保了配额限制在服务重启后仍然有效，不会因为重启而重置用量计数。

数据文件结构示例：
```json
{
  "quotaUsage": {
    "user:john": {
      "trafficUsed": 1073741824,
      "requestsUsed": 1500
    },
    "group:developers": {
      "trafficUsed": 5368709120,
      "requestsUsed": 8500
    }
  }
}
```

## 高级功能与用例

### 流量策略 (Policies)

- `timeout`: `integer` (秒)。连接超时。
- `idleTimeout`: `integer` (秒)。空闲连接超时。
- `maxThread`: `integer`。并发连接数限制。
- `quality`: `float` (0.0 到 1.0)。传输质量系数（带宽倍率），1.0 表示满速，0.5 表示以 50% 带宽传输（不做丢包，仅限速）。注意：这是带宽倍率，不是丢包率。
- `rateLimit`: `string` (e.g., "500kbps", "2mbps")。速率限制。
- `trafficQuota`: `string` (e.g., "10gb", "500mb")。总流量配额。
- `requestQuota`: `integer`。总请求次数配额。

**示例: 模拟弱网环境**

```json
"mappings": [
  {
    "from": "http://*.mobile-api.com/*",
    "to": "http://backend.mobile-api.com/*",
    "quality": 0.8, // 80% 带宽（限速），不做丢包
    "rateLimit": "256kbps" // 模拟 2G/3G 网络速度
  }
]
```

### 脚本化修改 (Scripting)

使用 Python 或 Node.js 脚本在请求或响应阶段动态修改流量。

- 在 `from` 规则中定义的 `script` 会在请求被发送到目标服务器 **之前** 执行。
- 在 `to` 规则中定义的 `script` 会在收到目标服务器的响应 **之后** 执行。

脚本通过标准输入接收一个 JSON 对象，并通过标准输出返回一个修改后的 JSON 对象。

**JSON 结构:**

```json
{
  "method": "GET",
  "url": "http://example.com/path?a=1",
  "headers": { ... },
  "body": "base64-encoded-body", // body 是 base64 编码的
  // 仅 onResponse
  "status_code": 200,
  "status_text": "OK"
}
```

**示例: 使用 Python 脚本添加 HMAC 签名**

```json
// config.json
"from": {
  "url": "http://api.mycorp.com/v1/*",
  "script": "./scripts/add_hmac.py"
},
"to": "http://internal.api/*"
```

```python
# scripts/add_hmac.py
import sys
import json
import hmac
import hashlib
import base64
from datetime import datetime

def main():
    data = json.load(sys.stdin)
    secret_key = "my-secret-key"
  
    timestamp = str(datetime.utcnow().timestamp())
    body = base64.b64decode(data.get("body", "")).decode('utf-8')
  
    message = f"{timestamp}{data['method']}{data['url']}{body}"
  
    signature = hmac.new(
        secret_key.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
  
    data["headers"]["X-Timestamp"] = timestamp
    data["headers"]["X-Signature"] = signature
  
    json.dump(data, sys.stdout)

if __name__ == "__main__":
    main()
```

### 协议网关

#### gRPC 代理

根据 gRPC 的服务、方法和元数据来路由和修改流量。

```json
"mappings": [
  {
    "from": {
      "url": "*://grpc.example.com:443/*",
      "grpc": {
        "service": "myapp.UserService",
        "method": "GetUser",
        "metadata": { "source": "any-proxy" } // 添加/覆盖请求元数据
      }
    },
    "to": {
      "url": "http://localhost:50051"
    }
  }
]
```

#### WebSocket 消息拦截

拦截、检查和修改客户端与服务器之间的双向 WebSocket 消息。

- `intercept_client_messages`: 处理从客户端发往服务器的消息。
- `intercept_server_messages`: 处理从服务器发往客户端的消息。

每个规则支持 `match` (正则)、`replace`、`log` 和 `drop` 操作。

```json
"mappings": [
  {
    "from": "ws://chat.example.com/ws",
    "to": "ws://backend-chat:8000/ws",
    "websocket": {
      "intercept_client_messages": [
        {
          "match": "\"type\":\"private_message\"",
          "log": true, // 记录所有私信
          "drop": true // 并丢弃它们
        }
      ],
      "intercept_server_messages": [
        {
          "match": "token=([a-zA-Z0-9]+)",
          "replace": { "token=([a-zA-Z0-9]+)": "token=REDACTED" } // 隐藏 token
        }
      ]
    }
  }
]
```

#### 动态 REST-to-gRPC 转换

将一个标准的 RESTful API 请求动态地转换为对后端 gRPC 服务的调用，**无需预先生成任何代码**。

- `rest_to_grpc`:
  - `request_body_mapping`: 定义如何从 HTTP 请求的各个部分 (JSON body, URL 查询参数, URL 路径变量) 构建 gRPC 请求消息。
    - `"grpc_field": "json:http_json_field"`
    - `"grpc_field": "query:http_query_param"`
    - `"grpc_field": "path:url_path_variable"`

**示例: 将 RESTful 用户创建请求转换为 gRPC 调用**

```json
// POST http://api.example.com/v1/users/admin
// Body: { "user_name": "John Doe", "user_email": "john.doe@example.com" }
{
  "from": {
    "url": "http://api.example.com/v1/users/{role_id}",
    "method": "POST",
    "grpc": {
      "service": "myapp.UserService",
      "method": "CreateUser",
      "rest_to_grpc": {
        "request_body_mapping": {
          "name": "json:user_name",
          "email": "json:user_email",
          "role_id": "path:role_id"
        }
      }
    }
  },
  "to": "http://localhost:50051" // gRPC 后端地址
}
```

## 管理端点

- `/.api/stats`: 实时统计 JSON（已替换旧路径 `/.stats`）。未认证时对 `rules`/`users`/`servers`/`tunnels`/`proxies` 键名进行脱敏；认证后显示真实名称。指标包含：
  - QPS（按首末请求时间窗口计算，窗口 < 1s 时退化为请求数）
  - 响应时长 平均/最短/最长（毫秒）
  - 请求包/响应包大小 平均/最小/最大
  - 请求数、错误数、总字节
- `/.replay`: 重放捕获的请求。
- `/.admin/`: 管理面板静态资源（Carbon 样式），从 `./admin-ui/dist` 提供。

### 管理面板 API 与认证

- 后端 API：
  - `POST /.api/login`: 管理员登录，成功后返回 `token` 并设置 HttpOnly Cookie `APS-Admin-Token`。
  - `POST /.api/logout`: 退出登录，清理会话与 Cookie。
  - `GET /.api/config`: 读取配置（需管理员令牌）。
  - `POST /.api/config`: 写入配置（需管理员令牌，保存后触发热重载）。
- 认证方式：
  - 会话 Cookie：`APS-Admin-Token`（通过登录接口发放，24h 过期）。
  - Bearer Token：`Authorization: Bearer <token>`，来源于 `config.json -> auth.users[].token`，且该用户需 `admin: true`。
- 脱敏规则：
  - 未认证访问 `/.api/stats` 时，维度键名以 `md5(key + timestamp)` 返回；认证后返回真实键名。
- 前端静态：
  - `/.admin/`: 从 `./admin-ui/dist` 目录提供管理界面静态文件，包含统计仪表盘（1s 自动刷新）、配置编辑器、登录/退出。

### WebSocket 路由与匹配说明

- `from.url` 支持 `ws://` / `wss://` 作为协议匹配：
  - `ws://` 匹配将要升级为 WebSocket 的 HTTP 请求；
  - `wss://` 匹配将要升级为 WebSocket 的 HTTPS 请求；
  - 实际转发时，后端目标会自动转换为 `ws`/`wss` 协议连接。
- 可在 `from.websocket` 中配置消息拦截规则，对客户端/服务端方向分别进行 `match`、`replace`、`log`、`drop` 操作。
- 参考实现：[handleWebSocket()](websocket_handler.go:14)。

## 配置热重载与服务器同步

- 支持配置文件热重载，后台监视文件变化并自动重新解析与应用规则。
- 当检测到 `servers` 增删改时，自动启动、停止或重启对应监听服务。
- 重载成功后输出当前生效的规则摘要，便于快速核验。
- 参考实现：[ConfigWatcher](watcher.go:33)、[Config.Reload()](config.go:680)、[processConfig()](config.go:576)。

## 配置验证与错误处理

配置加载时会进行严格的验证，无效的规则会被自动过滤并记录警告日志：

- **映射规则验证**：
  - `from` 和 `to` 字段必须存在且包含有效的 URL
  - 引用的服务器名称必须在 `servers` 配置中存在
  - 引用的代理、隧道名称必须已定义
- **端点配置验证**：
  - URL 格式验证
  - 方法匹配验证
  - 头信息和查询参数格式验证
- **策略验证**：
  - 速率限制单位验证（支持 kbps、mbps、gbps）
  - 流量配额单位验证
  - 质量系数范围验证（0.0-1.0）

验证失败的规则会被跳过，服务会继续使用有效的配置运行。详细的验证错误会输出到日志中，便于排查问题。

## 附录：策略与单位说明

- 连接策略决策（最小值生效）：
  - 参考 [ResolvePolicies()](config.go:733)。
- 流量策略聚合：
  - 速率限制取最小值，配额按层级聚合；参考 [ResolveTrafficPolicies()](config.go:796)、[minRate()](config.go:909)。
- 速率单位：
  - 支持 `kbps`、`mbps`、`gbps`，示例 `500kbps`、`2mbps`；参考 [parseRateLimit()](config.go:880)。
- 流量配额单位：
  - 支持 `kb`、`mb`、`gb` 或字节数字；参考 [parseSize()](traffic_shaper.go:200)。
- 请求次数配额：
  - 设置为整数（总请求数）。
- 配额用量持久化：
  - 运行时配额用量会写入数据文件并在重启后恢复；参考 [LoadDataStore()](config.go:535)、[SaveDataStore()](config.go:561)。

## 完整配置示例

这是一个展示了多种功能的综合配置文件：

```json
{
  "servers": {
    "main-gateway": {
      "port": 443,
      "cert": {
        "cert": "./certs/server.crt",
        "key": "./certs/server.key"
      },
      "auth": {
        "groups": ["internal_users"]
      },
      "dump": "./logs/all_traffic.har"
    }
  },
  "auth": {
    "users": {
      "api_user": {
        "password": "secure_password",
        "groups": ["internal_users"],
        "trafficQuota": "100gb"
      }
    },
    "groups": {
      "internal_users": {}
    }
  },
  "proxies": {
    "external_proxy": {
      "urls": ["http://proxy.external.com:8080"]
    }
  },
  "scripting": {
    "pythonPath": "/usr/bin/python3"
  },
  "mappings": [
    // 规则 1: REST to gRPC
    {
      "from": {
        "url": "https://api.example.com/v1/users/{role}",
        "method": "POST",
        "grpc": {
          "service": "UserService",
          "method": "CreateUser",
          "rest_to_grpc": {
            "request_body_mapping": {
              "user_name": "json:name",
              "email_address": "json:email",
              "role": "path:role"
            }
          }
        }
      },
      "to": "http://grpc-user-service:50051",
      "servers": ["main-gateway"]
    },
    // 规则 2: 脚本化修改 + 上游代理
    {
      "from": {
        "url": "https://api.thirdparty.com/*",
        "script": "./scripts/add_api_key.py"
      },
      "to": "https://api.thirdparty.com/*",
      "via": {
        "proxies": "external_proxy",
        "endpoints": ["app-instance-1", "app-instance-2"]
      }
      "servers": ["main-gateway"]
    },
    // 规则 3: API 模拟
    {
      "from": "https://api.example.com/v1/status",
      "to": "file://./mocks/status.json",
      "servers": ["main-gateway"]
    },
    // 规则 4: 流量整形
    {
      "from": "https://*.slow-service.com/*",
      "to": "https://backend.slow-service.com/*",
      "rateLimit": "512kbps",
      "quality": 0.9,
      "servers": ["main-gateway"]
    }
  ]
}
## 管理面板使用指南

- 入口地址
  - 管理面板静态页面：`/.admin/`（Carbon Design 风格，无需构建即可使用）
- 登录与认证
  - 登录接口：`POST /.api/login`（仅 `auth.users` 中设置了 `admin: true` 的用户可登录）
  - 登录成功后：
    - 后端会设置 HttpOnly Cookie：`APS-Admin-Token`（默认 24h 过期）
    - 同时返回一个 `token`（可选用于 `Authorization: Bearer <token>`）
  - 退出登录：`POST /.api/logout`（清理会话与 Cookie）
  - 管理员令牌的两种形式：
    - 会话 Cookie：`APS-Admin-Token`（通过登录获取）
    - Bearer Token：`Authorization: Bearer <token>`（来自 `config.json -> auth.users[].token`，且该用户需 `admin: true`）
- 配置编辑器（需管理员令牌）
  - 读取配置：`GET /.api/config`
  - 写入配置：`POST /.api/config`（保存后触发热重载）
  - 建议：在管理面板中登录后即可使用 Cookie 访问；如需脚本访问可使用 Bearer Token
- 统计仪表盘
  - 数据源：`GET /.api/stats`
  - 刷新频率：默认每 1s 自动刷新，支持“立即刷新”“暂停/恢复”
  - 未认证访问时：`rules`/`users`/`servers`/`tunnels`/`proxies` 的键名会被脱敏（`md5(key + timestamp)`）；认证后显示真实名称
  - 指标包含：请求数、错误数、QPS、请求包/响应包大小的平均/最小/最大、响应时长的平均/最短/最长

## 统计指标说明（/.api/stats）

- 顶层字段
  - `totalRequests`：自启动以来的总请求数
  - `activeConnections`：当前活跃连接数
  - `totalBytesSent` / `totalBytesRecv`：自启动以来的总发送/接收字节数
  - `uptime`：运行时长
- 维度映射
  - `rules` / `users` / `servers` / `tunnels` / `proxies`：键名为维度的标识（未认证访问时为脱敏后的 MD5 值）
- 每个维度项的结构（PublicMetrics）
  - `requestCount`：请求数
  - `errors`：错误数
  - `qps`：每秒请求数（基于该维度首/末次请求时间窗口计算；窗口 < 1s 时退化为 `requestCount`）
  - `bytesSent`：
    - `total`：累计发送字节
    - `avg`：平均每请求发送字节（`total / requestCount`）
    - `min` / `max`：单请求发送字节的最小/最大值
  - `bytesRecv`：
    - 同 `bytesSent` 字段说明
  - `responseTime`（单位：毫秒）：
    - `totalMs`：累计响应时长（ns 汇总后转 ms）
    - `avgMs`：平均响应时长（`total / requestCount` 后转 ms）
    - `minMs` / `maxMs`：单请求响应时长的最短/最长值（ms）
- 示例（部分字段）：
  ```json
  {
    "totalRequests": 12345,
    "activeConnections": 7,
    "rules": {
      "rule-key-or-masked": {
        "requestCount": 100,
        "errors": 2,
        "qps": 5.5,
        "bytesSent": { "total": 1024000, "avg": 10240.0, "min": 512, "max": 65536 },
        "bytesRecv": { "total": 2048000, "avg": 20480.0, "min": 1024, "max": 131072 },
        "responseTime": { "totalMs": 2500.0, "avgMs": 25.0, "minMs": 3, "maxMs": 120 }
      }
    }
  }
```

- 计算与初始值约定
  - 最小值初始哨兵：
    - `bytesSent.min` / `bytesRecv.min` 初始为 `^uint64(0)`，若无数据则在输出时归零
    - `responseTime.min` 初始为 `-1`，若无数据则在输出时归零
  - QPS 窗口：
    - 使用该维度的首个请求时间与最新请求时间的区间；区间秒数 ≤ 1 时，`qps = requestCount`
