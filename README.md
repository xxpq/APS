# Cato Proxy Service (重构后)

## 简介

Cato Proxy Service 是一个功能强大、高度可配置、可编写脚本的多协议 API 网关和代理服务器。它专为现代开发、测试和网络调试而设计，为您提供对网络流量无与伦比的精细化控制能力，允许您检查、修改、重定向、转换和模拟各种网络条件。

## ✨ 功能矩阵

| 类别 | 功能点 |
| :--- | :--- |
| **核心代理** | 同时运行多个 HTTP/HTTPS 代理、自动化的 HTTPS 流量拦截、上游代理链 |
| **高级路由** | 基于 URL (支持通配符 `*`、正则表达式和 `*://` 协议通配)、方法、标头、查询参数的灵活映射规则 |
| **协议网关** | gRPC 代理、WebSocket 代理与双向消息拦截、动态 REST-to-gRPC 转换 (无需代码生成) |
| **流量策略** | 速率限制 (e.g., `500kbps`)、流量配额 (e.g., `10gb`)、请求次数配额、网络质量模拟 (丢包率) |
| **安全与认证** | 基于用户/组的访问控制，可在服务器、规则、隧道等多个级别应用 |
| **自动化** | 使用 Python/Node.js 脚本在请求和响应阶段进行动态修改、HAR 日志记录、配置热重载 |
| **持久化** | 流量和请求次数的配额用量会自动保存到配置文件，防止因服务重启而重置 |

## 🚀 快速上手

### 1. 安装

确保您已经安装了 Go 语言环境。

```bash
# 构建可执行文件
go build .
```

### 2. 配置

创建一个名为 `config.json` 的文件。这是一个最简化的配置，它启动一个在 `8080` 端口的 HTTP 代理，并将所有对 `http://example.com` 的请求重定向到 `http://httpbin.org`。

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
./cato-proxy-service -config=config.json
```

### 4. 配置 HTTPS 拦截

1.  在 `config.json` 中添加一个支持 HTTPS 拦截的服务器：
    ```json
    "https-proxy": {
      "port": 8443,
      "cert": "auto"
    }
    ```
2.  将您的系统或浏览器的代理设置为 `127.0.0.1:8443`。
3.  在浏览器中访问任意 HTTP 网站，然后导航到 `http://<any-domain>/.ssl` (例如 `http://example.com/.ssl`)。
4.  下载 `cato_root_ca.crt` 证书文件。
5.  将此证书导入到您的系统或浏览器的“受信任的根证书颁发机构”中。

## 核心概念

-   **服务器 (`servers`)**: 代理的入口点，定义了监听的端口和基础行为。
-   **映射规则 (`mappings`)**: 代理的核心。每一条规则都定义了“当一个请求满足 `from` 的条件时，应该如何通过 `to` 或 `local` 来处理它”。
-   **端点配置 (`EndpointConfig`)**: `from` 和 `to` 字段都可以是一个详细的配置对象，而不仅仅是 URL 字符串。这个对象是进行高级匹配、修改和协议转换的关键。
-   **策略 (`policies`)**: 用于定义连接和流量的限制。策略可以应用在服务器、规则、用户、组等多个层级，最终生效的将是所有适用策略中最严格的一个 (例如，最低的速率限制)。

## 配置详解

### `servers`

定义代理服务器。

-   `port`: (必需) 监听端口。
-   `cert`: (可选) 用于 HTTPS。可以是 `"auto"` 来自动生成证书，也可以是一个包含 `cert` 和 `key` 文件路径的对象。

### `mappings`

定义请求处理规则。

-   `from`: (必需) 匹配传入请求的源。可以是 URL 字符串或 `EndpointConfig` 对象。
-   `to`: (可选) 将请求转发到的目标。可以是 URL 字符串或 `EndpointConfig` 对象。
-   `local`: (可选) 将请求映射到本地文件或目录。`to` 和 `local` 必须至少有一个。
-   `servers`: (可选) 此规则适用的服务器名称列表。如果省略，则适用于所有服务器。

#### 深入 `EndpointConfig` 对象

`from` 和 `to` 字段都可以使用此对象进行高级配置。

-   **`url`**: URL 字符串。
    -   **通配符**: `*` 可用于匹配路径的其余部分，例如 `http://api.example.com/v1/*`。
    -   **协议匹配**: `from.url` 的协议头会精确匹配请求协议。
        -   `http://`: 只匹配 HTTP 请求。
        -   `https://`: 只匹配 HTTPS 请求。
        -   `ws://`: 只匹配 WebSocket (基于 HTTP) 的升级请求。
        -   `wss://`: 只匹配 Secure WebSocket (基于 HTTPS) 的升级请求。
        -   `*://`: 匹配任何协议。
-   **`method`**: 匹配一个或多个 HTTP 方法，例如 `"POST"` 或 `["GET", "POST"]`。
-   **`headers`**: 匹配或修改标头。
    -   `{"Header-Name": "value"}`: 添加或覆盖标头。
    -   `{"Header-Name": null}`: 移除标头。
    -   `{"Header-Name": ["val1", "val2"]}`: 从列表中随机选择一个值。
-   **`querystring`**: 匹配或修改查询参数。
-   **`script` (重要更新)**: 指定用于处理请求或响应的脚本。
    -   `from.script`: 在 **请求** 发送到目标之前执行。
    -   `to.script`: 在从目标收到 **响应** 之后执行。

**示例: 使用请求脚本添加认证头**
```json
"mappings": [
  {
    "from": {
      "url": "http://api.service.com/*",
      "script": {
        "onRequest": "./scripts/add_auth.py"
      }
    },
    "to": "http://internal.service.com/*"
  }
]
```

### `proxies`

定义可供 `mappings` 使用的上游代理。

### `auth`

定义用户、组和访问策略。

### `scripting`

配置脚本解释器的路径。

-   `pythonPath`: Python 解释器的路径 (例如 `/usr/bin/python3`)。
-   `nodePath`: Node.js 解释器的路径。

### `quotaUsage`

此字段由 Cato Proxy 自动管理，用于持久化流量和请求次数的配额用量。请勿手动修改。

## 高级功能：协议网关

### gRPC 代理

通过在 `EndpointConfig` 中使用 `grpc` 字段，您可以根据 gRPC 的服务、方法和元数据来路由和修改流量。

### WebSocket 消息拦截

通过 `websocket` 字段，您可以拦截、检查和修改客户端与服务器之间的双向 WebSocket 消息。

-   `intercept_client_messages`: 处理从客户端发往服务器的消息。
-   `intercept_server_messages`: 处理从服务器发往客户端的消息。

每个规则支持 `match` (正则)、`replace`、`log` 和 `drop` 操作。

### 动态 REST-to-gRPC 转换

这是 Cato Proxy 最强大的功能之一。您可以通过 `rest_to_grpc` 配置，将一个标准的 RESTful API 请求动态地转换为对后端 gRPC 服务的调用，**无需预先生成任何代码**。

-   `rest_to_grpc`:
    -   `request_body_mapping`: 定义如何从 HTTP 请求的各个部分 (JSON body, URL 查询参数, URL 路径变量) 构建 gRPC 请求消息。

**示例: 将 RESTful 用户创建请求转换为 gRPC 调用**
```json
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
  "to": "http://localhost:50051"
}
```

## 用例与示例

-   **API 模拟**: 使用 `local` 规则返回静态 JSON 文件，模拟后端 API。
-   **流量调试**: 使用 HTTPS 拦截和 HAR 日志记录来检查和分析流量。
-   **安全测试**: 使用随机的 `Authorization` 标头来测试端点的认证和授权逻辑。
-   **性能模拟**: 使用 `quality` 和 `rateLimit` 模拟慢速或不稳定的网络环境。
-   **API 网关**: 结合认证、速率限制和协议转换，构建一个轻量级的 API 网关。

## 管理端点

-   `/.ssl`: 下载用于 HTTPS 拦截的根 CA 证书。
-   `/.stats`: 查看实时的流量统计信息。
-   `/.replay`: 重放捕获的请求。