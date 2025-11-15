# Any Proxy Service - 高级 HTTP/HTTPS/gRPC 代理转发工具

## 简介

Any Proxy Service 是一个功能强大、高度可配置、可编写脚本的多协议 API 网关和代理服务器。它专为现代开发、测试和网络调试而设计，为您提供对网络流量无与伦比的精细化控制能力，允许您检查、修改、重定向、转换和模拟各种网络条件。

## ✨ 功能矩阵

| 类别 | 功能点 |
| :--- | :--- |
| **核心代理** | 同时运行多个 HTTP/HTTPS 代理、自动化的 HTTPS 流量拦截、上游代理链。 |
| **高级路由** | 基于 URL (支持通配符 `*`、正则表达式和 `*://` 协议通配)、方法、标头、查询参数的灵活映射规则。 |
| **协议网关** | gRPC 代理、WebSocket 代理与双向消息拦截、动态 REST-to-gRPC 转换 (无需代码生成)。 |
| **流量策略** | 速率限制 (e.g., `500kbps`)、流量配额 (e.g., `10gb`)、请求次数配额、网络质量模拟 (丢包率)。 |
| **安全与认证** | 基于用户/组的访问控制，可在服务器、规则、隧道等多个级别应用。 |
| **自动化** | 使用 Python/Node.js 脚本在请求和响应阶段进行动态修改、HAR 日志记录、配置热重载。 |
| **持久化** | 流量和请求次数的配额用量会自动保存到配置文件，防止因服务重启而重置。 |

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
./aps -config=config.json
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
4.  下载 `root_ca.crt` 证书文件。
5.  将此证书导入到您的系统或浏览器的“受信任的根证书颁发机构”中。

## 核心概念

-   **服务器 (`servers`)**: 代理的入口点，定义了监听的端口和基础行为。每个服务器可以有自己独立的认证、策略和日志配置。
-   **映射规则 (`mappings`)**: 代理的核心。每一条规则都定义了“当一个请求满足 `from` 的条件时，应该如何通过 `to` 来处理它”。
-   **端点配置 (`EndpointConfig`)**: `from` 和 `to` 字段都可以是一个详细的配置对象，而不仅仅是 URL 字符串。这个对象是进行高级匹配、修改和协议转换的关键。
-   **策略 (`policies`)**: 用于定义连接和流量的限制。策略可以应用在服务器、规则、用户、组等多个层级，最终生效的将是所有适用策略中最严格的一个 (例如，最低的速率限制)。

## 配置详解

### `servers`

定义一个或多个代理服务器实例。`key` 是服务器的唯一名称。

-   `port`: (必需) `integer` 监听端口。
-   `cert`: (可选) `string` 或 `object`。用于启用 HTTPS。
    -   值为 `"auto"`: 自动生成 CA 证书用于 HTTPS 拦截。
    -   值为一个对象: `{ "cert": "path/to/cert.pem", "key": "path/to/key.pem" }`，指定证书和私钥文件的路径。
-   `auth`: (可选) `object`。为此服务器启用代理认证。
    -   `users`: `array` of `string`。允许访问的用户列表。
    -   `groups`: `array` of `string`。允许访问的用户组列表。
-   `dump`: (可选) `string`。HAR 文件路径，用于记录通过此服务器的所有流量。
-   `ConnectionPolicies` & `TrafficPolicies`: (可选) 为此服务器上的所有连接设置默认策略。

**示例:**
```json
"servers": {
  "http-proxy": {
    "port": 8080
  },
  "https-proxy-with-auth": {
    "port": 8443,
    "cert": "auto",
    "auth": {
      "users": ["user1"],
      "groups": ["admin_group"]
    },
    "rateLimit": "1mbps"
  }
}
```

### `mappings`

定义请求处理规则的数组。规则按顺序匹配。

-   `from`: (必需) `string` 或 `EndpointConfig` 对象。匹配传入请求的源。
-   `to`: (必需) `string` 或 `EndpointConfig` 对象。定义请求的目标。
    -   **远程目标**: `http://...`, `https://://...`, `ws://...`
    -   **本地文件/目录**: `file:///path/to/your/file` 或 `file://./relative/path`
-   `servers`: (可选) `array` of `string`。此规则适用的服务器名称列表。如果省略，则适用于所有服务器。
-   `proxy`: (可选) `string` 或 `array` of `string`。为这条规则指定一个或多个上游代理 (在 `proxies` 中定义)。
-   `auth`: (可选) `object`。为此规则覆盖服务器级别的认证，或为无认证的服务器添加认证。
-   `dump`: (可选) `string`。HAR 文件路径，仅记录匹配此规则的流量。
-   `p12`: (可选) `string`。指定一个在 `p12s` 中定义的 P12 客户端证书，用于与目标服务器进行 mTLS 通信。
-   `ConnectionPolicies` & `TrafficPolicies`: (可选) 为此规则设置特定的策略。

#### `EndpointConfig` 对象详解

`from` 和 `to` 字段都可以使用此对象进行高级配置。

-   `url`: (必需) `string`。URL 字符串。
    -   **通配符**: `*` 可用于匹配路径的其余部分，例如 `http://api.example.com/v1/*`。
    -   **协议匹配**: `from.url` 的协议头会精确匹配请求协议。
        -   `http://`: 只匹配 HTTP 请求。
        -   `https://`: 只匹配 HTTPS 请求。
        -   `ws://` / `wss://`: 匹配 WebSocket 升级请求。
        -   `*://`: 匹配任何协议。
-   `method`: (可选) `string` 或 `array` of `string`。匹配一个或多个 HTTP 方法，例如 `"POST"` 或 `["GET", "POST"]`。
-   `headers`: (可选) `object`。匹配或修改标头。
    -   `{"Header-Name": "value"}`: 在 `from` 中用于匹配，在 `to` 中用于添加或覆盖。
    -   `{"Header-Name": null}`: 在 `to` 中用于移除标头。
    -   `{"Header-Name": ["val1", "val2"]}`: 在 `to` 中用于从列表中随机选择一个值。
-   `querystring`: (可选) `object`。匹配或修改查询参数。用法同 `headers`。
-   `script`: (可选) `string`。指定用于处理请求或响应的脚本路径。
    -   在 `from` 中使用: 脚本在 **请求** 发送到目标之前执行。
    -   在 `to` 中使用: 脚本在从目标收到 **响应** 之后执行。
-   `grpc`: (可选) `GRPCConfig` 对象。用于 gRPC 代理和转换。
-   `websocket`: (可选) `WebSocketConfig` 对象。用于 WebSocket 消息拦截。

**示例: 高级映射规则**
```json
"mappings": [
  {
    "from": {
      "url": "http://api.service.com/users/*",
      "method": "POST",
      "headers": { "X-Client-ID": "app-v1" }
    },
    "to": {
      "url": "http://internal.service.com/users/*",
      "headers": {
        "X-Forwarded-For": null, // 移除 X-Forwarded-For
        "Authorization": ["token1", "token2"] // 随机使用一个 token
      }
    },
    "servers": ["http-proxy"],
    "requestQuota": 1000 // 此规则每小时最多 1000 次请求
  }
]
```

### `proxies`

定义可供 `mappings` 使用的上游代理池。`key` 是代理的唯一名称。

-   `urls`: (必需) `array` of `string`。上游代理服务器的 URL 列表。如果提供多个，将进行轮询。
-   `ConnectionPolicies` & `TrafficPolicies`: (可选) 为通过此代理的连接设置策略。

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

### `auth`

定义用户、组和访问策略。

-   `users`: `object`。`key` 是用户名。
    -   `password`: (必需) `string`。用户密码。
    -   `groups`: (可选) `array` of `string`。用户所属的组。
    -   `ConnectionPolicies` & `TrafficPolicies`: (可选) 为此用户设置特定的策略。
-   `groups`: `object`。`key` 是组名。
    -   `ConnectionPolicies` & `TrafficPolicies`: (可选) 为此组设置特定的策略。

**策略继承与优先级**:
最终生效的策略是所有适用策略（服务器 -> 规则 -> 用户 -> 组）中最严格的一个。例如，如果服务器限制 `1mbps`，用户限制 `500kbps`，则最终速率为 `500kbps`。

**示例:**
```json
"auth": {
  "users": {
    "john": {
      "password": "password123",
      "groups": ["developers"],
      "trafficQuota": "10gb"
    },
    "guest": {
      "password": "guest",
      "rateLimit": "100kbps"
    }
  },
  "groups": {
    "developers": {
      "rateLimit": "10mbps"
    }
  }
}
```

### `scripting`

配置脚本解释器的路径。如果留空，系统会尝试从 `PATH` 环境变量中查找。

-   `pythonPath`: (可选) `string`。Python 解释器的路径 (例如 `/usr/bin/python3`)。
-   `nodePath`: (可选) `string`。Node.js 解释器的路径。

### `p12s`

定义 P12/PFX 客户端证书，用于 mTLS 认证。`key` 是证书的唯一名称。

-   `path`: (必需) `string`。`.p12` 或 `.pfx` 文件的路径。
-   `password`: (必需) `string`。证书的密码。

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

## 高级功能与用例

### 流量策略 (Policies)

-   `timeout`: `integer` (秒)。连接超时。
-   `idleTimeout`: `integer` (秒)。空闲连接超时。
-   `maxThread`: `integer`。并发连接数限制。
-   `quality`: `float` (0.0 到 1.0)。网络质量模拟，1.0 为最佳，0.5 代表 50% 的丢包率。
-   `rateLimit`: `string` (e.g., "500kbps", "2mbps")。速率限制。
-   `trafficQuota`: `string` (e.g., "10gb", "500mb")。总流量配额。
-   `requestQuota`: `integer`。总请求次数配额。

**示例: 模拟弱网环境**
```json
"mappings": [
  {
    "from": "http://*.mobile-api.com/*",
    "to": "http://backend.mobile-api.com/*",
    "quality": 0.8, // 20% 丢包
    "rateLimit": "256kbps" // 模拟 2G/3G 网络速度
  }
]
```

### 脚本化修改 (Scripting)

使用 Python 或 Node.js 脚本在请求或响应阶段动态修改流量。

-   在 `from` 规则中定义的 `script` 会在请求被发送到目标服务器 **之前** 执行。
-   在 `to` 规则中定义的 `script` 会在收到目标服务器的响应 **之后** 执行。

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
        "method": "GetUser"
      }
    },
    "to": {
      "url": "http://localhost:50051",
      "grpc": {
        "metadata": { "source": "any-proxy" } // 添加元数据
      }
    }
  }
]
```

#### WebSocket 消息拦截

拦截、检查和修改客户端与服务器之间的双向 WebSocket 消息。

-   `intercept_client_messages`: 处理从客户端发往服务器的消息。
-   `intercept_server_messages`: 处理从服务器发往客户端的消息。

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

-   `rest_to_grpc`:
    -   `request_body_mapping`: 定义如何从 HTTP 请求的各个部分 (JSON body, URL 查询参数, URL 路径变量) 构建 gRPC 请求消息。
        -   `"grpc_field": "json:http_json_field"`
        -   `"grpc_field": "query:http_query_param"`
        -   `"grpc_field": "path:url_path_variable"`

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

-   `/.ssl`: 下载用于 HTTPS 拦截的根 CA 证书。
-   `/.stats`: 查看实时的流量统计信息。
-   `/.replay`: 重放捕获的请求。

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
      "proxy": "external_proxy",
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