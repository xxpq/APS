# Cato Proxy Service

Cato Proxy Service 是一个功能强大、高度可配置、可编写脚本的 HTTP/HTTPS 代理服务器，专为开发、测试和网络调试而设计。它提供了对网络流量的精细控制，允许您检查、修改、重定向和模拟各种网络条件。

## ✨ 功能特性

- **多代理服务器**: 同时运行多个具有不同配置的 HTTP 和 HTTPS 代理服务器。
- **高级请求/响应映射**:
  - 根据 URL、方法、标头和查询参数将请求重定向到不同的目标。
  - 将请求映射到本地文件系统以进行 API 模拟。
  - 动态修改请求/响应的标头和查询参数。
  - 支持从数组中随机选择标头值（例如 `Authorization` 令牌）。
- **HTTPS 拦截**: 支持自动生成证书以拦截和解密 HTTPS 流量。
- **上游代理链**: 将传出流量通过一个或多个上游代理进行路由，并可为代理本身配置策略。
- **认证与授权**:
  - 基于用户和组的精细访问控制。
  - 可在服务器、映射规则、隧道等多个级别应用认证策略。
- **安全隧道**: 创建加密的 WebSocket 隧道，用于安全地传输流量。
- **请求/响应脚本**: 使用 Python 或 Node.js 脚本在请求处理的生命周期中动态修改请求和响应。
- **连接与流量策略**:
  - **连接策略**: 配置超时、空闲超时、最大并发连接数。
  - **网络模拟**: 模拟不同的网络质量（丢包率）。
  - **流量策略**: 对服务器、用户、组、代理、隧道或特定规则应用速率限制、流量配额和**请求次数配额**。
- **配额持久化**: 自动将流量和请求次数的配额用量持久化到配置文件中。
- **HAR 日志记录**: 将所有通过代理的流量捕获为 HAR (HTTP Archive) 文件，以便进行后续分析。
- **实时配置重载**: 修改配置文件后，代理服务器可以自动重新加载配置，无需重启。
- **内置管理端点**:
  - `/.ssl`: 下载用于 HTTPS 拦截的根 CA 证书。
  - `/.stats`: 查看实时的流量统计信息。
  - `/.replay`: 重放捕获的请求。

## 🚀 快速开始

### 1. 安装

确保您已经安装了 Go 语言环境。

```bash
# 克隆仓库 (如果需要)
# git clone ...

# 构建可执行文件
go build .
```

### 2. 配置

创建一个名为 `config.json` 的文件。您可以从 `config.example.json` 开始。这是一个基本的配置示例：

```json
{
  "servers": {
    "http-proxy": {
      "port": 8080
    },
    "https-proxy": {
      "port": 8443,
      "cert": "auto"
    }
  },
  "mappings": [
    {
      "from": "http://example.com",
      "to": "http://httpbin.org",
      "servers": ["http-proxy", "https-proxy"]
    },
    {
      "from": "http://api.example.com/v1/users",
      "local": "/path/to/mock/users.json",
      "servers": ["http-proxy", "https-proxy"]
    }
  ]
}
```

这个配置启动了两个代理：
- 一个在 `8080` 端口的 HTTP 代理。
- 一个在 `8443` 端口的支持 HTTPS 拦截的 HTTPS 代理。

它还定义了两条规则：
1.  所有到 `http://example.com` 的请求都会被重定向到 `http://httpbin.org`。
2.  所有到 `http://api.example.com/v1/users` 的请求将返回本地文件 `/path/to/mock/users.json` 的内容。

### 3. 运行

```bash
./cato-proxy-service -config=config.json
```

### 4. 设置 HTTPS 拦截

1.  将您的系统或浏览器的代理设置为 `127.0.0.1:8443`。
2.  在浏览器中访问任意 HTTP 网站，然后导航到 `http://<any-domain>/.ssl` (例如 `http://example.com/.ssl`)。
3.  下载 `cato_root_ca.crt` 证书文件。
4.  将此证书导入到您的系统或浏览器的“受信任的根证书颁发机构”中。

完成这些步骤后，您就可以拦截和查看 HTTPS 流量了。

## 📚 配置指南

### `servers`

定义代理服务器监听的端口和行为。

- `port`: (必需) 监听端口。
- `cert`: (可选) 用于 HTTPS。可以是 `"auto"` 来自动生成证书，也可以是一个包含 `cert` 和 `key` 文件路径的对象。
- `auth`: (可选) 为此服务器配置认证。

**示例:**
```json
"servers": {
  "main-proxy": {
    "port": 8080
  },
  "secure-proxy": {
    "port": 8443,
    "cert": {
      "cert": "./certs/server.crt",
      "key": "./certs/server.key"
    }
  },
  "intercept-proxy": {
    "port": 9000,
    "cert": "auto"
  }
}
```

### `mappings`

映射规则是 Cato Proxy 的核心。每个规则定义了如何处理匹配的请求。

- `from`: (必需) 匹配传入请求的源。可以是 URL 字符串或一个详细的 `EndpointConfig` 对象。
- `to`: (可选) 将请求转发到的目标。可以是 URL 字符串或 `EndpointConfig` 对象。
- `local`: (可选) 将请求映射到本地文件或目录。`to` 和 `local` 必须至少有一个。
- `servers`: (可选) 此规则适用的服务器名称列表。如果省略，则适用于所有服务器。
- `proxy`: (可选) 为此规则指定一个或多个上游代理。
- `script`: (可选) 为此规则配置请求/响应处理脚本。
- `auth`: (可选) 为此规则配置认证。

#### `EndpointConfig` 对象

`from` 和 `to` 字段都可以使用 `EndpointConfig` 对象来进行更复杂的匹配和修改。

- `url`: (必需) URL 字符串。
- `method`: (可选) 匹配一个或多个 HTTP 方法，例如 `"GET"` 或 `["GET", "POST"]`。
- `headers`: (可选) 匹配或修改请求/响应头。
  - `{"Header-Name": "value"}`: 添加或覆盖标头。
  - `{"Header-Name": null}`: 移除标头。
  - `{"Header-Name": ["val1", "val2"]}`: 从列表中随机选择一个值。
- `querystring`: (可选) 匹配或修改查询参数。
  - `{"param": "value"}`: 添加或覆盖参数。
  - `{"param": null}`: 移除参数。

**示例:**
```json
{
  "from": {
    "url": "https://api.service.com/data",
    "method": "POST",
    "headers": {
      "X-Client-ID": "required-client-id"
    }
  },
  "to": {
    "url": "https://internal-api.service.com/v2/data",
    "headers": {
      "Authorization": ["token1", "token2", "token3"], // 随机选择一个 token
      "X-Client-ID": null // 移除原始的 X-Client-ID
    }
  }
}
```

### `proxies`

定义可供 `mappings` 使用的上游代理。代理可以是一个简单的 URL 字符串、一个 URL 数组，或者一个包含策略的完整对象。

**示例:**
```json
"proxies": {
  "datacenter-proxy": "http://user:pass@proxy.example.com:8080",
  "rotating-proxies": [
    "http://proxy1.example.com:8000",
    "http://proxy2.example.com:8000"
  ],
  "limited-proxy": {
    "urls": ["http://proxy3.example.com:8000"],
    "rateLimit": "500kbps",
    "trafficQuota": "10gb"
  }
},
"mappings": [
  {
    "from": "https://example.com",
    "to": "https://example.com",
    "proxy": "limited-proxy" // 使用带策略的代理
  }
]
```

### `auth`

定义用户、组和访问策略。

**示例:**
```json
"auth": {
  "users": {
    "alice": {
      "password": "password123",
      "groups": ["developers"]
    },
    "bob": {
      "password": "password456"
    }
  },
  "groups": {
    "developers": {
      "users": ["alice"]
    }
  }
},
"mappings": [
  {
    "from": "https://internal.dev",
    "to": "http://localhost:3000",
    "auth": {
      "groups": ["developers"] // 只允许 'developers' 组的成员访问
    }
  }
]
```

### `scripting`

使用外部脚本动态处理流量。脚本通过 stdin 接收一个 JSON 对象（包含请求/响应的详细信息），并通过 stdout 返回一个修改后的 JSON 对象。

- `pythonPath`: (可选) Python 解释器的路径。
- `nodePath`: (可选) Node.js 解释器的路径。

**示例:**
```json
"scripting": {
  "pythonPath": "/usr/bin/python3"
},
"mappings": [
  {
    "from": "https://api.example.com/user",
    "to": "https://api.example.com/user",
    "script": {
      "onResponse": "./scripts/add_header.py"
    }
  }
]
```

`add_header.py` 示例:
```python
import sys
import json

def main():
    data = json.load(sys.stdin)
    
    # 在响应中添加一个新标头
    if 'headers' not in data['response']:
        data['response']['headers'] = {}
    data['response']['headers']['X-Processed-By'] = ['Cato-Proxy-Script']
    
    # 将修改后的数据写回 stdout
    json.dump(data, sys.stdout)

if __name__ == "__main__":
    main()
```

### 策略

策略可以在 `servers`、`mappings`、`tunnels`、`proxies`、`users` 和 `groups` 等多个级别上定义。生效的策略将是所有适用策略中最严格的一个（例如，最低的超时时间，最低的速率限制）。

- **`ConnectionPolicies`**:
  - `timeout`: 连接超时（秒）。
  - `idleTimeout`: 空闲超时（秒）。
  - `maxThread`: 最大并发连接数。
  - `quality`: 网络质量模拟（0.0 到 1.0，1.0 表示无丢包）。
- **`TrafficPolicies`**:
  - `rateLimit`: 速率限制，例如 `"500kbps"` 或 `"1mbps"`。
  - `trafficQuota`: 流量配额，例如 `"500mb"` 或 `"10gb"`。
  - `requestQuota`: 请求次数配额，例如 `1000`。

**示例:**
```json
"auth": {
  "users": {
    "free_user": {
      "password": "password",
      "rateLimit": "100kbps",
      "trafficQuota": "1gb",
      "requestQuota": 10000
    }
  }
}
```

### 配额用量持久化

为了防止因服务重启导致配额用量重置，Cato Proxy 会自动将当前的流量和请求次数用量每 10 秒钟同步回您的 `config.json` 文件中。这些数据会保存在顶级的 `quotaUsage` 字段下。

```json
{
  "...": "...",
  "quotaUsage": {
    "user:free_user": {
      "trafficUsed": 12345678,
      "requestsUsed": 890
    }
  }
}
```
服务在启动时会自动加载这些用量数据，确保配额的持续性。

## 💡 用例

- **API 开发与模拟**: 使用 `local` 规则返回静态 JSON 文件，模拟后端 API。
- **安全测试**: 使用随机的 `Authorization` 标头来测试端点的认证和授权逻辑。
- **性能测试**: 使用 `quality` 和 `rateLimit` 模拟慢速或不稳定的网络环境。
- **A/B 测试**: 将部分用户流量重定向到新版本的服务。
- **流量调试**: 拦截和检查移动应用或第三方服务的 HTTPS 流量。
- **API 网关**: 作为简单的 API 网关，为用户或用户组提供速率限制和配额管理。